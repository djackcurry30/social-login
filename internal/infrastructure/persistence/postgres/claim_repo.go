package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/17track/social-login/internal/domain/identity"
	"github.com/17track/social-login/internal/pkg/appctx"
	"github.com/17track/social-login/internal/pkg/errs"
)

// ClaimRepository 是 identity_claims 表的仓储。
type ClaimRepository struct {
	db *gorm.DB
}

// NewClaimRepository 构造仓储。
func NewClaimRepository(db *gorm.DB) *ClaimRepository {
	return &ClaimRepository{db: db}
}

var _ identity.ClaimRepository = (*ClaimRepository)(nil)

// Insert 写入一条归并依据。
//
// 唯一约束是【部分唯一索引】 uk_claims_verified
//
//	(app_id, claim_type, claim_value_hash) WHERE verified = true AND revoked_at IS NULL
//
// 因此唯一冲突（SQLSTATE 23505）需要分两种情况处理，混为一谈会造成误报：
//
//	同一身份重复写入同一凭证（接入方重试、用户重新授权）→ 幂等，返回既有记录
//	另一个身份已验证过同一凭证                            → ErrClaimTaken，走冲突/合并流程
//
// 未验证的 claim 不参与唯一性判定，因此"用户手填手机号"不会占住号码
// ——这正是修正 P0-1 要解决的问题：原设计会让未验证的手填号码把唯一键占死，
// 导致真正通过平台验证的用户反而插不进来。
func (r *ClaimRepository) Insert(ctx context.Context, in identity.ClaimUpsertInput) (*identity.Claim, error) {
	if in.AppID <= 0 || in.IdentityID <= 0 {
		return nil, errs.New(errs.CodeInternal, "凭证写入缺少 app_id 或 identity_id")
	}
	if in.Type == "" || in.ValueHash == "" {
		return nil, errs.New(errs.CodeInternal, "凭证写入缺少类型或哈希")
	}
	if in.Source == "" {
		return nil, errs.New(errs.CodeInternal, "凭证写入缺少来源，无法进行 R4 白名单校验")
	}
	if !identity.IsValidSource(in.Source) {
		return nil, errs.Newf(errs.CodeInternal, "未知的凭证来源: %s（须与权威枚举一致）", in.Source).
			WithDetail("source", in.Source)
	}
	// 红线：未验证的凭证绝不允许标记为可信来源。
	if in.Verified && !identity.IsTrustedSource(in.Source) {
		return nil, errs.Newf(errs.CodeInternal,
			"来源 %s 不是平台已验证凭证，不允许标记 verified=true（R4 红线 1）", in.Source)
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, in.AppID)

	m := claimModel{
		AppID:            in.AppID,
		IdentityID:       in.IdentityID,
		ClaimType:        in.Type,
		ClaimValueHash:   in.ValueHash,
		ClaimValueCipher: in.ValueCipher,
		Verified:         in.Verified,
		Source:           in.Source,
		CreatedAt:        at,
	}
	if in.Verified {
		m.VerifiedAt = &at
	}

	err := r.db.WithContext(ctx).Create(&m).Error
	if err == nil {
		return claimToDomain(&m), nil
	}
	if !IsUniqueViolation(err) {
		return nil, errs.Wrap(errs.CodeInternal, "写入归并凭证失败", err)
	}

	// 唯一冲突：先看是不是同一个身份的重复写入。
	var existing claimModel
	lookupErr := r.db.WithContext(ctx).
		Where(`app_id = ? AND claim_type = ? AND claim_value_hash = ?
		       AND verified = true AND revoked_at IS NULL`,
			in.AppID, in.Type, in.ValueHash).
		Take(&existing).Error
	if lookupErr != nil {
		// 冲突了却查不到记录，说明并发下记录又被撤销了。让接入方重试即可。
		return nil, errs.Wrap(errs.CodeBindDuplicate, "凭证写入冲突，请重试", err).
			WithRetryable(true)
	}
	if existing.IdentityID == in.IdentityID {
		// 同一身份重复写入：幂等返回既有记录，不视为冲突。
		return claimToDomain(&existing), nil
	}
	return nil, identity.ErrClaimTaken.
		WithDetail("claim_type", in.Type).
		WithDetail("existing_identity_id", existing.IdentityID).
		WithDetail("incoming_identity_id", in.IdentityID)
}

// FindVerified 按已验证凭证反查归属身份。
func (r *ClaimRepository) FindVerified(ctx context.Context, appID int64, claimType, valueHash string) (*identity.Claim, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInternal, "凭证查询缺少 app_id")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var m claimModel
	err := r.db.WithContext(ctx).
		Where(`app_id = ? AND claim_type = ? AND claim_value_hash = ?
		       AND verified = true AND revoked_at IS NULL`,
			appID, claimType, valueHash).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, identity.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询归并凭证失败", err)
	}
	return claimToDomain(&m), nil
}

// ListByIdentity 列出某身份的全部有效凭证。
func (r *ClaimRepository) ListByIdentity(ctx context.Context, appID, identityID int64) ([]identity.Claim, error) {
	if appID <= 0 || identityID <= 0 {
		return nil, errs.New(errs.CodeInternal, "凭证查询参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var ms []claimModel
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND identity_id = ? AND revoked_at IS NULL", appID, identityID).
		Order("created_at").
		Find(&ms).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询归并凭证列表失败", err)
	}
	out := make([]identity.Claim, 0, len(ms))
	for i := range ms {
		out = append(out, *claimToDomain(&ms[i]))
	}
	return out, nil
}

// Revoke 撤销某身份下的指定凭证（换号 / 解绑）。
//
// 撤销后该号码即可被其他身份占用——这依赖部分唯一索引里的
// `WHERE revoked_at IS NULL` 条件（修正 P0-1 的第二半）。
func (r *ClaimRepository) Revoke(ctx context.Context, appID, identityID int64, claimType, valueHash string, at time.Time) error {
	if appID <= 0 || identityID <= 0 {
		return errs.New(errs.CodeInternal, "凭证撤销参数不完整")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, appID)

	res := r.db.WithContext(ctx).Model(&claimModel{}).
		Where(`app_id = ? AND identity_id = ? AND claim_type = ? AND claim_value_hash = ?
		       AND revoked_at IS NULL`,
			appID, identityID, claimType, valueHash).
		Update("revoked_at", at)
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "撤销归并凭证失败", res.Error)
	}
	return nil
}

func claimToDomain(m *claimModel) *identity.Claim {
	return &identity.Claim{
		ID:          m.ID,
		AppID:       m.AppID,
		IdentityID:  m.IdentityID,
		Type:        m.ClaimType,
		ValueHash:   m.ClaimValueHash,
		ValueCipher: m.ClaimValueCipher,
		Verified:    m.Verified,
		VerifiedAt:  m.VerifiedAt,
		Source:      m.Source,
		CreatedAt:   m.CreatedAt,
		RevokedAt:   m.RevokedAt,
	}
}
