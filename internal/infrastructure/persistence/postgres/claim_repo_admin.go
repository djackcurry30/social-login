package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// ClaimAdminRepository 提供管理端 J 组的凭证多维查询。
//
// 与 IdentityAdminRepository 同构：核心 ClaimRepository 只承担授权链路用到的
// 精确操作（Insert / FindVerified / FindByID / Revoke），运维需要的跨身份分页
// 与"看已撤销记录"单独放在这里。
type ClaimAdminRepository struct {
	db *gorm.DB
}

// NewClaimAdminRepository 构造仓储。
func NewClaimAdminRepository(db *gorm.DB) *ClaimAdminRepository {
	return &ClaimAdminRepository{db: db}
}

var _ identity.ClaimAdminLister = (*ClaimAdminRepository)(nil)

// ListAdmin 按应用 / 类型 / 身份 / 状态分页查询凭证。
//
// 状态筛选是本方法存在的核心理由：运维排查"这个手机号为什么被释放了"
// 需要看 revoked_at 非空的记录，而 ListByIdentity 恒过滤掉它们。
func (r *ClaimAdminRepository) ListAdmin(ctx context.Context, q identity.ClaimAdminQuery) ([]identity.Claim, int64, error) {
	// 管理端天然跨应用：显式声明后用 q.AppID 做业务过滤。
	ctx = appctx.WithCrossAppScope(ctx)

	apply := func(db *gorm.DB) *gorm.DB {
		if q.AppID > 0 {
			db = db.Where("app_id = ?", q.AppID)
		}
		if q.ClaimType != "" {
			db = db.Where("claim_type = ?", q.ClaimType)
		}
		if q.IdentityID > 0 {
			db = db.Where("identity_id = ?", q.IdentityID)
		}
		switch q.Status {
		case identity.ClaimStatusVerified:
			db = db.Where("verified = true AND revoked_at IS NULL")
		case identity.ClaimStatusUnverified:
			db = db.Where("verified = false AND revoked_at IS NULL")
		case identity.ClaimStatusRevoked:
			db = db.Where("revoked_at IS NOT NULL")
		}
		return db
	}

	base := func() *gorm.DB {
		return r.db.WithContext(ctx).Model(&claimModel{})
	}

	var total int64
	if err := apply(base()).Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计归并凭证失败", err)
	}

	page, size := q.Page, q.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}

	var ms []claimModel
	if err := apply(base()).
		Order("id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&ms).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询归并凭证失败", err)
	}

	out := make([]identity.Claim, 0, len(ms))
	for i := range ms {
		out = append(out, *claimToDomain(&ms[i]))
	}
	return out, total, nil
}
