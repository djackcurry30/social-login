package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// BindingRepository 是 oauth_bindings 表的仓储。
type BindingRepository struct {
	db *gorm.DB
}

// NewBindingRepository 构造仓储。
func NewBindingRepository(db *gorm.DB) *BindingRepository {
	return &BindingRepository{db: db}
}

var _ binding.Repository = (*BindingRepository)(nil)

// FindActiveByIdentity 查询某身份的活跃绑定。
func (r *BindingRepository) FindActiveByIdentity(ctx context.Context, appID, identityID int64) (*binding.Binding, error) {
	if appID <= 0 || identityID <= 0 {
		return nil, errs.New(errs.CodeInternal, "绑定查询参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var m bindingModel
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND identity_id = ? AND status = ?", appID, identityID, binding.StatusActive).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, binding.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询绑定关系失败", err)
	}
	return bindingToDomain(&m), nil
}

// ListActiveByExternalUser 列出某业务账号的全部活跃绑定。
func (r *BindingRepository) ListActiveByExternalUser(ctx context.Context, appID int64, externalUserID string) ([]binding.Binding, error) {
	if appID <= 0 || externalUserID == "" {
		return nil, errs.New(errs.CodeInternal, "绑定查询参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var ms []bindingModel
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND external_user_id = ? AND status = ?",
			appID, externalUserID, binding.StatusActive).
		Order("bound_at").
		Find(&ms).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询绑定列表失败", err)
	}
	out := make([]binding.Binding, 0, len(ms))
	for i := range ms {
		out = append(out, *bindingToDomain(&ms[i]))
	}
	return out, nil
}

// Activate 建立绑定。
//
// 并发安全靠数据库的部分唯一索引 uk_bindings_active 兜底，而不是分布式锁
// （架构 §5.2：更轻、更可靠）。做法是 INSERT ... ON CONFLICT DO NOTHING
// RETURNING id：冲突时返回 0 行，我们据此判定"已被占用"。
//
// alreadyExists=true 是【设计预期内的正常路径】，不是错误——用户在小程序
// 登录产生账号 B、之后在 App 登录产生账号 C、再在 C 里绑定"微信小程序"时，
// 必然命中这个分支，这正是需求 R1 要处理的主场景。
func (r *BindingRepository) Activate(ctx context.Context, in binding.ActivateInput) (*binding.Binding, bool, error) {
	if in.AppID <= 0 || in.IdentityID <= 0 || in.ExternalUserID == "" {
		return nil, false, errs.New(errs.CodeInternal, "绑定参数不完整")
	}
	if in.BindSource == "" {
		in.BindSource = binding.SourceLogin
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, in.AppID)

	m := bindingModel{
		AppID:          in.AppID,
		ExternalUserID: in.ExternalUserID,
		IdentityID:     in.IdentityID,
		Status:         binding.StatusActive,
		IsPrimary:      in.IsPrimary,
		BindSource:     in.BindSource,
		BoundAt:        at,
	}

	err := r.db.WithContext(ctx).Clauses(
		clause.OnConflict{DoNothing: true},
		clause.Returning{Columns: []clause.Column{{Name: "id"}}},
	).Create(&m).Error
	if err != nil {
		return nil, false, errs.Wrap(errs.CodeInternal, "建立绑定失败", err)
	}

	if m.ID != 0 {
		return bindingToDomain(&m), false, nil
	}

	// 冲突：该身份已被某个账号占用，返回既有绑定供上层走冲突策略。
	existing, err := r.FindActiveByIdentity(ctx, in.AppID, in.IdentityID)
	if err != nil {
		// 冲突了却查不到活跃绑定：只可能是并发下对方刚解绑。让调用方重试。
		return nil, false, errs.Wrap(errs.CodeBindDuplicate, "绑定冲突，请重试", err).
			WithRetryable(true)
	}
	return existing, true, nil
}

// Unbind 解绑（置 status=unbound，保留历史行用于审计）。
func (r *BindingRepository) Unbind(ctx context.Context, appID, identityID int64, at time.Time) error {
	if appID <= 0 || identityID <= 0 {
		return errs.New(errs.CodeInternal, "解绑参数不完整")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, appID)

	res := r.db.WithContext(ctx).Model(&bindingModel{}).
		Where("app_id = ? AND identity_id = ? AND status = ?", appID, identityID, binding.StatusActive).
		Updates(map[string]any{"status": binding.StatusUnbound, "unbound_at": at})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "解绑失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return binding.ErrNotFound
	}
	return nil
}

// CountActive 统计某业务账号的活跃绑定数。
func (r *BindingRepository) CountActive(ctx context.Context, appID int64, externalUserID string) (int, error) {
	if appID <= 0 || externalUserID == "" {
		return 0, errs.New(errs.CodeInternal, "绑定统计参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var n int64
	err := r.db.WithContext(ctx).Model(&bindingModel{}).
		Where("app_id = ? AND external_user_id = ? AND status = ?",
			appID, externalUserID, binding.StatusActive).
		Count(&n).Error
	if err != nil {
		return 0, errs.Wrap(errs.CodeInternal, "统计绑定数量失败", err)
	}
	return int(n), nil
}

func bindingToDomain(m *bindingModel) *binding.Binding {
	return &binding.Binding{
		ID:             m.ID,
		AppID:          m.AppID,
		ExternalUserID: m.ExternalUserID,
		IdentityID:     m.IdentityID,
		Status:         m.Status,
		IsPrimary:      m.IsPrimary,
		BindSource:     m.BindSource,
		BoundAt:        m.BoundAt,
		UnboundAt:      m.UnboundAt,
	}
}
