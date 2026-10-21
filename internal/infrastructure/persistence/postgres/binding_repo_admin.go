package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// BindingAdminRepository 是管理端 C 组对绑定的查询与干预。
type BindingAdminRepository struct {
	db *gorm.DB
}

// NewBindingAdminRepository 构造仓储。
func NewBindingAdminRepository(db *gorm.DB) *BindingAdminRepository {
	return &BindingAdminRepository{db: db}
}

var (
	_ binding.AdminLister = (*BindingAdminRepository)(nil)
	_ binding.AdminWriter = (*BindingAdminRepository)(nil)
)

// ListAdmin 按条件查询绑定（含已解绑历史）。
func (r *BindingAdminRepository) ListAdmin(ctx context.Context, f binding.AdminFilter) ([]binding.Binding, int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	apply := func(q *gorm.DB) *gorm.DB {
		if f.AppID > 0 {
			q = q.Where("app_id = ?", f.AppID)
		}
		if f.ExternalUserID != "" {
			q = q.Where("external_user_id = ?", f.ExternalUserID)
		}
		if f.Status != "" {
			q = q.Where("status = ?", f.Status)
		}
		if f.IdentityID > 0 {
			q = q.Where("identity_id = ?", f.IdentityID)
		}
		return q
	}

	var total int64
	if err := apply(r.db.WithContext(ctx).Model(&bindingModel{})).
		Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计绑定失败", err)
	}

	page, size := f.Page, f.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}

	var rows []bindingModel
	if err := apply(r.db.WithContext(ctx).Model(&bindingModel{})).
		Order("id DESC").Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询绑定失败", err)
	}

	out := make([]binding.Binding, 0, len(rows))
	for i := range rows {
		out = append(out, *bindingToDomain(&rows[i]))
	}
	return out, total, nil
}

// ForceUnbind 强制解绑，并在同一事务内写 outbox 事件。
func (r *BindingAdminRepository) ForceUnbind(ctx context.Context, in binding.AdminUnbindInput) (*binding.Binding, error) {
	// 路径里只有 binding id，没有 app_id；而写入事件与审计需要应用作用域。
	// 先用显式跨应用作用域读出这条绑定，拿到它真正的 app_id，
	// 之后所有写入都用这个值——绝不能由调用方"猜"应用归属。
	ctx = appctx.WithCrossAppScope(ctx)

	var result *binding.Binding
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var m bindingModel
		q := tx.Where("id = ?", in.BindingID)
		if in.AppID > 0 {
			q = q.Where("app_id = ?", in.AppID)
		}
		if err := q.Take(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errs.New(errs.CodeNotFound, "绑定不存在")
			}
			return errs.Wrap(errs.CodeInternal, "查询绑定失败", err)
		}
		if m.Status != binding.StatusActive {
			// 已解绑的再解一次：返回成功但不产生新事件（幂等），
			// 避免客服重复点击产生一串重复通知。
			result = bindingToDomain(&m)
			return nil
		}
		now := in.At
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if err := tx.Model(&bindingModel{}).
			Where("id = ? AND status = ?", m.ID, binding.StatusActive).
			Updates(map[string]any{
				"status":     binding.StatusUnbound,
				"unbound_at": now,
			}).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "解绑失败", err)
		}
		m.Status = binding.StatusUnbound
		m.UnboundAt = &now
		result = bindingToDomain(&m)

		if in.Event != nil {
			if err := writeOutboxEvent(tx, m.AppID, in.Event, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Transfer 把 identity 从原账号转到新账号（原账号保留）。
//
// 与合并的差别（§7.2）：transfer 只动这一条绑定，不迁移任何账号数据，
// 也不撤销令牌——原账号仍然可以正常登录，只是少了这一个登录方式。
// 因此它是低风险旁路，供"客服确认该微信实际属于另一个账号"这类场景使用。
func (r *BindingAdminRepository) Transfer(ctx context.Context, in binding.AdminTransferInput) (*binding.Binding, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	var result *binding.Binding
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var m bindingModel
		q := tx.Where("id = ?", in.BindingID)
		if in.AppID > 0 {
			q = q.Where("app_id = ?", in.AppID)
		}
		if err := q.Take(&m).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errs.New(errs.CodeNotFound, "绑定不存在")
			}
			return errs.Wrap(errs.CodeInternal, "查询绑定失败", err)
		}
		if m.Status != binding.StatusActive {
			return errs.New(errs.CodeInvalidRequest, "只能转移生效中的绑定")
		}
		if m.ExternalUserID == in.TargetUser {
			// 转给自己：幂等成功，不重复写事件。
			result = bindingToDomain(&m)
			return nil
		}

		// 目标账号是否已经绑定了这个 identity？
		// uk_bindings_active 是 (identity_id) 上的部分唯一索引，改挂后仍然只有一条
		// active 记录，因此这里只需确认"没有别的 active 行"，冲突会由索引兜底。
		var conflict int64
		if err := tx.Model(&bindingModel{}).
			Where("identity_id = ? AND status = ? AND id <> ?", m.IdentityID, binding.StatusActive, m.ID).
			Count(&conflict).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "检查绑定冲突失败", err)
		}
		if conflict > 0 {
			return errs.New(errs.CodeBindIdentityTaken, "该身份已存在其他生效绑定，请先解绑")
		}

		now := in.At
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if err := tx.Model(&bindingModel{}).
			Where("id = ?", m.ID).
			Updates(map[string]any{
				"external_user_id": in.TargetUser,
				"bind_source":      binding.SourceAdmin,
				"bound_at":         now,
			}).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "转移绑定失败", err)
		}
		from := m.ExternalUserID
		m.ExternalUserID = in.TargetUser
		m.BindSource = binding.SourceAdmin
		m.BoundAt = now
		result = bindingToDomain(&m)

		if in.Event != nil {
			// payload 里带上 from/to，业务方才能同时更新两侧的账号数据。
			in.Event.Payload["from_user_id"] = from
			in.Event.Payload["to_user_id"] = in.TargetUser
			if err := writeOutboxEvent(tx, m.AppID, in.Event, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// writeOutboxEvent 在事务内写一条待投递事件。
func writeOutboxEvent(tx *gorm.DB, appID int64, e *binding.AdminEvent, at time.Time) error {
	if e == nil {
		return nil
	}
	m := &eventOutboxModel{
		AppID:         appID,
		EventID:       e.EventID,
		EventType:     e.Type,
		SchemaVersion: e.SchemaVersion,
		Payload:       jsonNotNull(e.Payload),
		Status:        "pending",
		CreatedAt:     at,
	}
	if err := tx.Create(m).Error; err != nil {
		return errs.Wrap(errs.CodeInternal, "写入事件失败", err)
	}
	return nil
}
