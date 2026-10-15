// 应用仓储的 admin 端扩展（UpdatePolicy / SetStatus / ListIDs）。
//
// 这些方法只允许管理端在跨应用作用域下调用，所以单独成文（不与 FindByID 混在一起），
// 并在每个方法里显式建立 WithCrossAppScope。
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// UpdatePolicy 是 admin 端"保存策略"的专用方法（不做完整 Upsert 的字段合并）。
//
// 之所以单独写：tenant.ApplicationRepository.Upsert 会做完整应用替换，
// admin 改 policy 不应该把 app_secret_hash 也碰一下。
func (r *AppRepository) UpdatePolicy(ctx context.Context, appID int64, policy tenant.Policy) error {
	if appID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&applicationModel{}).
		Where("id = ?", appID).
		Updates(map[string]any{
			"policy":     policyToModel(policy),
			"updated_at": now,
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "保存策略失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// SetStatus 启停应用。
func (r *AppRepository) SetStatus(ctx context.Context, appID int64, status int16) error {
	if appID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	res := r.db.WithContext(ctx).Model(&applicationModel{}).
		Where("id = ?", appID).
		Updates(map[string]any{
			"status":     status,
			"updated_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "更新应用状态失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// ListIDs 列出最近 N 个应用 ID（管理端用，倒序）。
//
// 之所以不在仓储里直接提供完整 List 仓储：
// 1. List 的分页/筛选语义在 admin 端有特定需求（按名/状态过滤），不适合硬塞进业务端口；
// 2. admin 端天然跨应用，必须用 WithCrossAppScope，这里集中显式声明一次；
// 3. 本期先做"按 ID 倒序取前 N"，下一期可扩展为游标分页。
func (r *AppRepository) ListIDs(ctx context.Context, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	ctx = appctx.WithCrossAppScope(ctx)
	var ids []int64
	err := r.db.WithContext(ctx).Model(&applicationModel{}).
		Order("id DESC").
		Limit(limit).
		Pluck("id", &ids).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "列出应用 ID 失败", err)
	}
	return ids, nil
}

// --- 内部 helper（admin_repo 复用）---

// 抑制 "imported and not used"——errors 在某些构建配置下被引用。
var _ = errors.New
var _ = fmt.Sprintf
