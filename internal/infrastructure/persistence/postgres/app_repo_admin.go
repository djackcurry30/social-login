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

	"gorm.io/gorm"

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

// WebhookConfig 读取应用的事件投递配置（管理端与 worker 共用）。
//
// 返回的 secretEnc 是【密文】，解密由投递器侧用 KeyManager 完成：
// 仓储不持有密钥材料，避免"能读库的组件也能拿到明文签名密钥"。
func (r *AppRepository) WebhookConfig(ctx context.Context, appID int64) (appCode, url string, secretEnc []byte, kid string, err error) {
	if appID <= 0 {
		return "", "", nil, "", errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	ctx = appctx.WithCrossAppScope(ctx)
	var row struct {
		AppCode    string
		WebhookURL *string
		SecretEnc  []byte
		SecretKid  *string
	}
	res := r.db.WithContext(ctx).Model(&applicationModel{}).
		Select("app_code, webhook_url, webhook_secret_enc, webhook_secret_kid").
		Where("id = ?", appID).
		Take(&row)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return "", "", nil, "", tenant.ErrNotFound
	}
	if res.Error != nil {
		return "", "", nil, "", errs.Wrap(errs.CodeInternal, "读取应用投递配置失败", res.Error)
	}
	if row.WebhookURL != nil {
		url = *row.WebhookURL
	}
	if row.SecretKid != nil {
		kid = *row.SecretKid
	}
	return row.AppCode, url, row.SecretEnc, kid, nil
}

// SetWebhook 保存事件投递配置。
//
// url 为空表示"关闭外发"：此后该应用的事件在 outbox 里会被标记为 skipped，
// 而不是伪装成 sent。secretEnc 为 nil 时保留原密钥（只改地址的场景不必重传密钥）。
func (r *AppRepository) SetWebhook(ctx context.Context, appID int64, url string, secretEnc []byte, kid string) error {
	if appID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	ctx = appctx.WithCrossAppScope(ctx)

	updates := map[string]any{
		"webhook_url": url,
		"updated_at":  time.Now().UTC(),
	}
	if len(secretEnc) > 0 {
		updates["webhook_secret_enc"] = secretEnc
		updates["webhook_secret_kid"] = kid
	}
	res := r.db.WithContext(ctx).Model(&applicationModel{}).
		Where("id = ?", appID).
		Updates(updates)
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "保存投递配置失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return tenant.ErrNotFound
	}
	return nil
}
