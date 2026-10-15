// 渠道配置仓储的 admin 端扩展（FindByID / UpdateStatus / UpdateSecretRotation / SoftDelete）。
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

// FindByID 跨应用查渠道配置（admin 端用）。
func (r *ProviderConfigRepository) FindByID(ctx context.Context, id int64) (*tenant.ProviderConfig, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	ctx = appctx.WithCrossAppScope(ctx)
	var m providerConfigModel
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查渠道配置失败", err)
	}
	return providerConfigToDomain(&m), nil
}

// UpdateStatus 启停渠道配置（status = 1 启用, 0 停用）。
func (r *ProviderConfigRepository) UpdateStatus(ctx context.Context, id int64, status int16) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if status != 0 && status != 1 {
		return errs.New(errs.CodeInvalidRequest, "status 必须为 0 或 1")
	}
	ctx = appctx.WithCrossAppScope(ctx)
	res := r.db.WithContext(ctx).Model(&providerConfigModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":     status,
			"updated_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "更新渠道状态失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// SoftDelete 软删渠道配置。
//
// 与 UpdateStatus(status=0) 的差别：这是"删除"语义，写审计时 action=delete。
// 实际只把 status 置 0（业务端 ListByApp 仍能看到，便于事后排查）；
// 真删是 admin 端专用的"清理已停用配置"接口（P2），本期不做。
func (r *ProviderConfigRepository) SoftDelete(ctx context.Context, id int64) error {
	return r.UpdateStatus(ctx, id, 0)
}

// UpdateSecretRotation 轮换凭据：把当前 secret 移到 prev，新 secret 写入。
//
// 关键不变量：prev 字段只保留"上一版"（E6 双活期），如果 prev 已有值，
// 直接覆盖——因为同时只可能有"上一版"和"当前版"两个有效凭据，保留更多反而是攻击面。
func (r *ProviderConfigRepository) UpdateSecretRotation(ctx context.Context, id int64, newCipher []byte, dekID string) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if len(newCipher) == 0 {
		return errs.New(errs.CodeInvalidRequest, "newCipher 不能为空")
	}
	if dekID == "" {
		return errs.New(errs.CodeInvalidRequest, "dekID 不能为空")
	}
	ctx = appctx.WithCrossAppScope(ctx)
	now := time.Now().UTC()

	// 事务：先读 prev，写 prev，再写新 secret。
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current providerConfigModel
		if err := tx.Where("id = ?", id).Take(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return tenant.ErrNotFound
			}
			return err
		}
		// 当前 secret → prev
		prevCipher := current.SecretCipher
		res := tx.Model(&providerConfigModel{}).
			Where("id = ?", id).
			Updates(map[string]any{
				"secret_cipher":      newCipher,
				"secret_cipher_prev": prevCipher,
				"secret_dek_id":      dekID,
				"secret_rotated_at":  now,
				"updated_at":         now,
				"version":            gorm.Expr("app_provider_configs.version + 1"),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return tenant.ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			return tenant.ErrNotFound
		}
		return errs.Wrap(errs.CodeInternal, "轮换凭据失败", err)
	}
	return nil
}

// FinalizeSecret 结束轮换过渡期：清空 prev。
func (r *ProviderConfigRepository) FinalizeSecret(ctx context.Context, id int64) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	ctx = appctx.WithCrossAppScope(ctx)
	res := r.db.WithContext(ctx).Model(&providerConfigModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"secret_cipher_prev": nil,
			"updated_at":         time.Now().UTC(),
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "结束凭据过渡期失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// 抑制 unused
var _ = fmt.Sprintf
