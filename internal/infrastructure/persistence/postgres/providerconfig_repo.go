package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// DefaultConfigKey 是渠道配置的默认 config_key。
const DefaultConfigKey = "default"

// DefaultEnv 是渠道配置的默认环境。
const DefaultEnv = "prod"

// ProviderConfigRepository 是 app_provider_configs 表的仓储。
type ProviderConfigRepository struct {
	db *gorm.DB
}

// NewProviderConfigRepository 构造仓储。
func NewProviderConfigRepository(db *gorm.DB) *ProviderConfigRepository {
	return &ProviderConfigRepository{db: db}
}

var _ tenant.ProviderConfigRepository = (*ProviderConfigRepository)(nil)

// Find 精确查找一份渠道配置。
//
// 查找键是四元组 (app_id, platform, scene, config_key) 加环境。
// 【不含承载形态】—— iOS 与 Android 都命中 wechat:app 的同一份配置（规则 2）。
func (r *ProviderConfigRepository) Find(ctx context.Context, appID int64, platform, scene, configKey, env string) (*tenant.ProviderConfig, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInternal, "渠道配置查询缺少 app_id")
	}
	if !provider.IsValidScene(platform, scene) {
		return nil, errs.Newf(errs.CodeProviderNotFound, "非法或不支持的接入场景: %s:%s", platform, scene).
			WithDetail("platform", platform).
			WithDetail("scene", scene).
			WithDetail("valid_scenes", provider.ScenesOf(platform))
	}
	if configKey == "" {
		configKey = DefaultConfigKey
	}
	if env == "" {
		env = DefaultEnv
	}
	// 该表按应用隔离，必须显式建立作用域（否则回调会 panic，这正是设计意图）。
	ctx = appctx.WithAppScope(ctx, appID)

	var m providerConfigModel
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND platform = ? AND scene = ? AND config_key = ? AND env = ? AND status = 1",
			appID, platform, scene, configKey, env).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询渠道配置失败", err)
	}
	return providerConfigToDomain(&m), nil
}

// ListByApp 列出某应用的全部渠道配置（管理端与引导绑定页需要）。
func (r *ProviderConfigRepository) ListByApp(ctx context.Context, appID int64) ([]tenant.ProviderConfig, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInternal, "渠道配置查询缺少 app_id")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var ms []providerConfigModel
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("platform, scene, config_key, env").
		Find(&ms).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询渠道配置列表失败", err)
	}
	out := make([]tenant.ProviderConfig, 0, len(ms))
	for i := range ms {
		out = append(out, *providerConfigToDomain(&ms[i]))
	}
	return out, nil
}

// Upsert 插入或更新渠道配置（供引导脚本与管理端使用）。
//
// secretCipher 由调用方用 crypto.KeyManager 加密后传入——仓储层永远不接触明文。
func (r *ProviderConfigRepository) Upsert(ctx context.Context, cfg *tenant.ProviderConfig) (*tenant.ProviderConfig, error) {
	if cfg == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "渠道配置为空")
	}
	if cfg.AppID <= 0 {
		return nil, errs.New(errs.CodeInternal, "渠道配置缺少 app_id")
	}
	if !provider.IsValidScene(cfg.Platform, cfg.Scene) {
		return nil, errs.Newf(errs.CodeConfigInvalid, "非法或不支持的接入场景: %s:%s", cfg.Platform, cfg.Scene).
			WithDetail("valid_scenes", provider.ScenesOf(cfg.Platform))
	}
	if cfg.ConfigKey == "" {
		cfg.ConfigKey = DefaultConfigKey
	}
	if cfg.Env == "" {
		cfg.Env = DefaultEnv
	}
	ctx = appctx.WithAppScope(ctx, cfg.AppID)

	now := time.Now().UTC()
	m := providerConfigModel{
		AppID:            cfg.AppID,
		Platform:         cfg.Platform,
		Scene:            cfg.Scene,
		ConfigKey:        cfg.ConfigKey,
		ProviderAppID:    cfg.ProviderAppID,
		SecretCipher:     cfg.SecretCipher,
		SecretCipherPrev: cfg.SecretCipherPrev,
		SecretRotatedAt:  cfg.SecretRotatedAt,
		SecretDEKID:      cfg.SecretDEKID,
		Env:              cfg.Env,
		Extra:            cfg.Extra,
		Version:          1,
		Status:           1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if cfg.Status != 0 {
		m.Status = cfg.Status
	}

	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "app_id"}, {Name: "platform"}, {Name: "scene"},
			{Name: "config_key"}, {Name: "env"},
		},
		DoUpdates: clause.Assignments(map[string]any{
			"provider_app_id": m.ProviderAppID,
			"secret_cipher":   m.SecretCipher,
			"secret_dek_id":   m.SecretDEKID,
			"extra":           m.Extra,
			"status":          m.Status,
			"updated_at":      m.UpdatedAt,
			"version":         gorm.Expr("app_provider_configs.version + 1"),
		}),
	}).Create(&m).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "保存渠道配置失败", err)
	}
	return providerConfigToDomain(&m), nil
}

func providerConfigToDomain(m *providerConfigModel) *tenant.ProviderConfig {
	return &tenant.ProviderConfig{
		ID:               m.ID,
		AppID:            m.AppID,
		Platform:         m.Platform,
		Scene:            m.Scene,
		ConfigKey:        m.ConfigKey,
		ProviderAppID:    m.ProviderAppID,
		SecretCipher:     m.SecretCipher,
		SecretCipherPrev: m.SecretCipherPrev,
		SecretRotatedAt:  m.SecretRotatedAt,
		SecretDEKID:      m.SecretDEKID,
		Env:              m.Env,
		Extra:            m.Extra,
		Version:          m.Version,
		Status:           m.Status,
		CreatedAt:        m.CreatedAt,
		UpdatedAt:        m.UpdatedAt,
	}
}
