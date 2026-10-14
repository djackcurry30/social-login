// Package tenantconfig 是应用与渠道配置的用例层。
//
// 它的核心职责只有一件：把"某个业务应用在某接入场景下的渠道凭据"解析出来，
// 并在这一处完成密文解密（决策 D6 的唯一解密点，便于审计）。
package tenantconfig

import (
	"context"
	"errors"

	"github.com/alex/social-login/internal/domain/provider"
	"github.com/alex/social-login/internal/domain/tenant"
	"github.com/alex/social-login/internal/pkg/errs"
)

// Options 是构造参数。
type Options struct {
	// Env 是当前部署环境（prod | test），用于筛选渠道配置（扩展性 E5）。
	Env string
}

// Service 提供应用与渠道配置查询。
type Service struct {
	apps    tenant.ApplicationRepository
	configs tenant.ProviderConfigRepository
	secrets tenant.SecretResolver
	env     string
}

// New 构造服务。
func New(opts Options, apps tenant.ApplicationRepository, configs tenant.ProviderConfigRepository, secrets tenant.SecretResolver) *Service {
	env := opts.Env
	if env == "" {
		env = "prod"
	}
	return &Service{apps: apps, configs: configs, secrets: secrets, env: env}
}

// Application 按对外 app_id 加载并校验应用。
func (s *Service) Application(ctx context.Context, appCode string) (*tenant.Application, error) {
	if appCode == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "缺少 app_id").
			WithDetail("field", "app_id")
	}
	app, err := s.apps.FindByAppCode(ctx, appCode)
	if errors.Is(err, tenant.ErrNotFound) {
		// 不区分"不存在"与"未授权"，避免通过错误信息枚举 app_id（架构 §10.1 用户枚举）。
		return nil, errs.New(errs.CodeUnauthorized, "app_id 无效或应用未启用").
			WithDetail("app_id", appCode)
	}
	if err != nil {
		return nil, err
	}
	if !app.Enabled() {
		return nil, errs.New(errs.CodeAuthAppDisabled, "应用已停用").
			WithDetail("app_id", appCode)
	}
	if app.AccountMode != tenant.AccountModeRemote {
		// 约束 C4：账号模式固定为 remote。出现其它值说明数据被人工改过，
		// 属于需要修数据的信号，不能静默按 remote 处理。
		return nil, errs.Newf(errs.CodeAuthInvalidConfig,
			"应用 %s 的 account_mode=%s，与约束 C4（remote）不符", appCode, app.AccountMode).
			WithDetail("account_mode", app.AccountMode)
	}
	return app, nil
}

// Channel 是解析后的渠道，包含配置与已解密的凭据。
type Channel struct {
	Config *tenant.ProviderConfig
	// Creds 承载明文密钥，【禁止写入日志与错误 details】。
	Creds provider.Credentials
}

// Channel 解析某业务应用在某接入场景下的渠道配置与凭据。
//
// 查找键是 (app_id, platform, scene, config_key) + env，【不含承载形态】：
// iOS 与 Android 都命中 wechat:app 的同一份配置（规则 2）。
func (s *Service) Channel(ctx context.Context, appID int64, platform, scene, configKey string) (*Channel, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInternal, "解析渠道配置缺少 app_id")
	}
	cfg, err := s.configs.Find(ctx, appID, platform, scene, configKey, s.env)
	if errors.Is(err, tenant.ErrNotFound) {
		return nil, errs.Newf(errs.CodeProviderNotFound, "渠道未配置或未启用: %s", provider.Key(platform, scene)).
			WithDetail("platform", platform).
			WithDetail("scene", scene).
			WithDetail("config_key", configKey).
			WithDetail("env", s.env)
	}
	if err != nil {
		return nil, err
	}

	secret, prev, err := s.secrets.Resolve(cfg)
	if err != nil {
		return nil, err
	}
	return &Channel{
		Config: cfg,
		Creds: provider.Credentials{
			ProviderAppID:  cfg.ProviderAppID,
			Secret:         secret,
			PreviousSecret: prev,
			Extra:          cfg.Extra,
		},
	}, nil
}

// ListChannels 列出某应用的渠道配置（管理端使用，不返回凭据明文）。
func (s *Service) ListChannels(ctx context.Context, appID int64) ([]tenant.ProviderConfig, error) {
	return s.configs.ListByApp(ctx, appID)
}

// Env 返回当前环境。
func (s *Service) Env() string { return s.env }
