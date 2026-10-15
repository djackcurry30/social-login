// Package adminchan 是管理端"渠道配置（B 组）"用例。
//
// 职责严格按 §15.4 B 组限定：
//   - provider-configs CRUD + secret:rotate + secret:finalize + secret:verify
//   - enable / disable
//
// 所有写操作自动写 admin_audit_logs。
package adminchan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// Deps 是用例依赖。
type Deps struct {
	TenantConfigs tenant.ProviderConfigRepository
	TenantSecrets tenant.SecretResolver
	// EncryptSecret 是新明文密钥的加密入口（注入 KeyManager，避免本包依赖 infra/crypto）。
	EncryptSecret func(plain string) (ciphertext []byte, dekID string, err error)
	AdminAudit    admin.AuditWriter
	Logger        *zap.Logger
	// Now 可注入。
	Now func() time.Time
	// VerifyHTTP 注入"对 token_url 调一次 client_credentials"的能力。
	// 生产用 httpx.Client，测试可注入桩。
	VerifyHTTP func(ctx context.Context, tokenURL, clientID, clientSecret string) (latency time.Duration, err error)
}

// Service 是 B 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: d}
}

// CreateConfigInput 是 POST /admin/v1/apps/{appId}/provider-configs 的入参。
type CreateConfigInput struct {
	AppID         int64           `json:"app_id"`
	Platform      string          `json:"platform" binding:"required"`
	Scene         string          `json:"scene" binding:"required"`
	ConfigKey     string          `json:"config_key"`
	Env           string          `json:"env"`
	ProviderAppID string          `json:"provider_app_id" binding:"required"`
	ClientSecret  string          `json:"client_secret" binding:"required"` // 明文，仅在创建/轮换时上传
	Extra         map[string]any  `json:"extra,omitempty"`
	Reason        string          `json:"reason" binding:"required"`
	Principal     *admin.Principal
}

// CreateConfig 创建渠道配置。
//
// 关键不变量：platform/scene 走权威枚举白名单校验（E4），防止拼写错误入库；
// 凭据加密后入库，明文不出调用方边界。
func (s *Service) CreateConfig(ctx context.Context, in CreateConfigInput) (*tenant.ProviderConfig, error) {
	if in.AppID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	if in.Platform == "" || in.Scene == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "platform/scene 必填")
	}
	if !provider.IsValidScene(in.Platform, in.Scene) {
		return nil, errs.Newf(errs.CodeConfigInvalid, "非法或不支持的接入场景: %s:%s", in.Platform, in.Scene).
			WithDetail("platform", in.Platform).
			WithDetail("scene", in.Scene).
			WithDetail("valid_scenes", provider.ScenesOf(in.Platform))
	}
	if in.ProviderAppID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "provider_app_id 必填")
	}
	if in.ClientSecret == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "client_secret 必填")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（config.create）必须填写 reason（≥4 字符）")
	}
	if in.ConfigKey == "" {
		in.ConfigKey = "default"
	}
	if in.Env == "" {
		in.Env = "prod"
	}

	cipher, dekID, err := s.deps.EncryptSecret(in.ClientSecret)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "加密凭据失败", err)
	}

	cfg := &tenant.ProviderConfig{
		AppID:         in.AppID,
		Platform:      in.Platform,
		Scene:         in.Scene,
		ConfigKey:     in.ConfigKey,
		ProviderAppID: in.ProviderAppID,
		SecretCipher:  cipher,
		SecretDEKID:   dekID,
		Env:           in.Env,
		Extra:         in.Extra,
		Status:        1,
	}
	created, err := s.deps.TenantConfigs.Upsert(ctx, cfg)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "config.create", "provider_config",
			fmt.Sprintf("%s:%s/%s", in.Platform, in.Scene, in.ConfigKey),
			in.Reason, nil, configToState(created), "error", err)
		return nil, err
	}
	s.writeAudit(ctx, in.Principal, "config.create", "provider_config", fmt.Sprintf("%d", created.ID),
		in.Reason, nil, configToState(created), "success", nil)
	return created, nil
}

// UpdateConfigInput 是 PATCH /admin/v1/apps/{appId}/provider-configs/{id} 的入参。
type UpdateConfigInput struct {
	Extra     map[string]any
	Reason    string
	Principal *admin.Principal
}

// UpdateConfig 改 extra / env / config_key 等非凭据字段。
//
// 凭据走专用的 secret:rotate 流程，不允许在 PATCH 中改。
func (s *Service) UpdateConfig(ctx context.Context, id int64, in UpdateConfigInput) (*tenant.ProviderConfig, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（config.update）必须填写 reason（≥4 字符）")
	}
	current, err := s.findByID(ctx, id)
	if err != nil {
		return nil, err
	}
	before := configToState(current)
	if in.Extra != nil {
		current.Extra = in.Extra
	}
	updated, err := s.deps.TenantConfigs.Upsert(ctx, current)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "config.update", "provider_config", fmt.Sprintf("%d", id),
			in.Reason, before, nil, "error", err)
		return nil, err
	}
	s.writeAudit(ctx, in.Principal, "config.update", "provider_config", fmt.Sprintf("%d", id),
		in.Reason, before, configToState(updated), "success", nil)
	return updated, nil
}

// RotateSecretInput 是 POST .../secret:rotate 的入参。
type RotateSecretInput struct {
	NewSecret   string
	Reason      string
	Principal   *admin.Principal
}

// RotateSecretOutput 是轮换出参。
type RotateSecretOutput struct {
	RotatedAt time.Time `json:"rotated_at"`
}

// RotateSecret 轮换凭据。
//
// 新 secret 加密后写入 secret_cipher；旧 secret 移到 secret_cipher_prev。
// 调用方拿到的是时间戳——旧凭据在过渡期（prev 非空）继续可用，
// 直到 finalize 被调用或 max_transition_period（配置项）过期。
func (s *Service) RotateSecret(ctx context.Context, id int64, in RotateSecretInput) (*RotateSecretOutput, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if in.NewSecret == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "new_secret 必填")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（config.rotate）必须填写 reason（≥4 字符）")
	}
	current, err := s.findByID(ctx, id)
	if err != nil {
		return nil, err
	}
	before := configToState(current)
	cipher, dekID, err := s.deps.EncryptSecret(in.NewSecret)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "加密新凭据失败", err)
	}
	if err := s.deps.TenantConfigs.UpdateSecretRotation(ctx, id, cipher, dekID); err != nil {
		s.writeAudit(ctx, in.Principal, "config.rotate", "provider_config", fmt.Sprintf("%d", id),
			in.Reason, before, nil, "error", err)
		return nil, err
	}
	after := before
	after["secret_cipher_prev_set"] = true
	after["secret_dek_id"] = dekID
	s.writeAudit(ctx, in.Principal, "config.rotate", "provider_config", fmt.Sprintf("%d", id),
		in.Reason, before, after, "success", nil)
	return &RotateSecretOutput{RotatedAt: s.deps.Now()}, nil
}

// FinalizeSecret 结束轮换过渡期：清空 prev。
func (s *Service) FinalizeSecret(ctx context.Context, id int64, principal *admin.Principal, reason string) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if reason == "" || len([]rune(reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired,
			"高危操作（config.finalize）必须填写 reason（≥4 字符）")
	}
	current, err := s.findByID(ctx, id)
	if err != nil {
		return err
	}
	before := configToState(current)
	if err := s.deps.TenantConfigs.FinalizeSecret(ctx, id); err != nil {
		s.writeAudit(ctx, principal, "config.finalize", "provider_config", fmt.Sprintf("%d", id),
			reason, before, nil, "error", err)
		return err
	}
	after := before
	after["secret_cipher_prev_set"] = false
	s.writeAudit(ctx, principal, "config.finalize", "provider_config", fmt.Sprintf("%d", id),
		reason, before, after, "success", nil)
	return nil
}

// VerifyConfigInput 是 POST .../secret:verify 的入参。
type VerifyConfigInput struct {
	Reason    string
	Principal *admin.Principal
}

// VerifyConfigOutput 是连通性校验结果。
type VerifyConfigOutput struct {
	OK        bool          `json:"ok"`
	LatencyMs int64         `json:"latency_ms"`
	Error     string        `json:"error,omitempty"`
	HTTPStatus int          `json:"http_status,omitempty"`
	ProviderError string    `json:"provider_error,omitempty"`
}

// VerifyConfig 连通性校验。
//
// 做法：从 extra 读 token_url，POST client_credentials 一次；用平台真实凭据真实调一次。
// 不存任何响应（验签成功后只回写 ok + 耗时）。
//
// 返回的 ok 取决于平台返回 access_token；如果是 401 / invalid_client，则 ok=false。
func (s *Service) VerifyConfig(ctx context.Context, id int64, in VerifyConfigInput) (*VerifyConfigOutput, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（config.verify）必须填写 reason（≥4 字符）")
	}
	current, err := s.findByID(ctx, id)
	if err != nil {
		return nil, err
	}
	tokenURL, _ := current.Extra["token_url"].(string)
	if tokenURL == "" {
		return nil, errs.New(errs.CodeConfigInvalid, "extra.token_url 未配置").
			WithDetail("field", "extra.token_url")
	}
	if s.deps.VerifyHTTP == nil {
		return nil, errs.New(errs.CodeInternal, "未注入 VerifyHTTP")
	}
	// 解密（明文仅在这一次调用中出现）
	secretPlain, _, err := s.deps.TenantSecrets.Resolve(current)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "解密凭据失败", err)
	}
	// 给 verify 一个独立的 5s 截止（与正式 Exchange 同档）——快速失败是 verify 的灵魂。
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	latency, verifyErr := s.deps.VerifyHTTP(verifyCtx, tokenURL, current.ProviderAppID, secretPlain)
	_ = secretPlain
	out := &VerifyConfigOutput{
		OK:        verifyErr == nil,
		LatencyMs: latency.Milliseconds(),
	}
	result := "success"
	if verifyErr != nil {
		out.Error = verifyErr.Error()
		result = "error"
		// 若 verifyErr 携带了 HTTP 状态与平台错误码，从 details 里抽出来
		if e, ok := errs.As(verifyErr); ok {
			for k, v := range e.Details {
				if k == "http_status" {
					if s, ok := v.(int); ok {
						out.HTTPStatus = s
					}
				}
				if k == "provider_error" {
					if s, ok := v.(string); ok {
						out.ProviderError = s
					}
				}
			}
		}
	}
	s.writeAudit(ctx, in.Principal, "config.verify", "provider_config", fmt.Sprintf("%d", id),
		in.Reason, nil, map[string]any{
			"ok":         out.OK,
			"latency_ms": out.LatencyMs,
			"http_status": out.HTTPStatus,
		}, result, verifyErr)
	return out, nil
}

// Enable / Disable 启停渠道。
func (s *Service) Enable(ctx context.Context, id int64, principal *admin.Principal, reason string) error {
	return s.setStatus(ctx, id, 1, "config.enable", principal, reason)
}
func (s *Service) Disable(ctx context.Context, id int64, principal *admin.Principal, reason string) error {
	return s.setStatus(ctx, id, 0, "config.disable", principal, reason)
}

func (s *Service) setStatus(ctx context.Context, id int64, status int16, action string, principal *admin.Principal, reason string) error {
	if reason == "" || len([]rune(reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired,
			"高危操作（"+action+"）必须填写 reason（≥4 字符）")
	}
	current, err := s.findByID(ctx, id)
	if err != nil {
		return err
	}
	before := configToState(current)
	if err := s.deps.TenantConfigs.UpdateStatus(ctx, id, status); err != nil {
		s.writeAudit(ctx, principal, action, "provider_config", fmt.Sprintf("%d", id),
			reason, before, nil, "error", err)
		return err
	}
	after := before
	after["status"] = status
	s.writeAudit(ctx, principal, action, "provider_config", fmt.Sprintf("%d", id),
		reason, before, after, "success", nil)
	return nil
}

// Delete 软删。
func (s *Service) Delete(ctx context.Context, id int64, principal *admin.Principal, reason string) error {
	if reason == "" || len([]rune(reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired,
			"高危操作（config.delete）必须填写 reason（≥4 字符）")
	}
	current, err := s.findByID(ctx, id)
	if err != nil {
		return err
	}
	before := configToState(current)
	if err := s.deps.TenantConfigs.SoftDelete(ctx, id); err != nil {
		s.writeAudit(ctx, principal, "config.delete", "provider_config", fmt.Sprintf("%d", id),
			reason, before, nil, "error", err)
		return err
	}
	after := before
	after["status"] = 0
	s.writeAudit(ctx, principal, "config.delete", "provider_config", fmt.Sprintf("%d", id),
		reason, before, after, "success", nil)
	return nil
}

// ListConfigs 列出某应用的全部渠道配置（凭据只返回掩码）。
func (s *Service) ListConfigs(ctx context.Context, appID int64) ([]tenant.ProviderConfig, error) {
	return s.deps.TenantConfigs.ListByApp(ctx, appID)
}

// GetConfig 详情（凭据返回掩码）。
func (s *Service) GetConfig(ctx context.Context, id int64) (*tenant.ProviderConfig, error) {
	return s.findByID(ctx, id)
}

func (s *Service) findByID(ctx context.Context, id int64) (*tenant.ProviderConfig, error) {
	// 业务端的 Find 只支持 (app_id, platform, scene, config_key, env)，
	// admin 端需要按主键查，所以这里走仓储的 FindByID（admin_repo 里实现）。
	// 为保持端口稳定：用一个轻量适配。
	type byIDFinder interface {
		FindByID(ctx context.Context, id int64) (*tenant.ProviderConfig, error)
	}
	if f, ok := s.deps.TenantConfigs.(byIDFinder); ok {
		return f.FindByID(ctx, id)
	}
	// 兜底：返回 not found
	return nil, tenant.ErrNotFound
}

// configToState 把渠道配置投影成审计快照（屏蔽敏感字段）。
func configToState(c *tenant.ProviderConfig) map[string]any {
	if c == nil {
		return nil
	}
	return map[string]any{
		"id":                       c.ID,
		"app_id":                   c.AppID,
		"platform":                 c.Platform,
		"scene":                    c.Scene,
		"config_key":               c.ConfigKey,
		"provider_app_id":          c.ProviderAppID,
		"env":                      c.Env,
		"status":                   c.Status,
		"version":                  c.Version,
		"secret_cipher_prev_set":   c.SecretCipherPrev != nil,
		"secret_dek_id":            c.SecretDEKID,
		"secret_rotated_at":        c.SecretRotatedAt,
		"extra":                    c.Extra,
	}
}

// reasonShort 仅用于审计日志的辅助（被 cite 改写时调）。
func reasonShort(s string) string { return s }

// writeAudit 写审计。
func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action, targetType, targetID, reason string,
	before, after map[string]any, result string, auditErr error,
) {
	if s.deps.AdminAudit == nil {
		return
	}
	ev := &admin.AuditEvent{
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Reason:      reason,
		BeforeState: before,
		AfterState:  after,
		Result:      result,
	}
	if p != nil && p.User != nil {
		ev.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	} else {
		ev.SubjectID = "admin:anonymous"
	}
	if auditErr != nil {
		if e, ok := errs.As(auditErr); ok {
			ev.ErrorCode = string(e.Code)
		} else {
			ev.ErrorCode = string(errs.CodeInternal)
		}
	}
	if err := s.deps.AdminAudit.Write(ctx, ev); err != nil {
		if s.deps.Logger != nil {
			s.deps.Logger.Error("写入管理审计失败", zap.Error(err), zap.String("action", action))
		}
	}
}

// VerifyHTTPDefault 是默认的 token_url 健康探测实现。
//
// 用 httpx.PostFormJSON 调一次 client_credentials，5s 超时；
// 401/invalid_client 时返回带 details 的 errs.Error。
//
// 之所以单独成函数而不是放在 New 里默认注入，是为了
// adminapp.New 不依赖 httpx（防止包循环引用），同时让测试可以替换。
func VerifyHTTPDefault() func(ctx context.Context, tokenURL, clientID, clientSecret string) (time.Duration, error) {
	c := httpx.New(httpx.Config{
		Name:         "admin-verify",
		TotalTimeout: 5 * time.Second,
	})
	return func(ctx context.Context, tokenURL, clientID, clientSecret string) (time.Duration, error) {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
		form.Set("scope", "")

		start := time.Now()
		var resp struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
			ErrDesc     string `json:"error_description"`
		}
		httpResp, err := c.PostFormJSON(ctx, tokenURL, form, &resp)
		latency := time.Since(start)
		if err != nil {
			return latency, err
		}
		if httpResp.StatusCode >= 500 {
			return latency, errs.New(errs.CodeAdminVerifyFailed, "平台返回 5xx").
				WithDetail("http_status", httpResp.StatusCode)
		}
		if httpResp.StatusCode == 401 || resp.Error == "invalid_client" {
			return latency, errs.New(errs.CodeAdminVerifyFailed, "client 凭据被平台拒绝").
				WithDetail("http_status", httpResp.StatusCode).
				WithDetail("provider_error", firstNonEmpty(resp.Error, resp.ErrDesc))
		}
		if httpResp.StatusCode >= 400 {
			return latency, errs.New(errs.CodeAdminVerifyFailed, "平台返回 4xx").
				WithDetail("http_status", httpResp.StatusCode).
				WithDetail("provider_error", firstNonEmpty(resp.Error, resp.ErrDesc))
		}
		if resp.AccessToken == "" {
			return latency, errs.New(errs.CodeAdminVerifyFailed, "平台未返回 access_token")
		}
		return latency, nil
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// 抑制 unused
var _ = json.Marshal
