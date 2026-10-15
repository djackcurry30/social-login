// Package handler 中的 provider_configs.go：B 组（渠道配置 + secret verify）路由薄壳。
//
// 端点清单（架构 §15.4 B 组第一期 10 个）：
//
//	GET    /admin/v1/apps/:appId/provider-configs                    List
//	POST   /admin/v1/apps/:appId/provider-configs                    Create
//	GET    /admin/v1/apps/:appId/provider-configs/:id                Get
//	PATCH  /admin/v1/apps/:appId/provider-configs/:id                Update
//	POST   /admin/v1/apps/:appId/provider-configs/:id/secret:rotate  RotateSecret
//	POST   /admin/v1/apps/:appId/provider-configs/:id/secret:finalize FinalizeSecret
//	POST   /admin/v1/apps/:appId/provider-configs/:id/secret:verify   VerifyConfig
//	POST   /admin/v1/apps/:appId/provider-configs/:id/enable          Enable
//	POST   /admin/v1/apps/:appId/provider-configs/:id/disable         Disable
//	DELETE /admin/v1/apps/:appId/provider-configs/:id                Delete
//
// 与 A 组一致：高危操作在 application 层校验 reason ≥4 字符。
// 注意：Path 参数有两段——:appId 与 :id（config 主键）。本文件把 :appId 透传给
// application 层（Create 时需要校验 app_id 与路由上的一致），:id 是查改用的主键。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminchan"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// ProviderConfigsHandler 是 B 组 handler。
type ProviderConfigsHandler struct {
	svc    *adminchan.Service
	logger *zap.Logger
}

// NewProviderConfigsHandler 构造 B 组 handler。
func NewProviderConfigsHandler(svc *adminchan.Service, logger *zap.Logger) *ProviderConfigsHandler {
	return &ProviderConfigsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/apps/:appId/provider-configs
func (h *ProviderConfigsHandler) List(c *gin.Context) {
	appID, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	items, err := h.svc.ListConfigs(c.Request.Context(), appID)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"items": items})
}

// Create POST /admin/v1/apps/:appId/provider-configs
//
// body 必须带 client_secret（明文），仅在创建/轮换时上传。
// server 端用 keyManager 加密后存库，明文不出调用方边界。
func (h *ProviderConfigsHandler) Create(c *gin.Context) {
	appID, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	var in adminchan.CreateConfigInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	// 以 URL 路径的 appId 为准，body 里的 app_id 必须匹配，否则 400。
	if in.AppID == 0 {
		in.AppID = appID
	}
	if in.AppID != appID {
		httputil.Fail(c, h.logger,
			errs.New(errs.CodeInvalidRequest, "app_id 与 URL 不一致").
				WithDetail("url_app_id", appID).
				WithDetail("body_app_id", in.AppID))
		return
	}
	in.Principal = adminmw.Principal(c)
	out, err := h.svc.CreateConfig(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusCreated, gin.H{"config": out})
}

// Get GET /admin/v1/apps/:appId/provider-configs/:id
//
// 返回的 config 中 secret_cipher 等敏感字段已经在仓储层做掩码。
func (h *ProviderConfigsHandler) Get(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	out, err := h.svc.GetConfig(c.Request.Context(), id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"config": out})
}

// Update PATCH /admin/v1/apps/:appId/provider-configs/:id
//
// 仅允许改 extra / env / config_key 等非凭据字段；client_secret 必须走 RotateSecret。
func (h *ProviderConfigsHandler) Update(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminchan.UpdateConfigInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	out, err := h.svc.UpdateConfig(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"config": out})
}

// reasonRequest 是只含 reason 的小型请求体，供 RotateSecret / FinalizeSecret /
// Enable / Disable / Delete / Verify 复用。
//
// 这些操作都要求 reason ≥4 字符——统一在本类型里做"非空检查"在 application，
// handler 只负责透传。
type reasonRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// RotateSecret POST /admin/v1/apps/:appId/provider-configs/:id/secret:rotate
//
// body 必须带 new_client_secret；旧 secret 会被移到 prev（仍在过渡期可用），
// 直到 finalize 被显式调用。
func (h *ProviderConfigsHandler) RotateSecret(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body struct {
		NewSecret string `json:"new_client_secret" binding:"required"`
		reasonRequest
	}
	if !httputil.BindJSON(c, &body, h.logger) {
		return
	}
	out, err := h.svc.RotateSecret(c.Request.Context(), id, adminchan.RotateSecretInput{
		NewSecret: body.NewSecret,
		Reason:    body.Reason,
		Principal: adminmw.Principal(c),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// FinalizeSecret POST /admin/v1/apps/:appId/provider-configs/:id/secret:finalize
//
// 清空 prev：旧 secret 立刻失效。运维确认"已经更新完成 push"后调用。
func (h *ProviderConfigsHandler) FinalizeSecret(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body reasonRequest
	if !httputil.BindJSON(c, &body, h.logger) {
		return
	}
	if err := h.svc.FinalizeSecret(c.Request.Context(), id, adminmw.Principal(c), body.Reason); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// Verify POST /admin/v1/apps/:appId/provider-configs/:id/secret:verify
//
// 真实调一次 token_url 的 client_credentials；返回 ok + 耗时。
// 成功/失败都不影响配置状态（不写 status），只把结果写到 audit。
func (h *ProviderConfigsHandler) Verify(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body reasonRequest
	if !httputil.BindJSON(c, &body, h.logger) {
		return
	}
	out, err := h.svc.VerifyConfig(c.Request.Context(), id, adminchan.VerifyConfigInput{
		Reason:    body.Reason,
		Principal: adminmw.Principal(c),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Enable POST /admin/v1/apps/:appId/provider-configs/:id/enable
func (h *ProviderConfigsHandler) Enable(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body reasonRequest
	if !httputil.BindJSON(c, &body, h.logger) {
		return
	}
	if err := h.svc.Enable(c.Request.Context(), id, adminmw.Principal(c), body.Reason); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// Disable POST /admin/v1/apps/:appId/provider-configs/:id/disable
func (h *ProviderConfigsHandler) Disable(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body reasonRequest
	if !httputil.BindJSON(c, &body, h.logger) {
		return
	}
	if err := h.svc.Disable(c.Request.Context(), id, adminmw.Principal(c), body.Reason); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// Delete DELETE /admin/v1/apps/:appId/provider-configs/:id
//
// 软删：把 status 置 0 + 写 deleted_at（不是真删）。这与 Delete 在 §15.4 的语义一致
// （渠道配置不可逆删除，运维回滚需要看到历史）。
func (h *ProviderConfigsHandler) Delete(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body reasonRequest
	if !httputil.BindJSON(c, &body, h.logger) {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), id, adminmw.Principal(c), body.Reason); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}