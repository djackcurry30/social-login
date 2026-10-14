package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/alex/social-login/internal/application/binding"
	"github.com/alex/social-login/internal/interfaces/http/httputil"
	"github.com/alex/social-login/internal/interfaces/http/middleware"
	"github.com/alex/social-login/internal/pkg/errs"
)

// bindRequest 是 POST /v1/bind 的请求体。
type bindRequest struct {
	BindTicket string `json:"bind_ticket" binding:"required"`
	DeviceID   string `json:"device_id"`
	// ExternalUserID 仅在【服务端到服务端】调用时提供，且必须同时持有应用凭据。
	//
	// 若请求头带 Authorization: Bearer，则以令牌中的 sub 为准，忽略本字段——
	// 令牌是更强的凭据（它证明的是"该用户本人"，而不只是"某个可信服务端说他是"）。
	ExternalUserID string `json:"external_user_id"`
}

// Bind 处理 POST /v1/bind：用 bind_ticket 完成引导绑定。
//
// 这是 C4 + C5 组合下唯一能把"三方授权成功"接上"业务账号令牌"的通道：
//
//	授权成功但无绑定 → AUTH.NEED_REGISTER + bind_ticket
//	业务方引导用户注册/登录 → 拿到自己的 external_user_id
//	带 bind_ticket 调本接口 → 建立绑定并直接签发令牌
func (h *Handler) Bind(c *gin.Context) {
	var req bindRequest
	if !httputil.BindJSON(c, &req, h.logger()) {
		return
	}
	app := middleware.App(c)
	if app == nil {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "缺少已认证的应用上下文"))
		return
	}

	userID, err := h.resolveBindTarget(c, app.AppCode, req.ExternalUserID)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}

	res, err := h.deps.Bindings.Bind(c.Request.Context(), binding.BindInput{
		AppCode:        app.AppCode,
		BindTicket:     req.BindTicket,
		ExternalUserID: userID,
		DeviceID:       req.DeviceID,
	})
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{
		"identity_id": res.IdentityID,
		"platform":    res.Platform,
		"scene":       res.Scene,
		"profile":     res.Profile,
		"token":       res.Tokens,
	})
}

// resolveBindTarget 决定"把身份绑到哪个账号"。
//
// 顺序不能颠倒：先令牌、后请求体。令牌证明的是用户本人，请求体只能证明
// "调用方持有 app_secret"。在两者都存在时采用更强的那个，可以避免
// "持有令牌的用户被自己所属服务端绕开"这种越权。
func (h *Handler) resolveBindTarget(c *gin.Context, appCode, bodyUserID string) (string, error) {
	if raw := bearerToken(c); raw != "" {
		res, err := h.deps.Tokens.Introspect(c.Request.Context(), appCode, raw, false)
		if err != nil {
			return "", err
		}
		if !res.Active || res.Subject == "" {
			return "", errs.New(errs.CodeTokenInvalid, "访问令牌无效或已过期")
		}
		if res.Scope == "identity_only" {
			// identity_only 说明这个令牌本身就来自"未注册"状态，
			// 用它来断言账号归属会形成循环依赖。
			return "", errs.New(errs.CodeForbidden,
				"受限令牌（identity_only）不能用于绑定操作")
		}
		return res.Subject, nil
	}
	if bodyUserID == "" {
		return "", errs.New(errs.CodeUnauthorized,
			"缺少账号归属：请携带 Authorization: Bearer 令牌，或在请求体中提供 external_user_id")
	}
	return bodyUserID, nil
}

// ListBindings 处理 GET /v1/bindings：列出当前账号已绑渠道。
//
// 这是"引导绑定"页面的数据源（需求 R1 的落地前提之一）。
func (h *Handler) ListBindings(c *gin.Context) {
	app := middleware.App(c)
	userID := middleware.ExternalUserID(c)
	if app == nil || userID == "" {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeUnauthorized, "需要已登录的账号"))
		return
	}
	rows, err := h.deps.Bindings.ListBindings(c.Request.Context(), app.AppCode, userID)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{
		"bindings": rows,
		// 一并列出该应用已启用的渠道，便于前端渲染"可绑定渠道"列表
		// （已绑的置灰、未绑的可点）。少了它前端还得自己算差集。
		"available_channels": h.availableChannels(c),
	})
}

// Unbind 处理 DELETE /v1/bind/{identity_id}。
func (h *Handler) Unbind(c *gin.Context) {
	app := middleware.App(c)
	userID := middleware.ExternalUserID(c)
	if app == nil || userID == "" {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeUnauthorized, "需要已登录的账号"))
		return
	}
	identityID, err := strconv.ParseInt(c.Param("identity_id"), 10, 64)
	if err != nil || identityID <= 0 {
		httputil.FailBadRequest(c, h.logger(), "identity_id 非法", "identity_id")
		return
	}
	if err := h.deps.Bindings.Unbind(c.Request.Context(), app.AppCode, userID, identityID); err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"unbound": true})
}

// availableChannels 列出应用已启用的渠道（不含凭据）。
func (h *Handler) availableChannels(c *gin.Context) []gin.H {
	app := middleware.App(c)
	if app == nil {
		return nil
	}
	cfgs, err := h.deps.Tenant.ListChannels(c.Request.Context(), app.ID)
	if err != nil {
		// 渠道列表是辅助信息，取不到不影响主流程，返回空数组即可。
		h.logger().Warn("获取渠道列表失败（不影响绑定列表）")
		return nil
	}
	out := make([]gin.H, 0, len(cfgs))
	for _, cfg := range cfgs {
		out = append(out, gin.H{
			"platform":   cfg.Platform,
			"scene":      cfg.Scene,
			"config_key": cfg.ConfigKey,
			"status":     cfg.Status,
		})
	}
	return out
}
