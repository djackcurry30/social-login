package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/alex/social-login/internal/interfaces/http/httputil"
	"github.com/alex/social-login/internal/interfaces/http/middleware"
	"github.com/alex/social-login/internal/pkg/errs"
)

// tokenRequest 是 POST /v1/token 的请求体。
//
// 按 OAuth2 习惯允许把客户端凭据放在请求体（client_id / client_secret），
// 这要求本接口【不能】挂 AppAuth 中间件——中间件无法读取尚未绑定的请求体。
// 因此凭据校验在本处理器内显式完成。
type tokenRequest struct {
	GrantType string `json:"grant_type" binding:"required"`
	Code      string `json:"code"`
	// RefreshToken 是 grant_type=refresh_token 时的入参。
	RefreshToken string `json:"refresh_token"`
	// ClientID / ClientSecret 可替代 X-App-Id / X-App-Secret 请求头。
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// DeviceID 仅用于多设备会话管理，不参与鉴权。
	DeviceID string `json:"device_id"`
}

// 支持的授权类型。
const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	grantSilent            = "silent"
)

// Token 处理 POST /v1/token。
func (h *Handler) Token(c *gin.Context) {
	var req tokenRequest
	if !httputil.BindJSON(c, &req, h.logger()) {
		return
	}

	appCode, secret := h.clientCredentials(c, req.ClientID, req.ClientSecret)
	app, err := middleware.AuthenticateApp(c.Request.Context(), h.deps.Tenant, h.deps.SecretHasher, appCode, secret)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}

	ctx := c.Request.Context()
	switch req.GrantType {
	case grantAuthorizationCode:
		res, err := h.deps.Tokens.ExchangeAuthCode(ctx, app.AppCode, req.Code, req.DeviceID)
		if err != nil {
			httputil.Fail(c, h.logger(), err)
			return
		}
		httputil.OK(c, http.StatusOK, res)

	case grantRefreshToken:
		res, err := h.deps.Tokens.Refresh(ctx, app.AppCode, req.RefreshToken, req.DeviceID)
		if err != nil {
			httputil.Fail(c, h.logger(), err)
			return
		}
		httputil.OK(c, http.StatusOK, res)

	case grantSilent:
		// silent 是"用已有会话静默换新令牌"的授权类型，需要业务方传入
		// 自己的会话凭据。它依赖的是一次性 auth_code 之外的第二条信任链，
		// 属于第三期随会话管理一起设计，这里显式声明未实现——
		// 静默失败比返回一个假的令牌更危险。
		httputil.Fail(c, h.logger(), errs.New(errs.CodeProviderNotSupported,
			"grant_type=silent 尚未实现（第三期随会话管理交付）"))

	default:
		httputil.FailBadRequest(c, h.logger(),
			"不支持的 grant_type: "+req.GrantType, "grant_type")
	}
}

// clientCredentials 解析客户端凭据：请求头优先，请求体次之。
func (h *Handler) clientCredentials(c *gin.Context, bodyID, bodySecret string) (string, string) {
	id := c.GetHeader(middleware.HeaderAppID)
	secret := c.GetHeader(middleware.HeaderAppSecret)
	if id == "" {
		id = bodyID
	}
	if secret == "" {
		secret = bodySecret
	}
	return id, secret
}

// introspectRequest 是 POST /v1/introspect 的请求体。
type introspectRequest struct {
	Token string `json:"token" binding:"required"`
	// CheckRevocation 为 true 时额外校验 jti 黑名单。
	//
	// 默认 false 是为了保住"业务方本地验签、零网络开销"这一核心收益；
	// 安全敏感操作（改密、提现、绑定新渠道）应显式开启。
	CheckRevocation bool `json:"check_revocation"`
}

// Introspect 处理 POST /v1/introspect。
func (h *Handler) Introspect(c *gin.Context) {
	var req introspectRequest
	if !httputil.BindJSON(c, &req, h.logger()) {
		return
	}
	app := middleware.App(c)
	if app == nil {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "缺少已认证的应用上下文"))
		return
	}
	res, err := h.deps.Tokens.Introspect(c.Request.Context(), app.AppCode, req.Token, req.CheckRevocation)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	if !res.Active {
		// 按 RFC 7662，无效令牌返回 {"active": false} 而不是错误。
		httputil.OK(c, http.StatusOK, gin.H{"active": false})
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{
		"active": true,
		"sub":    res.Subject,
		"app_id": res.AppCode,
		"scope":  res.Scope,
		"amr":    res.AMR,
		"exp":    res.ExpiresAt.Unix(),
		"iat":    res.IssuedAt.Unix(),
		"jti":    res.JWTID,
		// 明确告知接入方撤销的生效延迟，避免它以为撤销是即时的（架构 §8.4）。
		"revocation_note": "access_token 采用本地验签，普通登出后最长 15 分钟内仍然有效",
	})
}

// revokeRequest 是 POST /v1/revoke 的请求体。
type revokeRequest struct {
	Token string `json:"token" binding:"required"`
	// Reason 用于审计。高危撤销应传明确原因，便于事后追溯。
	Reason string `json:"reason"`
}

// Revoke 处理 POST /v1/revoke。
func (h *Handler) Revoke(c *gin.Context) {
	var req revokeRequest
	if !httputil.BindJSON(c, &req, h.logger()) {
		return
	}
	app := middleware.App(c)
	if app == nil {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "缺少已认证的应用上下文"))
		return
	}
	kind, err := h.deps.Tokens.Revoke(c.Request.Context(), app.AppCode, req.Token, req.Reason)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	// 如实返回被撤销的令牌形态，让接入方知道生效延迟：
	// access_token 不会被立即作废（需要 jti 黑名单，第四期）。
	httputil.OK(c, http.StatusOK, gin.H{
		"revoked": true,
		"type":    kind,
	})
}
