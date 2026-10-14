package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/authflow"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// authorizeQuery 是 /v1/authorize 的查询参数。
type authorizeQuery struct {
	AppID     string `form:"app_id" binding:"required"`
	Platform  string `form:"platform" binding:"required"`
	Scene     string `form:"scene" binding:"required"`
	ConfigKey string `form:"config_key"`
	// Client 是承载形态（ios / android / miniprogram / h5 / web），
	// 仅用于遥测与审计，【不参与路由】（规则 2）。
	Client string `form:"client"`
	// Mode 是 login | bind，默认 login。
	Mode string `form:"mode"`
	// RedirectURI 是回调后跳回业务方的地址，必须命中应用白名单。
	RedirectURI string `form:"redirect_uri" binding:"required"`
	// State 是业务侧透传的 state，本服务只原样回传。
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	// ResponseMode 是 redirect（默认，302）| json。
	ResponseMode string `form:"response_mode"`
}

// Authorize 处理 GET /v1/authorize。
//
// 关于鉴权：本接口是【浏览器可达的公开接口】，不要求应用凭据。
// 开放重定向风险由 redirect_uri 白名单兜住（见 tenant.Policy.IsRedirectURIAllowed），
// 这也是业界标准 OAuth2 授权端点的通行做法——授权端点一旦要求出参与客户端密钥，
// 就没法在浏览器里直接使用了。
//
// bind 模式是例外：它必须在请求头带 Authorization: Bearer <access_token>，
// 因为"要绑到哪个账号"这件事必须由服务端从签名令牌解出，不能由请求参数指定。
func (h *Handler) Authorize(c *gin.Context) {
	var q authorizeQuery
	if !httputil.BindQuery(c, &q, h.logger()) {
		return
	}

	mode := q.Mode
	if mode == "" {
		mode = provider.ModeLogin
	}

	in := authflow.AuthorizeInput{
		AppCode:             q.AppID,
		Platform:            q.Platform,
		Scene:               q.Scene,
		ConfigKey:           q.ConfigKey,
		Client:              q.Client,
		Mode:                mode,
		RedirectURI:         q.RedirectURI,
		BusinessState:       q.State,
		CodeChallenge:       q.CodeChallenge,
		CodeChallengeMethod: q.CodeChallengeMethod,
		ResponseMode:        q.ResponseMode,
	}

	if mode == provider.ModeBind {
		userID, err := h.resolveBindUser(c, q.AppID)
		if err != nil {
			httputil.Fail(c, h.logger(), err)
			return
		}
		in.AuthenticatedUserID = userID
	}

	out, err := h.deps.AuthFlow.Authorize(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}

	if q.ResponseMode == "json" || out.Immediate || mode == provider.ModeBind {
		httputil.OK(c, http.StatusOK, gin.H{
			"redirect_url": out.RedirectURL,
			"immediate":    out.Immediate,
			"params":       out.Params,
			"state":        out.State,
		})
		return
	}
	c.Redirect(http.StatusFound, out.RedirectURL)
}

// resolveBindUser 从 Authorization: Bearer 解出绑定目标账号。
func (h *Handler) resolveBindUser(c *gin.Context, appCode string) (string, error) {
	raw := bearerToken(c)
	if raw == "" {
		return "", errs.New(errs.CodeUnauthorized,
			"bind 模式必须在 Authorization 头携带访问令牌")
	}
	res, err := h.deps.Tokens.Introspect(c.Request.Context(), appCode, raw, false)
	if err != nil {
		return "", err
	}
	if !res.Active || res.Subject == "" {
		return "", errs.New(errs.CodeTokenInvalid, "访问令牌无效或已过期")
	}
	if res.Scope == "identity_only" {
		return "", errs.New(errs.CodeForbidden,
			"受限令牌（identity_only）不能用于绑定操作")
	}
	return res.Subject, nil
}

// Callback 处理 GET /v1/oauth/callback/{platform}。
//
// 只有这一个回调地址，全部上下文由 state 票据还原（架构 §5.2）——
// 平台侧的回调配置量因此不随渠道数量增长。
//
// 失败也回跳业务方（带 error 参数），而不是给用户一个 500 页面：
// 用户看到的是业务方统一的错误提示，而不是我们的服务内部信息。
func (h *Handler) Callback(c *gin.Context) {
	platform := c.Param("platform")

	out, err := h.deps.AuthFlow.Callback(c.Request.Context(), authflow.CallbackInput{
		Platform: platform,
		Query:    c.Request.URL.Query(),
		Header:   c.Request.Header,
	})
	if err != nil {
		// 票据无效/过期时我们不知道该回跳到哪，只能返回结构化错误。
		httputil.Fail(c, h.logger(), err)
		return
	}
	if out.Cause != nil {
		h.logger().Warn("授权回调失败（已带 error 回跳业务方）",
			zap.String("platform", platform),
			zap.String("error_code", out.ErrorCode),
			zap.Error(out.Cause))
	}

	if c.Query("response_mode") == "json" {
		httputil.OK(c, http.StatusOK, gin.H{
			"redirect_url":  out.RedirectURL,
			"error":         out.ErrorCode,
			"error_message": out.ErrorDescription,
			"retryable":     out.Retryable,
			"code":          out.AuthCode,
			"need_register": out.NeedRegister,
			"bind_ticket":   out.BindTicket,
			"state":         out.BusinessState,
		})
		return
	}
	c.Redirect(http.StatusFound, out.RedirectURL)
}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
