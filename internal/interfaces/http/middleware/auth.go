package middleware

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/application/token"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// 请求头名。
const (
	HeaderAppID     = "X-App-Id"
	HeaderAppSecret = "X-App-Secret"
)

const (
	ctxKeyApp    = "social_login.app"
	ctxKeyUserID = "social_login.external_user_id"
)

// App 读取当前请求已认证的应用。
func App(c *gin.Context) *tenant.Application {
	if v, ok := c.Get(ctxKeyApp); ok {
		if app, ok := v.(*tenant.Application); ok {
			return app
		}
	}
	return nil
}

// ExternalUserID 读取当前请求已认证的业务账号标识。
func ExternalUserID(c *gin.Context) string {
	if v, ok := c.Get(ctxKeyUserID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// AuthenticateApp 校验应用凭据。
//
// 单独导出（而不是只藏在中间件里）的原因：/v1/token 按 OAuth2 习惯允许把
// client_id / client_secret 放在请求体里，而中间件无法读取尚未绑定的请求体。
// 与其在中间件里抢先消费 body（会破坏后续 JSON 绑定），不如让该处理器显式调用本函数。
func AuthenticateApp(ctx context.Context, svc *tenantconfig.Service, hasher *crypto.AppSecretHasher, appCode, secret string) (*tenant.Application, error) {
	if appCode == "" {
		return nil, errs.New(errs.CodeUnauthorized, "缺少应用标识（X-App-Id 或 client_id）")
	}
	if secret == "" {
		return nil, errs.New(errs.CodeUnauthorized, "缺少应用密钥（X-App-Secret 或 client_secret）")
	}
	app, err := svc.Application(ctx, appCode)
	if err != nil {
		return nil, err
	}
	if !hasher.Verify(secret, app.AppSecretHash) {
		// 不区分"应用不存在"与"密钥错误"：区分会给出一个枚举 app_id 的通道。
		return nil, errs.New(errs.CodeUnauthorized, "应用凭据无效")
	}
	return app, nil
}

// AppAuth 是要求应用凭据的中间件（凭据取自请求头）。
func AppAuth(logger *zap.Logger, svc *tenantconfig.Service, hasher *crypto.AppSecretHasher) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, err := AuthenticateApp(c.Request.Context(), svc, hasher,
			c.GetHeader(HeaderAppID), c.GetHeader(HeaderAppSecret))
		if err != nil {
			httputil.Fail(c, logger, err)
			return
		}
		c.Set(ctxKeyApp, app)
		c.Next()
	}
}

// UserAuth 是要求已登录用户的中间件（Authorization: Bearer <access_token>）。
//
// 它同时校验令牌的 aud 必须是当前请求的应用：没有这一步，A 应用签发的令牌
// 就能直接调 B 应用的接口，约束 C1（账号按业务应用隔离）会被绕过。
func UserAuth(logger *zap.Logger, tokens *token.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app := App(c)
		if app == nil {
			httputil.Fail(c, logger, errs.New(errs.CodeInternal,
				"UserAuth 必须挂在 AppAuth 之后（需要已认证的应用上下文）"))
			return
		}
		raw := bearerToken(c)
		if raw == "" {
			httputil.Fail(c, logger, errs.New(errs.CodeUnauthorized, "缺少访问令牌"))
			return
		}
		res, err := tokens.Introspect(c.Request.Context(), app.AppCode, raw, false)
		if err != nil {
			httputil.Fail(c, logger, err)
			return
		}
		if !res.Active || res.Subject == "" {
			httputil.Fail(c, logger, errs.New(errs.CodeTokenInvalid, "访问令牌无效或已过期"))
			return
		}
		if res.Scope == "identity_only" {
			// identity_only 意味着"身份可信但尚未注册"，只允许走注册引导，
			// 不允许访问需要业务账号的接口。
			httputil.Fail(c, logger, errs.New(errs.CodeForbidden,
				"当前令牌为受限范围（identity_only），请先完成注册"))
			return
		}
		c.Set(ctxKeyUserID, res.Subject)
		c.Request = c.Request.WithContext(
			reqmeta.With(c.Request.Context(), reqmeta.From(c.Request.Context())))
		c.Next()
	}
}

// OptionalUserAuth 在存在令牌时解析用户，不存在时放行。
// 供 /v1/authorize 使用：bind 模式需要用户态，login 模式不需要。
func OptionalUserAuth(logger *zap.Logger, tokens *token.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app := App(c)
		raw := bearerToken(c)
		if app == nil || raw == "" {
			c.Next()
			return
		}
		res, err := tokens.Introspect(c.Request.Context(), app.AppCode, raw, false)
		if err == nil && res.Active && res.Scope != "identity_only" {
			c.Set(ctxKeyUserID, res.Subject)
		}
		c.Next()
	}
}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
