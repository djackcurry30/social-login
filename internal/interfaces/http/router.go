// Package httpapi 装配业务端路由。
//
// 路由分三类的依据是【信任边界】，而不是 URL 前缀：
//
//	公开端点  浏览器可达，靠 redirect_uri 白名单与票据机制保护
//	应用端点  需要 app_id + app_secret（服务端到服务端调用）
//	用户端点  需要应用凭据 + 已登录用户（Authorization: Bearer）
//
// 管理端（/admin/v1/*）不在这里——它的鉴权模型、网络边界与审计体系完全不同，
// 见架构 §15.2 与管理端装配代码。
package httpapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/17track/social-login/internal/application/tenantconfig"
	"github.com/17track/social-login/internal/application/token"
	"github.com/17track/social-login/internal/infrastructure/crypto"
	"github.com/17track/social-login/internal/interfaces/http/handler"
	"github.com/17track/social-login/internal/interfaces/http/httputil"
	"github.com/17track/social-login/internal/interfaces/http/middleware"
	"github.com/17track/social-login/internal/pkg/errs"
)

// 各路由分组的超时预算（架构 §5.7 的第二段超时）。
//
// 授权链路取 8s：这是 §5.5 定下的"整条授权链路预算"，
// 它必须大于单渠道总超时（微信 3s / Apple 5s），否则换渠道时会出现
// "链路先超时、三方调用还在跑"的错配。
const (
	TimeoutAuth   = 8 * time.Second
	TimeoutNormal = 15 * time.Second
)

// RouterDeps 是装配路由所需的依赖。
type RouterDeps struct {
	Handler      *handler.Handler
	Tenant       *tenantconfig.Service
	Tokens       *token.Service
	SecretHasher *crypto.AppSecretHasher
	Logger       *zap.Logger
}

// NewRouter 构造 gin 引擎。
func NewRouter(deps RouterDeps) *gin.Engine {
	// 用 gin.New() 而不是 gin.Default()：默认实例自带 Logger 与 Recovery，
	// 前者会绕过我们统一的 zap 日志与 trace_id 注入，后者会把堆栈打到 stdout。
	r := gin.New()
	r.Use(
		middleware.RequestID(),
		middleware.Recovery(deps.Logger),
		middleware.AccessLog(deps.Logger),
	)
	// 限制请求体大小，避免超大 body 打爆内存（§5.7 的入站保护同族问题）。
	r.MaxMultipartMemory = 1 << 20

	h := deps.Handler

	// --- 运维端点 ---
	r.GET("/healthz", h.Live)
	r.GET("/readyz", h.Ready)

	// --- 公开端点 ---
	//
	// /v1/authorize 与 /v1/oauth/callback 必须对浏览器可达：前者是用户点"微信登录"
	// 后跳转的起点，后者是三方平台回调的落点。它们的安全依赖 redirect_uri 白名单
	// 与一次性 state 票据，而不是 API 密钥——要求浏览器携带 app_secret 是不现实的。
	r.GET("/v1/authorize", middleware.Timeout(TimeoutAuth), h.Authorize)
	r.GET("/v1/oauth/callback/:platform", middleware.Timeout(TimeoutAuth), h.Callback)

	// JWKS 与 discovery 是公开的：公钥本来就是要给业务方用的。
	r.GET("/v1/jwks", h.JWKS)
	r.GET("/.well-known/openid-configuration", h.Discovery)

	// --- 应用端点（app_id + app_secret） ---
	//
	// /v1/token 是特例：按 OAuth2 习惯它允许把 client_id / client_secret 放在
	// 请求体里，而中间件无法读取尚未绑定的请求体，因此它自行完成凭据校验。
	r.POST("/v1/token", middleware.Timeout(TimeoutNormal), h.Token)

	appGroup := r.Group("/v1", middleware.AppAuth(deps.Logger, deps.Tenant, deps.SecretHasher))
	appGroup.Use(middleware.Timeout(TimeoutNormal))
	{
		appGroup.POST("/introspect", h.Introspect)
		appGroup.POST("/revoke", h.Revoke)

		// /v1/bind 刻意【不挂 UserAuth】，因为它在 v0.5 之前的设计里有个死结：
		//
		//	NEED_REGISTER 分支下，业务方【还没有】我们签发的访问令牌
		//	（用户刚在三方授权成功，业务方才刚要引导他注册/登录），
		//	此时若强制要求 Bearer，引导绑定流程根本走不通。
		//
		// 因此本接口接受两种信任基础（由处理器内部选择，Bearer 优先）：
		//	① Bearer 令牌 —— 用户在已登录会话里主动绑定
		//	② 应用凭据 + 请求体中的 external_user_id —— 业务方服务端到服务端调用
		// ② 的安全性来自 app_secret：能持有它的是可信服务端，它断言"这是我自己的账号"
		// 与 OAuth2 中客户端断言用户身份是同一模式。
		appGroup.POST("/bind", h.Bind)
	}

	// --- 用户端点（应用凭据 + 已登录用户） ---
	//
	// 这几个接口操作的是"当前用户"自身的资源，只能由持该用户令牌的请求方调用，
	// 不接受由应用凭据代为断言用户身份——那会给"越权查看他人绑定"留口子。
	userGroup := r.Group("/v1",
		middleware.AppAuth(deps.Logger, deps.Tenant, deps.SecretHasher),
		middleware.UserAuth(deps.Logger, deps.Tokens),
		middleware.Timeout(TimeoutNormal),
	)
	{
		userGroup.GET("/userinfo", h.UserInfo)
		userGroup.GET("/bindings", h.ListBindings)
		userGroup.DELETE("/bind/:identity_id", h.Unbind)
	}

	// 统一 404 / 405 响应，避免 gin 默认的纯文本 "404 page not found"
	// 与业务方的 JSON 解析器不兼容。
	r.NoRoute(func(c *gin.Context) {
		httputil.Fail(c, deps.Logger,
			errs.New(errs.CodeNotFound, "接口不存在: "+c.Request.Method+" "+c.Request.URL.Path))
	})
	r.NoMethod(func(c *gin.Context) {
		httputil.Fail(c, deps.Logger,
			errs.Newf(errs.CodeNotFound, "不支持的方法: %s %s", c.Request.Method, c.Request.URL.Path))
	})

	return r
}

// HTTPServer 构造带三段超时的 http.Server（架构 §5.7 的第一段超时）。
//
// 与 gin 分组超时的分工：
//   - 本处是【连接级】保护，在业务逻辑之前生效，防止慢连接、慢请求头占住连接
//   - 分组超时是【业务级】保护，给不同链路不同的预算
//
// 两者必须都在：只有分组超时时，一个慢慢发请求头的客户端可以让连接挂很久；
// 只有连接级超时时，长链路（管理端导出）与短链路（授权）无法区分对待。
func HTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: h,
		// ReadHeaderTimeout 是最重要的一项：它专门防 Slowloris 类攻击
		// （攻击者逐个字节发请求头，占满连接数）。
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
