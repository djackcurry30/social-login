package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/metrics"
	"github.com/djackcurry30/social-login/internal/pkg/tracing"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/observe"
	"github.com/djackcurry30/social-login/internal/usercenter/service"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// IdempotencyHeader 是幂等键请求头，与消费方 account.IdempotencyHeader 一致。
const IdempotencyHeader = "Idempotency-Key"

// Deps 是路由的依赖。
type Deps struct {
	Service         *service.Service
	Store           *postgres.Store
	Metrics         *observe.Metrics
	MetricsRegistry *metrics.Registry
	Logger          *zap.Logger
	// Token 是服务间 Bearer token。为空表示不鉴权（仅限内网联调）。
	// 生产模式下配置校验会拒绝空值，所以这里为空只可能是开发环境。
	Token        string
	MaxBodyBytes int64
	Mode         string
	// ServiceName 是链路追踪里的服务名。为空取 "usercenter"。
	ServiceName string
}

// NewRouter 装配路由。
//
// 路径形状是契约的一部分（§2.2）：所有业务路径都在 /v1/apps/{app_key}/ 下。
// 应用进【路径】而不是请求头，理由是漏带时是 404 而不是"静默落到某个
// 默认租户"；日志与网关限流也能一眼看到是哪个应用。
func NewRouter(d Deps) *gin.Engine {
	if d.Mode == "" {
		d.Mode = gin.DebugMode
	}
	gin.SetMode(d.Mode)

	// gin.New 而不是 gin.Default：Default 带 Logger/Recovery，格式与本服务
	// 的日志、错误信封都不一致。
	r := gin.New()
	// 顺序：Tracing → requestID → recoverPanic → accessLog → measure → maxBody。
	//
	//   - Tracing 必须最外层：入站 span 要覆盖 panic 与访问日志，
	//     并且它先把上游的 traceparent 解出来，requestID 才能取到同一个 id。
	//   - recoverPanic 在 requestID 之后：panic 日志里要能带上 trace_id。
	serviceName := d.ServiceName
	if serviceName == "" {
		serviceName = "usercenter"
	}
	r.Use(
		tracing.GinMiddleware(serviceName),
		requestID(),
		recoverPanic(d.Logger),
		accessLog(d.Logger),
		measure(d.Metrics),
		maxBody(d.MaxBodyBytes),
	)

	h := &handler{svc: d.Service, log: d.Logger, store: d.Store, reg: d.MetricsRegistry}

	// 运维端点不鉴权：探针通常没有凭证，而它们只暴露"活着吗"与开箱指标，
	// 不含账号数据。真实部署里这几个路径应由网关限制在内网。
	r.GET("/healthz", h.healthz)
	r.GET("/readyz", h.readyz)
	r.GET("/metrics", h.metrics)

	api := r.Group("/v1", requireToken(d.Token))

	// 应用维度的账号接口。
	app := api.Group("/apps/:app_key", h.resolveApp)
	{
		// 静态路径必须能压过 :user_id，否则 by-claim 会被当成一个 user_id。
		app.GET("/accounts/by-claim", h.getByClaim)
		app.POST("/accounts", h.createAccount)
		app.POST("/accounts/merge", h.mergeAccounts)
		app.GET("/accounts/:user_id", h.getAccount)
		app.PUT("/accounts/:user_id/claims/:claim_type", h.replaceClaim)
	}

	// 内部接口：应用注册与注销。不对公网暴露，由网关隔离。
	internal := r.Group("/internal/v1", requireToken(d.Token))
	{
		// 注册不带 app_key 路径参数——它本身就是"声明一个应用存在"。
		internal.POST("/apps", h.registerApp)
		inner := internal.Group("/apps/:app_key", h.resolveApp)
		// 注销只做 UC 侧的原子动作（§11）：完整流程要联动 social-login。
		inner.POST("/accounts/:user_id/close", h.closeAccount)
		inner.GET("/accounts/count", h.countAccounts)
		// 审计只读查询：客服/合规用它回答"这个账号被谁动过"。
		inner.GET("/audit", h.listAudit)
	}

	return r
}

// resolveApp 解析路径里的 app_key 并把应用放入上下文。
func (h *handler) resolveApp(c *gin.Context) {
	appKey := trimParam(c.Param("app_key"))
	app, err := h.svc.ResolveApp(c.Request.Context(), appKey)
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.Set(ctxKeyApp, app)
	c.Next()
}

// healthz 只回答"进程还在跑"。
//
// 不查库：数据库挂掉时进程仍然健康，这个端点用于判断"要不要重启容器"，
// 查库会让它在故障时被反复重启，反而放大了问题。查库的是 readyz。
func (h *handler) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// readyz 回答"能不能接流量"（依赖可用性）。
func (h *handler) readyz(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if err := h.store.Ping(ctx); err != nil {
		h.log.Warn("就绪检查失败：数据库不可用", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unavailable",
			"reason": "database",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// metrics 输出 Prometheus 文本格式。
func (h *handler) metrics(c *gin.Context) {
	if h.reg == nil {
		c.String(http.StatusOK, "")
		return
	}
	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if _, err := h.reg.WriteTo(c.Writer); err != nil {
		// 已经写出去一部分了，改不了状态码；记日志即可。
		h.log.Warn("输出指标失败", zap.Error(err))
	}
}

// countAccounts 是运维用的计数端点。
//
// 只放在 /internal 下：它按应用暴露账号总量，属于容量信息，
// 不该出现在业务方可见的接口面里。
func (h *handler) countAccounts(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}
	n, err := h.store.CountAccounts(c.Request.Context(), app.ID)
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"app_key": app.Key, "accounts": n})
}
