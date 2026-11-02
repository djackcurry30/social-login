package middleware

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/ratelimit"
)

// LimitConfig 是入站限流参数（架构 §6.3 / 修正 P1-8）。
//
// 两档维度对应两种不同的保护目标，阈值必须分开配：
//
//	Notify   平台服务端通知入口。它没有鉴权（调用方是平台服务器），
//	         完全暴露在公网，是最容易被刷的端点，阈值要单独收紧。
//	AppIP    业务端应用 + 客户端 IP。防止单个调用方打爆服务，
//	         同时不误伤其它应用。
//
// 第三档 rl:identity（身份维度）不在本层：身份 ID 只有在平台返回 open_id
// 之后才知道，属于授权流程内部，由 infrastructure/ratelimit 提供、
// authflow 在拿到 identity 后调用。分层的理由是"接入层拿不到这个主语"，
// 不是遗漏。
//
// rl:global（端点级兜底）仍不挂载：它按路由 + IP 计数，而 /admin/assets
// 这类静态资源一次页面加载就是几十个请求，3000/min 的口径很容易误伤正常用户。
type LimitConfig struct {
	Enabled bool
	// NotifyPerMinute 是 notify 端点每分钟上限（按 平台+IP）。
	NotifyPerMinute int
	// AppIPPerMinute 是业务端每分钟上限（按 app + IP）。
	AppIPPerMinute int
}

// DefaultLimitConfig 返回保守默认值。
//
// 默认【关闭】：限流阈值与业务量强相关，猜一个值上线比不限制更危险——
// 一旦偏低，正常用户会成片收到 429，而运维第一反应往往是"服务坏了"。
// 打开之前必须按实际 QPS 校准。
func DefaultLimitConfig() LimitConfig {
	return LimitConfig{
		Enabled:         false,
		NotifyPerMinute: 120,
		AppIPPerMinute:  600,
	}
}

// Counter 是限流需要的原子操作接口（实现见 pkg/ratelimit）。
//
// 保留这个别名是为了让既有测试与装配代码不必改动：限流的测试要覆盖
// "超限"与"Redis 故障时不拦请求"两条分支，这两条都靠注入假实现来构造。
type Counter = ratelimit.Counter

// Limiter 是基于 Redis 固定窗口的入站限流器。
type Limiter struct {
	window *ratelimit.Window
	cfg    LimitConfig
	// now 供测试覆盖时钟（窗口号由它决定）。保持字段而不是只留构造函数，
	// 是因为既有测试在构造之后才注入时间，改成构造函数参数会破坏那批用例。
	now func() time.Time
}

// NewLimiter 构造限流器。rdb 为 nil 时所有判定放行。
func NewLimiter(rdb *redis.Client, cfg LimitConfig) *Limiter {
	var c ratelimit.Counter
	if rdb != nil {
		c = ratelimit.RedisCounter{RDB: rdb}
	}
	return newLimiter(c, cfg)
}

// NewLimiterWithCounter 供测试注入计数实现。
func NewLimiterWithCounter(c Counter, cfg LimitConfig) *Limiter {
	return newLimiter(c, cfg)
}

func newLimiter(c ratelimit.Counter, cfg LimitConfig) *Limiter {
	l := &Limiter{cfg: cfg, now: time.Now}
	// 时钟用闭包转发，而不是在构造时取一份：测试会在构造之后改 l.now。
	l.window = ratelimit.NewWindowWithClock(c, func() time.Time { return l.now() })
	return l
}

// Enabled 报告限流是否开启（供装配时决定要不要挂中间件）。
func (l *Limiter) Enabled() bool { return l != nil && l.cfg.Enabled }

// Notify 是平台通知入口的限流（平台 + IP 维度）。
//
// 这个端点没有应用凭据可依赖，只能按来源 IP 限——伪造 IP 需要控制网络路径，
// 成本高于直接刷业务端点，因此这一层足够挡住脚本级滥用。
func (l *Limiter) Notify() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.Enabled() {
			c.Next()
			return
		}
		platform := c.Param("platform")
		key := fmt.Sprintf("rl:notify:%s:ip:%s", platform, c.ClientIP())
		l.enforce(c, key, l.cfg.NotifyPerMinute)
	}
}

// AppIP 是业务端的限流（应用 + IP 维度）。
//
// 必须挂在 AppAuth 之后：只有那时才知道 app_id。挂在前面只能按 IP 限，
// 会把"NAT 后面的整个办公室"当成一个滥用者。
func (l *Limiter) AppIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.Enabled() {
			c.Next()
			return
		}
		app := App(c)
		if app == nil {
			// 未认证到应用就放行，交给后续中间件返回 401——
			// 限流不该成为鉴权错误的替身，那会误导调用方。
			c.Next()
			return
		}
		key := fmt.Sprintf("rl:app:%d:ip:%s", app.ID, c.ClientIP())
		l.enforce(c, key, l.cfg.AppIPPerMinute)
	}
}

// enforce 执行计数与拦截。
func (l *Limiter) enforce(c *gin.Context, key string, limit int) {
	if limit <= 0 {
		c.Next()
		return
	}
	res := l.window.Allow(c.Request.Context(), key, limit)
	if res.Allowed {
		c.Next()
		return
	}
	// Retry-After 用"距窗口结束的秒数"，比固定的 60 更准确。
	c.Header("Retry-After", strconv.Itoa(res.RetryAfter))
	httputil.Fail(c, nil,
		errs.New(errs.CodeRateLimited, "请求过于频繁，请稍后重试").
			WithDetail("limit", limit).
			WithDetail("window", "60s").
			WithRetryAfter(res.RetryAfter*1000))
	c.Abort()
}
