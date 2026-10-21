package middleware

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// LimitConfig 是限流参数（架构 §6.3 / 修正 P1-8）。
//
// 三档维度对应三种不同的保护目标，阈值必须分开配：
//
//	Notify   平台服务端通知入口。它没有鉴权（调用方是平台服务器），
//	         完全暴露在公网，是最容易被刷的端点，阈值要单独收紧。
//	AppIP    业务端应用 + 客户端 IP。防止单个调用方打爆服务，
//	         同时不误伤其它应用。
//
// 文档还列了 rl:global（端点级兜底）与 rl:identity（身份维度）。
// 前者暂不挂载：它按路由 + IP 计数，而 /admin/assets 这类静态资源
// 一次页面加载就是几十个请求，3000/min 的口径很容易误伤正常用户；
// 后者需要 identity 上下文，属于授权流程内部，待后续接入。
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

// Counter 是限流需要的两个原子操作。
//
// 抽成接口而不是直接用 *redis.Client：限流的测试要覆盖"超限"与
// "Redis 故障时不拦请求"两条分支，拿着真 Redis 很难把后者造出来。
type Counter interface {
	// Incr 把 key 计数 +1 并返回新值。
	Incr(ctx context.Context, key string) (int64, error)
	// Expire 设置 TTL。
	Expire(ctx context.Context, key string, ttl time.Duration) error
}

// redisCounter 是 Counter 的 Redis 实现。
type redisCounter struct{ rdb *redis.Client }

func (c redisCounter) Incr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Incr(ctx, key).Result()
}

func (c redisCounter) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.rdb.Expire(ctx, key, ttl).Err()
}

// Limiter 是基于 Redis 固定窗口的入站限流器。
//
// 用固定窗口而不是令牌桶：本服务的限流目标是"挡住滥用的量级"，
// 不是精确整形。固定窗口一次 INCR 就能判定，成本最低；
// 代价是窗口边界的突刺（两个窗口交界处可能瞬时双倍），
// 对"防刷"这个目标完全够用。
type Limiter struct {
	counter Counter
	cfg     LimitConfig
	now     func() time.Time
}

// NewLimiter 构造限流器。
func NewLimiter(rdb *redis.Client, cfg LimitConfig) *Limiter {
	var c Counter
	if rdb != nil {
		c = redisCounter{rdb: rdb}
	}
	return &Limiter{counter: c, cfg: cfg, now: time.Now}
}

// NewLimiterWithCounter 供测试注入计数实现。
func NewLimiterWithCounter(c Counter, cfg LimitConfig) *Limiter {
	return &Limiter{counter: c, cfg: cfg, now: time.Now}
}

// Enabled 报告限流是否开启（供装配时决定要不要挂中间件）。
func (l *Limiter) Enabled() bool { return l != nil && l.cfg.Enabled && l.counter != nil }

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
	now := l.now().UTC()
	// 窗口号参与 key：每次计数落在固定窗口里，过期由 EXPIRE 兜底。
	// 把窗口号写进 key 而不是只靠 TTL，是为了避免"第一个请求决定窗口对齐"——
	// 那样两个请求可能落在同一 key 但属于不同实际窗口，计数被摊薄。
	window := now.Unix() / 60
	fullKey := fmt.Sprintf("%s:%d", key, window)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 200*time.Millisecond)
	defer cancel()

	n, err := l.counter.Incr(ctx, fullKey)
	if err != nil {
		// Redis 故障时不拦请求（fail-open）：
		// 限流是保护措施，不是正确性前提。一次 Redis 抖动不该让全站 429。
		c.Next()
		return
	}
	if n == 1 {
		// 只给首次计数设过期，避免每次请求都把 TTL 续上（那等于永不过期）。
		_ = l.counter.Expire(ctx, fullKey, 2*time.Minute)
	}
	if n > int64(limit) {
		// Retry-After 用"距窗口结束的秒数"，比固定的 60 更准确。
		retry := 60 - int(now.Unix()%60)
		if retry <= 0 {
			retry = 1
		}
		c.Header("Retry-After", strconv.Itoa(retry))
		httputil.Fail(c, nil,
			errs.New(errs.CodeRateLimited, "请求过于频繁，请稍后重试").
				WithDetail("limit", limit).
				WithDetail("window", "60s").
				WithRetryAfter(retry*1000))
		c.Abort()
		return
	}
	c.Next()
}
