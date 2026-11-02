// Package ratelimit 提供基于 Redis 的固定窗口计数。
//
// 为什么单独成包：本服务有两个地方需要"每分钟最多 N 次"——接入层的入站限流
// （middleware.Limiter）与授权流程内的身份维度限流（防撞库与暴力绑定）。
// 两者的判定语义完全相同（窗口号进 key + 首次计数设 TTL + 超限给出
// Retry-After），但分属不同层：接入层不能引用应用层，应用层也不该依赖
// 具体的 HTTP 中间件。把"计数"这一件事下沉到 pkg，两边各自组装即可。
//
// 用固定窗口而不是令牌桶：限流目标是"挡住滥用的量级"，不是精确整形。
// 一次 INCR 就能判定，成本最低；代价是窗口边界的瞬时双倍突刺，
// 对"防刷"这个目标完全够用。
package ratelimit

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Counter 是限流需要的两个原子操作。
//
// 抽成接口而不是直接用 *redis.Client：测试要覆盖"超限"与"Redis 故障时
// 不拦请求"两条分支，拿着真 Redis 很难把后者造出来。
type Counter interface {
	// Incr 把 key 计数 +1 并返回新值。
	Incr(ctx context.Context, key string) (int64, error)
	// Expire 设置 TTL。
	Expire(ctx context.Context, key string, ttl time.Duration) error
}

// RedisCounter 是 Counter 的 Redis 实现。
type RedisCounter struct{ RDB *redis.Client }

// Incr 实现 Counter。
func (c RedisCounter) Incr(ctx context.Context, key string) (int64, error) {
	return c.RDB.Incr(ctx, key).Result()
}

// Expire 实现 Counter。
func (c RedisCounter) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.RDB.Expire(ctx, key, ttl).Err()
}

// Window 是固定窗口计数器。
type Window struct {
	counter Counter
	// now 供测试注入时间。
	now func() time.Time
	// timeout 是单次计数的超时。Redis 抖动时宁可放行也不要卡住请求。
	timeout time.Duration
}

// NewWindow 构造计数器。counter 为 nil 时判定一律放行（等同未启用）。
func NewWindow(counter Counter) *Window {
	return &Window{counter: counter, now: time.Now, timeout: 200 * time.Millisecond}
}

// NewWindowWithClock 供测试注入时钟。
func NewWindowWithClock(counter Counter, now func() time.Time) *Window {
	w := NewWindow(counter)
	if now != nil {
		w.now = now
	}
	return w
}

// Result 是一次判定的结果。
type Result struct {
	// Allowed 表示是否放行。
	//
	// Redis 故障时恒为 true（fail-open）：限流是保护措施，不是正确性前提，
	// 一次 Redis 抖动不该让全站 429。
	Allowed bool
	// RetryAfter 是建议的重试等待秒数（距窗口结束），仅 Allowed=false 时有效。
	RetryAfter int
	// Count 是当前窗口的计数（故障时为 0）。
	Count int64
}

// Allow 在 key 上计数并按 limit 判定。
//
// key 里不要自己拼窗口号，本方法会拼——调用方只表达"按什么维度限"。
// limit <= 0 表示不限（直接放行），便于用配置关掉某一档而不改装配。
func (w *Window) Allow(ctx context.Context, key string, limit int) Result {
	return w.allow(ctx, key, limit, "m", func(now time.Time) (string, time.Duration, int) {
		// 窗口号参与 key：把窗口号写进 key 而不是只靠 TTL，是为了避免
		// "第一个请求决定窗口对齐"——那样两个请求会落在同一 key 却属于
		// 不同实际窗口，计数被摊薄。
		window := now.UTC().Unix() / 60
		retry := 60 - int(now.UTC().Unix()%60)
		if retry <= 0 {
			retry = 1
		}
		return strconv.FormatInt(window, 10), 2 * time.Minute, retry
	})
}

// AllowDaily 按【自然日】计数，用于渠道日配额（rl:platform:{platform}:day）。
//
// 与 Allow 的区别只有窗口粒度和过期时刻，判定语义完全一致——共用同一份
// 实现是刻意的：日配额如果自己写一套 TTL 计算，很容易在"跨零点"这件事上
// 与分钟窗口出现两种行为，而那种 bug 一年只会暴露两次（零点）。
//
// 日期取服务器本地时区：渠道的配额重置点由运维按业务时区理解，
// 统一用本地时区比用 UTC 更符合"今天还剩多少额度"的直觉。多实例部署
// 必须保证时区一致，否则同一平台的配额会被拆成两段各自计数。
func (w *Window) AllowDaily(ctx context.Context, key string, limit int) Result {
	return w.allow(ctx, key, limit, "day", func(now time.Time) (string, time.Duration, int) {
		day := now.Format("20060102")
		// 当天 24:00（本地）。加一分钟缓冲：零点前后各实例的时钟有毫秒级
		// 偏差时，旧 key 不会在零点瞬间消失，避免"新的一天从 0 开始"被
		// 误判成"旧窗口还剩 1 次"。
		endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).
			Add(24 * time.Hour)
		ttl := endOfDay.Sub(now) + time.Minute
		retry := int(endOfDay.Sub(now).Seconds())
		if retry <= 0 {
			retry = 1
		}
		return day, ttl, retry
	})
}

// allow 是分钟窗口与日窗口的共同实现。
//
// windowOf 返回 (窗口标识, key 的 TTL, 超限时的建议等待秒数)。
func (w *Window) allow(
	ctx context.Context,
	key string,
	limit int,
	kind string,
	windowOf func(now time.Time) (tag string, ttl time.Duration, retry int),
) Result {
	if limit <= 0 || w == nil || w.counter == nil {
		return Result{Allowed: true}
	}

	now := w.now()
	tag, ttl, retry := windowOf(now)
	fullKey := key + ":" + kind + ":" + tag

	callCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	n, err := w.counter.Incr(callCtx, fullKey)
	if err != nil {
		return Result{Allowed: true}
	}
	if n == 1 {
		// 只给首次计数设过期，避免每次请求都把 TTL 续上（那等于永不过期）。
		_ = w.counter.Expire(callCtx, fullKey, ttl)
	}
	if n > int64(limit) {
		return Result{Allowed: false, RetryAfter: retry, Count: n}
	}
	return Result{Allowed: true, Count: n}
}
