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
	if limit <= 0 || w == nil || w.counter == nil {
		return Result{Allowed: true}
	}

	now := w.now().UTC()
	// 窗口号参与 key：把窗口号写进 key 而不是只靠 TTL，是为了避免
	// "第一个请求决定窗口对齐"——那样两个请求会落在同一 key 却属于
	// 不同实际窗口，计数被摊薄。
	window := now.Unix() / 60
	fullKey := key + ":" + strconv.FormatInt(window, 10)

	callCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	n, err := w.counter.Incr(callCtx, fullKey)
	if err != nil {
		return Result{Allowed: true}
	}
	if n == 1 {
		// 只给首次计数设过期，避免每次请求都把 TTL 续上（那等于永不过期）。
		_ = w.counter.Expire(callCtx, fullKey, 2*time.Minute)
	}
	if n > int64(limit) {
		retry := 60 - int(now.Unix()%60)
		if retry <= 0 {
			retry = 1
		}
		return Result{Allowed: false, RetryAfter: retry, Count: n}
	}
	return Result{Allowed: true, Count: n}
}
