package ratelimit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// keyedCounter 按 key 独立计数，用来验证"窗口号进 key"这件事真的生效。
type keyedCounter struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
	ttl    map[string]time.Duration
}

func newKeyedCounter() *keyedCounter {
	return &keyedCounter{counts: map[string]int64{}, ttl: map[string]time.Duration{}}
}

func (c *keyedCounter) Incr(_ context.Context, key string) (int64, error) {
	if c.err != nil {
		return 0, c.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key]++
	return c.counts[key], nil
}

func (c *keyedCounter) Expire(_ context.Context, key string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl[key] = ttl
	return nil
}

func TestWindowAllowsUpToLimit(t *testing.T) {
	c := newKeyedCounter()
	w := NewWindow(c)

	for i := 1; i <= 3; i++ {
		if res := w.Allow(context.Background(), "rl:test", 3); !res.Allowed {
			t.Fatalf("第 %d 次不应被拦截", i)
		}
	}
	res := w.Allow(context.Background(), "rl:test", 3)
	if res.Allowed {
		t.Fatal("超过阈值后必须拦截")
	}
	if res.RetryAfter <= 0 || res.RetryAfter > 60 {
		t.Fatalf("Retry-After 应在 1..60 之间，实际 %d", res.RetryAfter)
	}
}

func TestWindowRotatesWithClock(t *testing.T) {
	c := newKeyedCounter()
	now := time.Unix(1700000000, 0)
	w := NewWindowWithClock(c, func() time.Time { return now })

	// 同一窗口内打满。
	for i := 0; i < 2; i++ {
		if res := w.Allow(context.Background(), "rl:rot", 2); !res.Allowed {
			t.Fatalf("窗口内第 %d 次不应被拦截", i+1)
		}
	}
	if res := w.Allow(context.Background(), "rl:rot", 2); res.Allowed {
		t.Fatal("同窗口内超限应被拦截")
	}

	// 跨到下一个窗口：计数必须从 0 重新开始，而不是被上一个窗口拖住。
	now = now.Add(61 * time.Second)
	if res := w.Allow(context.Background(), "rl:rot", 2); !res.Allowed {
		t.Fatal("新窗口应重新放行")
	}
	if len(c.counts) != 2 {
		t.Fatalf("窗口号应进 key，期望 2 个不同的 key，实际 %d: %v", len(c.counts), c.counts)
	}
}

func TestWindowFailsOpenOnCounterError(t *testing.T) {
	c := newKeyedCounter()
	c.err = errors.New("redis down")
	w := NewWindow(c)

	// Redis 故障时放行：限流是保护措施，不是正确性前提。
	for i := 0; i < 10; i++ {
		if res := w.Allow(context.Background(), "rl:down", 1); !res.Allowed {
			t.Fatal("计数组件故障时必须放行（fail-open）")
		}
	}
}

func TestWindowNonPositiveLimitAlwaysAllows(t *testing.T) {
	c := newKeyedCounter()
	w := NewWindow(c)

	if res := w.Allow(context.Background(), "rl:off", 0); !res.Allowed {
		t.Fatal("limit<=0 应表示不限")
	}
	if len(c.counts) != 0 {
		t.Fatal("limit<=0 时不该产生计数（避免无意义的 Redis 写入）")
	}
}

func TestWindowNilCounterAlwaysAllows(t *testing.T) {
	w := NewWindow(nil)
	if res := w.Allow(context.Background(), "rl:nil", 1); !res.Allowed {
		t.Fatal("没有计数实现时应放行")
	}
}

func TestAllowDailyLimitsWithinSameDay(t *testing.T) {
	c := newKeyedCounter()
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.Local)
	w := NewWindowWithClock(c, func() time.Time { return now })

	for i := 1; i <= 3; i++ {
		if res := w.AllowDaily(context.Background(), "rl:platform:wechat", 3); !res.Allowed {
			t.Fatalf("当日第 %d 次不应被拦截", i)
		}
	}
	res := w.AllowDaily(context.Background(), "rl:platform:wechat", 3)
	if res.Allowed {
		t.Fatal("超过日配额必须拦截")
	}
	// 同一天内建议等待时间应该指向次日零点，而不是 60 秒。
	if res.RetryAfter < 60 {
		t.Fatalf("日配额的重试等待应指向次日零点，实际 %d 秒", res.RetryAfter)
	}
}

func TestAllowDailyResetsAtMidnight(t *testing.T) {
	c := newKeyedCounter()
	now := time.Date(2026, 11, 2, 23, 59, 0, 0, time.Local)
	w := NewWindowWithClock(c, func() time.Time { return now })

	if res := w.AllowDaily(context.Background(), "rl:platform:alipay", 1); !res.Allowed {
		t.Fatal("当日第 1 次应放行")
	}
	if res := w.AllowDaily(context.Background(), "rl:platform:alipay", 1); res.Allowed {
		t.Fatal("当日第 2 次应拦截")
	}

	// 跨过零点：配额必须重置。这条用例盯的就是"跨天"——它一年只在零点
	// 暴露两次，写错了很难靠人工发现。
	now = now.Add(2 * time.Minute)
	if res := w.AllowDaily(context.Background(), "rl:platform:alipay", 1); !res.Allowed {
		t.Fatal("次日应重新放行")
	}
}
