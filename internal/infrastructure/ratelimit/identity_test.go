package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

// countingCounter 按 key 独立计数。
//
// 必须按 key 分开：这组用例里有"身份 2 不受身份 1 计数影响"的断言，
// 用一个共享自增变量会把两件事混成一件，测出来的失败是假的。
type countingCounter struct {
	mu     sync.Mutex
	counts map[string]int64
}

func newCountingCounter() *countingCounter {
	return &countingCounter{counts: map[string]int64{}}
}

func (c *countingCounter) Incr(_ context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key]++
	return c.counts[key], nil
}

func (c *countingCounter) Expire(_ context.Context, _ string, _ time.Duration) error { return nil }

func TestIdentityLimiterDisabledAlwaysAllows(t *testing.T) {
	l := NewIdentityLimiterWithCounter(newCountingCounter(), false, 2)
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow(context.Background(), 42); !ok {
			t.Fatal("未启用时不应拦截")
		}
	}
}

func TestIdentityLimiterBlocksAfterThreshold(t *testing.T) {
	l := NewIdentityLimiterWithCounter(newCountingCounter(), true, 2)

	if ok, _ := l.Allow(context.Background(), 7); !ok {
		t.Fatal("第 1 次应放行")
	}
	if ok, _ := l.Allow(context.Background(), 7); !ok {
		t.Fatal("第 2 次应放行")
	}
	ok, retry := l.Allow(context.Background(), 7)
	if ok {
		t.Fatal("超过阈值必须拦截")
	}
	if retry <= 0 {
		t.Fatalf("拦截时必须给出重试秒数，实际 %d", retry)
	}
}

func TestIdentityLimiterDifferentIdentitiesAreIndependent(t *testing.T) {
	l := NewIdentityLimiterWithCounter(newCountingCounter(), true, 1)

	if ok, _ := l.Allow(context.Background(), 1); !ok {
		t.Fatal("身份 1 第 1 次应放行")
	}
	if ok, _ := l.Allow(context.Background(), 1); ok {
		t.Fatal("身份 1 第 2 次应被拦截")
	}
	// 身份 2 不该被身份 1 的计数拖累——限流按身份隔离，这是"单身份被打爆
	// 不影响其他人"的前提。
	if ok, _ := l.Allow(context.Background(), 2); !ok {
		t.Fatal("身份 2 应独立计数")
	}
}

func TestIdentityLimiterNilReceiver(t *testing.T) {
	var l *IdentityLimiter
	if ok, _ := l.Allow(context.Background(), 1); !ok {
		t.Fatal("nil 限流器应放行（等价于未启用）")
	}
	if l.PerMinute() != 0 {
		t.Fatal("nil 限流器的阈值为 0")
	}
}

func TestIdentityLimiterDefaultThreshold(t *testing.T) {
	l := NewIdentityLimiterWithCounter(newCountingCounter(), true, 0)
	if l.PerMinute() != DefaultIdentityPerMinute {
		t.Fatalf("阈值未填时应取默认值 %d，实际 %d", DefaultIdentityPerMinute, l.PerMinute())
	}
}
