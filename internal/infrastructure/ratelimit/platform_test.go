package ratelimit

import (
	"context"
	"testing"
)

func TestPlatformQuotaDisabledAlwaysAllows(t *testing.T) {
	q := NewPlatformQuotaWithCounter(newCountingCounter(), false, map[string]int{"wechat": 1}, 0)
	for i := 0; i < 5; i++ {
		if ok, _ := q.Allow(context.Background(), "wechat"); !ok {
			t.Fatal("未启用时不应拦截")
		}
	}
}

func TestPlatformQuotaBlocksAfterDailyLimit(t *testing.T) {
	q := NewPlatformQuotaWithCounter(newCountingCounter(), true, map[string]int{"wechat": 2}, 0)

	if ok, _ := q.Allow(context.Background(), "wechat"); !ok {
		t.Fatal("第 1 次应放行")
	}
	if ok, _ := q.Allow(context.Background(), "wechat"); !ok {
		t.Fatal("第 2 次应放行")
	}
	ok, retry := q.Allow(context.Background(), "wechat")
	if ok {
		t.Fatal("超过日配额必须拦截")
	}
	if retry <= 0 {
		t.Fatalf("拦截时必须给出重试秒数，实际 %d", retry)
	}
}

func TestPlatformQuotaIsPerPlatform(t *testing.T) {
	q := NewPlatformQuotaWithCounter(newCountingCounter(), true,
		map[string]int{"wechat": 1, "alipay": 1}, 0)

	if ok, _ := q.Allow(context.Background(), "wechat"); !ok {
		t.Fatal("wechat 第 1 次应放行")
	}
	if ok, _ := q.Allow(context.Background(), "wechat"); ok {
		t.Fatal("wechat 第 2 次应被拦截")
	}
	// 一个渠道的配额用尽不该影响其它渠道：它们的上限是各自后台独立给的。
	if ok, _ := q.Allow(context.Background(), "alipay"); !ok {
		t.Fatal("alipay 应独立计数")
	}
}

func TestPlatformQuotaZeroMeansUnlimited(t *testing.T) {
	q := NewPlatformQuotaWithCounter(newCountingCounter(), true, nil, 0)
	for i := 0; i < 100; i++ {
		if ok, _ := q.Allow(context.Background(), "wechat"); !ok {
			t.Fatal("上限为 0 表示不限")
		}
	}
}

func TestPlatformQuotaFallsBackToDefault(t *testing.T) {
	q := NewPlatformQuotaWithCounter(newCountingCounter(), true, map[string]int{"wechat": 0}, 1)

	if q.Limit("wechat") != 0 {
		t.Fatal("显式配置为 0 的渠道应视为不限")
	}
	if q.Limit("apple") != 1 {
		t.Fatalf("未配置的渠道应取默认值 1，实际 %d", q.Limit("apple"))
	}
	if ok, _ := q.Allow(context.Background(), "apple"); !ok {
		t.Fatal("第 1 次应放行")
	}
	if ok, _ := q.Allow(context.Background(), "apple"); ok {
		t.Fatal("第 2 次应被默认上限拦截")
	}
}

func TestPlatformQuotaNilReceiver(t *testing.T) {
	var q *PlatformQuota
	if ok, _ := q.Allow(context.Background(), "wechat"); !ok {
		t.Fatal("nil 配额器应放行")
	}
	if q.Limit("wechat") != 0 {
		t.Fatal("nil 配额器的上限为 0")
	}
}
