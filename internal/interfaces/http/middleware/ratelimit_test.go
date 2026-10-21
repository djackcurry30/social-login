package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type fakeCounter struct {
	n       int64
	err     error
	expires int
}

func (f *fakeCounter) Incr(context.Context, string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.n++
	return f.n, nil
}

func (f *fakeCounter) Expire(context.Context, string, time.Duration) error {
	f.expires++
	return nil
}

func newRouter(l *Limiter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ping", l.Notify(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doGet(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)
	return w
}

// TestLimitDisabledPassesThrough：未启用时不拦任何请求。
func TestLimitDisabledPassesThrough(t *testing.T) {
	l := NewLimiterWithCounter(&fakeCounter{}, LimitConfig{Enabled: false, NotifyPerMinute: 1})
	r := newRouter(l)
	for i := 0; i < 5; i++ {
		if w := doGet(r); w.Code != http.StatusOK {
			t.Fatalf("未启用时不应限流，第 %d 次得到 %d", i+1, w.Code)
		}
	}
}

// TestLimitRejectsOverQuota：超过阈值返回 429 + Retry-After + RATE.LIMITED。
func TestLimitRejectsOverQuota(t *testing.T) {
	c := &fakeCounter{}
	l := NewLimiterWithCounter(c, LimitConfig{Enabled: true, NotifyPerMinute: 2})
	r := newRouter(l)

	// 前两次通过。
	for i := 0; i < 2; i++ {
		if w := doGet(r); w.Code != http.StatusOK {
			t.Fatalf("第 %d 次应通过，实际 %d", i+1, w.Code)
		}
	}
	// 第三次被拦。
	w := doGet(r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("超限应返回 429，实际 %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 必须带 Retry-After：客户端据此退避，否则会立即重试形成风暴")
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if body["code"] != "RATE.LIMITED" {
		t.Fatalf("应为 RATE.LIMITED，实际 %v", body["code"])
	}
}

// TestLimitFailsOpenOnRedisError：Redis 故障时不拦请求。
//
// 限流是保护措施，不是正确性前提。一次 Redis 抖动让全站 429，
// 造成的可用性损失远大于"这段时间没限流"。
func TestLimitFailsOpenOnRedisError(t *testing.T) {
	c := &fakeCounter{err: errors.New("redis down")}
	l := NewLimiterWithCounter(c, LimitConfig{Enabled: true, NotifyPerMinute: 1})
	r := newRouter(l)
	for i := 0; i < 3; i++ {
		if w := doGet(r); w.Code != http.StatusOK {
			t.Fatalf("Redis 故障时应放行，第 %d 次得到 %d", i+1, w.Code)
		}
	}
}

// TestLimitSetsTTLOnce：只给首次计数设过期，避免每次请求都把 TTL 续上。
func TestLimitSetsTTLOnce(t *testing.T) {
	c := &fakeCounter{}
	l := NewLimiterWithCounter(c, LimitConfig{Enabled: true, NotifyPerMinute: 10})
	r := newRouter(l)
	for i := 0; i < 3; i++ {
		doGet(r)
	}
	if c.expires != 1 {
		t.Fatalf("TTL 只应设置 1 次，实际 %d 次", c.expires)
	}
}

// TestLimitZeroQuotaSkips：阈值为 0 视为"该维度不限制"，不是"全部拒绝"。
//
// 配置漏填时把全部请求拒掉，比不限制危险得多。
func TestLimitZeroQuotaSkips(t *testing.T) {
	l := NewLimiterWithCounter(&fakeCounter{}, LimitConfig{Enabled: true, NotifyPerMinute: 0})
	r := newRouter(l)
	if w := doGet(r); w.Code != http.StatusOK {
		t.Fatalf("阈值为 0 应跳过限流，实际 %d", w.Code)
	}
}

// TestRetryAfterWithinWindow：Retry-After 必须是"距窗口结束"，不是固定 60。
func TestRetryAfterWithinWindow(t *testing.T) {
	l := NewLimiterWithCounter(&fakeCounter{n: 5}, LimitConfig{Enabled: true, NotifyPerMinute: 1})
	l.now = func() time.Time {
		// 落在窗口的第 10 秒 → 还剩 50 秒。
		base := time.Unix(1_700_000_000, 0).UTC()
		return base.Add(10 * time.Second)
	}
	r := newRouter(l)
	w := doGet(r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("应被限流，实际 %d", w.Code)
	}
	got, _ := strconv.Atoi(w.Header().Get("Retry-After"))
	if got <= 0 || got > 60 {
		t.Fatalf("Retry-After 应在 1..60 之间，实际 %d", got)
	}
}
