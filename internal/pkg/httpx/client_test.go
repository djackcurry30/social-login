package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// TestDoClassifiesFailureForCircuitBreaker 验证失败分类。
//
// 这一层分类是熔断器的判定基础（架构 §5.6.4）：只有 retryable 的错误才应计入
// 熔断。如果这里把 4xx（业务拒绝）也标成 retryable，攻击者用无效 code
// 高频打回调就能熔断整个渠道——从"平台保护"变成"服务级拒绝服务"。
func TestDoClassifiesFailureForCircuitBreaker(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/bad-request":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code 已使用"}`))
		case "/server-error":
			w.WriteHeader(http.StatusInternalServerError)
		case "/slow":
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	client := New(Config{Name: "test", TotalTimeout: 100 * time.Millisecond})

	t.Run("成功", func(t *testing.T) {
		var out map[string]any
		if _, err := client.GetJSON(context.Background(), srv.URL+"/ok", nil, &out); err != nil {
			t.Fatalf("期望成功，实际 %v", err)
		}
	})

	t.Run("4xx 是业务拒绝，不可重试", func(t *testing.T) {
		var out map[string]any
		_, err := client.GetJSON(context.Background(), srv.URL+"/bad-request", nil, &out)
		if err == nil {
			t.Fatal("4xx 必须返回错误")
		}
		if errs.CodeOf(err) != errs.CodeProviderRejected {
			t.Fatalf("期望 PROVIDER.REJECTED，实际 %s", errs.CodeOf(err))
		}
		if errs.Retryable(err) {
			t.Fatal("业务拒绝必须不可重试——否则会被构造为熔断攻击面")
		}
		// 平台错误描述应出现在 details 里，便于排障。
		e, _ := errs.As(err)
		if e.Details["provider_error"] == nil {
			t.Error("应把三方错误描述放入 details")
		}
	})

	t.Run("5xx 可重试", func(t *testing.T) {
		_, err := client.GetJSON(context.Background(), srv.URL+"/server-error", nil, nil)
		if errs.CodeOf(err) != errs.CodeProviderUnavailable {
			t.Fatalf("期望 PROVIDER.UNAVAILABLE，实际 %s", errs.CodeOf(err))
		}
		if !errs.Retryable(err) {
			t.Fatal("三方 5xx 必须标记为可重试")
		}
	})

	t.Run("超时归为 PROVIDER.TIMEOUT", func(t *testing.T) {
		_, err := client.GetJSON(context.Background(), srv.URL+"/slow", nil, nil)
		if errs.CodeOf(err) != errs.CodeProviderTimeout {
			t.Fatalf("期望 PROVIDER.TIMEOUT，实际 %s", errs.CodeOf(err))
		}
		if !errs.Retryable(err) {
			t.Fatal("超时必须标记为可重试")
		}
	})
}

// TestClientNeverRetries 验证约束 C6：一次失败即失败。
//
// 用"响应体里带 code 的 POST"来模拟三方授权码交换：重试会拿到
// "code 已使用"，因此不重试是语义正确性要求，不是性能优化。
func TestClientNeverRetries(t *testing.T) {
	t.Parallel()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	client := New(Config{Name: "test", TotalTimeout: time.Second})
	form := url.Values{"code": {"one-time-code"}}
	_, err := client.PostFormJSON(context.Background(), srv.URL+"/token", form, nil)
	if err == nil {
		t.Fatal("期望失败")
	}
	if calls != 1 {
		t.Fatalf("必须只调用一次（不重试），实际 %d 次", calls)
	}
}

// TestDoRejectsOversizedBody 验证响应体上限。
//
// 三方返回超大 body 不能打爆内存——这是最容易被忽略、但一旦发生就是 OOM 的路径。
func TestDoRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		big := make([]byte, 4096)
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	client := New(Config{Name: "test", TotalTimeout: time.Second, MaxBodyBytes: 1024})
	_, err := client.GetJSON(context.Background(), srv.URL, nil, nil)
	if err == nil {
		t.Fatal("超过上限的响应体必须被拒绝")
	}
	if errs.CodeOf(err) != errs.CodeProviderUnavailable {
		t.Fatalf("期望 PROVIDER.UNAVAILABLE，实际 %s", errs.CodeOf(err))
	}
}

// TestDetachIgnoresParentCancellation 验证取消隔离（架构 §5.7 第 3 条）。
//
// 场景：用户发起授权后断网，入站 context 被取消；但 Exchange 请求可能已经到达
// 平台、授权码已被消费。如果沿用入站 context，我们会既拿不到令牌、
// 又已经把 code 烧掉——用户必须重新授权，而这次失败本可避免。
func TestDetachIgnoresParentCancellation(t *testing.T) {
	t.Parallel()

	reached := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reached)
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer srv.Close()

	parent, cancel := context.WithCancel(context.Background())
	client := New(Config{Name: "test", TotalTimeout: time.Second})

	detached, detachCancel := Detach(parent, time.Second)
	defer detachCancel()

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		var out map[string]any
		_, err := client.GetJSON(detached, srv.URL, nil, &out)
		done <- result{err: err}
	}()

	<-reached
	// 模拟用户断网：取消父 context。
	cancel()

	res := <-done
	if res.err != nil {
		t.Fatalf("脱离父 context 后不应被取消，实际 %v", res.err)
	}

	// 反证：不 Detach 时同样的取消会导致失败。
	parent2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() {
		var out map[string]any
		_, err := client.GetJSON(parent2, srv.URL, nil, &out)
		done2 <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel2()
	if err := <-done2; err == nil {
		t.Fatal("未 Detach 时取消父 context 应导致请求失败（说明 Detach 确实起了作用）")
	}
}

// TestMaskURL 验证敏感查询参数被掩码。
func TestMaskURL(t *testing.T) {
	t.Parallel()

	raw := "https://api.example.com/token?access_token=SECRET&code=ABC&appid=public"
	got := MaskURL(raw)
	for _, leaked := range []string{"SECRET", "ABC"} {
		if contains(got, leaked) {
			t.Errorf("敏感值 %q 未被掩码: %s", leaked, got)
		}
	}
	if !contains(got, "appid=public") {
		t.Errorf("非敏感参数应保留: %s", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
