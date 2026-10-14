package errs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// TestRetryableContract 是约束 C6 的核心契约测试。
//
// 本服务对三方渠道不做网络重试，因此 retryable 字段是接入方【唯一】能据以判断
// "要不要重开一次授权流程"的依据。它一旦标错，接入方要么白重试，
// 要么在本该重试时放弃，两种都是线上可见的故障。
func TestRetryableContract(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code      Code
		retryable bool
	}{
		// 平台侧暂时性故障：重开授权流程有意义。
		{CodeProviderUnavailable, true},
		{CodeProviderTimeout, true},
		{CodeProviderCircuitOpen, true},
		{CodeProviderQuotaExceeded, true},
		{CodeAccountUnavailable, true},
		{CodeRequestTimeout, true},

		// 授权码无效/已消费：重试永远得到同样结果。
		{CodeProviderRejected, false},
		{CodeAuthInvalidState, false},
		{CodeAuthTicketExpired, false},
		{CodeAuthInvalidNonce, false},
		{CodeAuthNeedRegister, false},
		{CodeAuthInvalidConfig, false},

		// 需要业务处理，不是重试场景。
		{CodeBindIdentityTaken, false},
		{CodeBindTicketInvalid, false},
		{CodeTokenExpired, false},
		{CodeTokenRevoked, false},
		{CodeInvalidRequest, false},
		{CodeConfigInvalid, false},
	}
	for _, tc := range cases {
		e := New(tc.code, "x")
		if e.Retryable != tc.retryable {
			t.Errorf("%s 的 retryable 期望 %v，实际 %v", tc.code, tc.retryable, e.Retryable)
		}
		if Retryable(e) != tc.retryable {
			t.Errorf("%s 的 Retryable() 与字段不一致", tc.code)
		}
	}
}

// TestHTTPStatusMapping 验证错误码到 HTTP 状态码的映射。
func TestHTTPStatusMapping(t *testing.T) {
	t.Parallel()

	cases := map[Code]int{
		CodeInvalidRequest:       http.StatusBadRequest,
		CodeUnauthorized:         http.StatusUnauthorized,
		CodeForbidden:            http.StatusForbidden,
		CodeRateLimited:          http.StatusTooManyRequests,
		CodeAuthNeedRegister:     http.StatusConflict,
		CodeBindIdentityTaken:    http.StatusConflict,
		CodeTokenExpired:         http.StatusUnauthorized,
		CodeProviderUnavailable:  http.StatusBadGateway,
		CodeProviderTimeout:      http.StatusGatewayTimeout,
		CodeProviderCircuitOpen:  http.StatusServiceUnavailable,
		CodeRequestTimeout:       http.StatusGatewayTimeout,
		CodeAuthInvalidConfig:    http.StatusInternalServerError,
		CodeProviderNotSupported: http.StatusNotImplemented,
		CodeAccountNotSupported:  http.StatusNotImplemented,
	}
	for code, want := range cases {
		e := New(code, "x")
		if e.Status != want {
			t.Errorf("%s 的 HTTP 状态期望 %d，实际 %d", code, want, e.Status)
		}
	}
}

// TestUnknownCodeFallsBackSafely 验证未知错误码不会退化为 2xx 或 retryable。
func TestUnknownCodeFallsBackSafely(t *testing.T) {
	t.Parallel()

	e := New(Code("NOT.A.REAL.CODE"), "x")
	if e.Status != http.StatusInternalServerError {
		t.Errorf("未知错误码必须落到 500，实际 %d", e.Status)
	}
	if e.Retryable {
		t.Error("未知错误码默认必须不可重试——宁可漏重试，也不能让接入方无脑重试")
	}
}

// TestFromNormalizesForeignErrors 验证外部错误被归一化且不泄漏细节。
func TestFromNormalizesForeignErrors(t *testing.T) {
	t.Parallel()

	foreign := errors.New("pq: password authentication failed for user \"postgres\"")
	e := From(foreign)
	if e.Code != CodeInternal {
		t.Errorf("外部错误应归一化为 INTERNAL.ERROR，实际 %s", e.Code)
	}
	if e.Message != "内部错误" {
		t.Errorf("对外消息不得包含底层细节，实际 %q", e.Message)
	}
	// 但底层原因必须保留，供服务端日志排障。
	if !errors.Is(e, foreign) {
		t.Error("必须保留 cause 以便日志追溯")
	}
}

// TestWrapPreservesChainAndCode 验证包装后仍能取出原始错误码。
func TestWrapPreservesChainAndCode(t *testing.T) {
	t.Parallel()

	inner := New(CodeProviderTimeout, "超时")
	outer := Wrap(CodeInternal, "外层", inner)

	if CodeOf(outer) != CodeInternal {
		t.Errorf("CodeOf 应返回最外层的错误码，实际 %s", CodeOf(outer))
	}
	if !Is(outer, CodeInternal) {
		t.Error("Is 应匹配最外层")
	}
	var innerErr *Error
	if !errors.As(outer, &innerErr) {
		t.Fatal("errors.As 应能取出 *Error")
	}
	if !errors.Is(outer, inner) {
		t.Error("必须能沿链找到内层错误")
	}
}

// TestWrapNilReturnsNil 让 `return errs.Wrap(...)` 的直写风格可用。
func TestWrapNilReturnsNil(t *testing.T) {
	t.Parallel()

	if e := Wrap(CodeInternal, "x", nil); e != nil {
		t.Fatalf("err == nil 时应返回 nil，实际 %v", e)
	}
	if From(nil) != nil {
		t.Fatal("From(nil) 必须返回 nil")
	}
}

// TestWithDetailDoesNotMutateSharedDefaults 验证 Details 是每个实例独立的。
//
// 如果实现里把 Details 做成包级共享 map，"给某个错误加一个 detail"
// 会污染所有同码错误——这类 bug 只在并发下偶发，极难定位。
func TestWithDetailDoesNotMutateSharedDefaults(t *testing.T) {
	t.Parallel()

	a := New(CodeProviderTimeout, "a").WithDetail("k", "v-a")
	b := New(CodeProviderTimeout, "b")
	if _, exists := b.Details["k"]; exists {
		t.Fatal("两个错误实例的 Details 必须互不影响")
	}
	if a.Details["k"] != "v-a" {
		t.Fatal("detail 未正确写入")
	}
}

// TestContextDeadlineExceededIsRecognizable 验证入站超时能被识别。
//
// httpapi.Fail 依赖 errors.Is(err, context.DeadlineExceeded) 把它映射为
// 504 + retryable；如果这里断路，超时会被笼统报成 500，
// 接入方就分不清"我们超时了"和"我们崩了"。
func TestContextDeadlineExceededIsRecognizable(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("查询失败: %w", context.DeadlineExceeded)
	if !errors.Is(wrapped, context.DeadlineExceeded) {
		t.Fatal("包装后的超时错误必须仍可被 errors.Is 识别")
	}
}
