package domain_test

import (
	"net/http"
	"testing"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// TestErrorCodeLiterals 锁定错误码的字面量。
//
// 这张表是【对外契约】的一部分：消费方（social-login 的
// infrastructure/account）按这些字符串做 switch 翻译，业务方按它们写分支。
// 改一个字母，对方就会落到"未识别的码 → 通用失败"，而现象只是
// "错误信息变得含糊"，很容易被当成文案问题放过去。
//
// 跨服务的一致性由 test/contract/usercenter_codes_test.go 守（那里可以
// 同时引用两边）；这里只锁本服务的约定，改了就该有人停下来想一想。
func TestErrorCodeLiterals(t *testing.T) {
	cases := []struct {
		code domain.Code
		want string
	}{
		{domain.CodeNotFound, "ACCOUNT.NOT_FOUND"},
		{domain.CodeClaimTaken, "ACCOUNT.CLAIM_TAKEN"},
		{domain.CodeMultiple, "ACCOUNT.MULTIPLE"},
		{domain.CodeMergeRejected, "ACCOUNT.MERGE_REJECTED"},
		{domain.CodeIdemInProgress, "ACCOUNT.IDEMPOTENCY_IN_PROGRESS"},
		{domain.CodeConflict, "ACCOUNT.CONFLICT"},
		{domain.CodeAppUnknown, "APP.UNKNOWN"},
		{domain.CodeAppDisabled, "APP.DISABLED"},
		{domain.CodeInvalid, "INVALID.REQUEST"},
		{domain.CodeInternal, "INTERNAL.ERROR"},
		{domain.CodeUnauthorized, "AUTH.UNAUTHORIZED"},
	}
	for _, c := range cases {
		if string(c.code) != c.want {
			t.Errorf("错误码 %q 被改成了 %q（对外契约，不能随意改名）", c.want, c.code)
		}
	}
}

// TestErrorStatusInvariants 锁定"状态码与可重试性"的组合。
//
// 这张表是双向约束：消费方的 classify() 会【先】看 429 / 5xx 再读信封。
// 所以"凭证被占用"必须是 409 而不是 500，否则一次正常的业务冲突会被
// 译成"用户中心不可用（可重试）"。
func TestErrorStatusInvariants(t *testing.T) {
	cases := []struct {
		code      domain.Code
		status    int
		retryable bool
	}{
		{domain.CodeNotFound, http.StatusNotFound, false},
		{domain.CodeClaimTaken, http.StatusConflict, false},
		{domain.CodeMultiple, http.StatusConflict, false},
		{domain.CodeMergeRejected, http.StatusConflict, false},
		// 并发冲突与幂等处理中是可重试的：等一会儿再来可能就成功了。
		{domain.CodeConflict, http.StatusConflict, true},
		{domain.CodeIdemInProgress, http.StatusConflict, true},
		// 应用未注册用 400 而不是 409：409 会被译成"凭证被占用"，
		// 把排障方向从"配置问题"带偏到"数据冲突"（§2.5）。
		{domain.CodeAppUnknown, http.StatusBadRequest, false},
		{domain.CodeAppDisabled, http.StatusForbidden, false},
		{domain.CodeInvalid, http.StatusBadRequest, false},
	}
	for _, c := range cases {
		e := domain.New(c.code, "x")
		if e.Status != c.status {
			t.Errorf("%s: status=%d, want %d", c.code, e.Status, c.status)
		}
		if e.Retryable != c.retryable {
			t.Errorf("%s: retryable=%v, want %v", c.code, e.Retryable, c.retryable)
		}
	}
}

// TestUnknownCodeFailsSafe 未登记的码不能静默变成 200。
func TestUnknownCodeFailsSafe(t *testing.T) {
	e := domain.New(domain.Code("SOMETHING.NEW"), "x")
	if e.Status != http.StatusInternalServerError {
		t.Errorf("未登记错误码的默认状态码应为 500，实际 %d", e.Status)
	}
}

func TestAsAndWrap(t *testing.T) {
	base := domain.New(domain.CodeClaimTaken, "被占用")
	wrapped := domain.New(domain.CodeInternal, "外层").WithCause(base)

	e, ok := domain.As(wrapped)
	if !ok || e.Code != domain.CodeInternal {
		t.Fatalf("As 应取到最外层的错误，实际 %v/%v", e, ok)
	}
}
