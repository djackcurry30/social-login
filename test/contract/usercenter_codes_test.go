package contract_test

import (
	"testing"

	account "github.com/djackcurry30/social-login/internal/infrastructure/account"
	"github.com/djackcurry30/social-login/internal/testsupport/mockusercenter"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// TestUserCenterErrorCodes 断言三方错误码字面量完全一致。
//
// 三方各自写一份常量是刻意的：复用同一份常量会让"一边改了、另一边没改"
// 这种漂移永远测不出来，而跨服务契约最怕的正是这个——它在编译期毫无征兆，
// 只在上线后表现为"对方的错误信息变得含糊"或"该重试的没重试"。
//
//	用户中心  internal/usercenter/domain.Code*
//	消费方    internal/infrastructure/account.CodeUpstream*
//	假对端    internal/testsupport/mockusercenter.Code*
//
// 真对端的实现（cmd/usercenter）直接用 domain.Code*，所以它也被这条测试覆盖。
func TestUserCenterErrorCodes(t *testing.T) {
	cases := []struct {
		name string
		uc   domain.Code
		cons string
		mock string
	}{
		{"NOT_FOUND", domain.CodeNotFound, account.CodeUpstreamNotFound, mockusercenter.CodeNotFound},
		{"CLAIM_TAKEN", domain.CodeClaimTaken, account.CodeUpstreamClaimTaken, mockusercenter.CodeClaimTaken},
		{"MULTIPLE", domain.CodeMultiple, account.CodeUpstreamMultiple, mockusercenter.CodeMultiple},
		{"MERGE_REJECTED", domain.CodeMergeRejected, account.CodeUpstreamMergeRejected, mockusercenter.CodeMergeRejected},
		{"IDEM_IN_PROGRESS", domain.CodeIdemInProgress, account.CodeUpstreamIdemInProgress, mockusercenter.CodeIdemInProgress},
		{"CONFLICT", domain.CodeConflict, account.CodeUpstreamConflict, mockusercenter.CodeConflict},
		{"APP_UNKNOWN", domain.CodeAppUnknown, account.CodeUpstreamAppUnknown, mockusercenter.CodeAppUnknown},
		{"APP_DISABLED", domain.CodeAppDisabled, account.CodeUpstreamAppDisabled, mockusercenter.CodeAppDisabled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if string(c.uc) != c.cons {
				t.Errorf("用户中心 %q 与消费方 %q 不一致：改了一边却漏了另一边", c.uc, c.cons)
			}
			if string(c.uc) != c.mock {
				t.Errorf("用户中心 %q 与假对端 %q 不一致：假对端已不能代表真实契约", c.uc, c.mock)
			}
		})
	}
}

// TestIdempotencyHeader 幂等键头名也必须一致。
//
// 它是个字符串常量，最容易"看起来一样、实际差一个连字符"：
// 对端读不到键时的行为是 400，而消费方会把它当成"对方不支持幂等"，
// 于是补偿任务开始重复迁移。
func TestIdempotencyHeader(t *testing.T) {
	const ucHeader = "Idempotency-Key" // 与 httpapi.IdempotencyHeader 一致
	if account.IdempotencyHeader != ucHeader {
		t.Errorf("消费方的幂等键头 %q 与契约 %q 不一致", account.IdempotencyHeader, ucHeader)
	}
	if mockusercenter.IdempotencyHeader != ucHeader {
		t.Errorf("假对端的幂等键头 %q 与契约 %q 不一致", mockusercenter.IdempotencyHeader, ucHeader)
	}
}
