// Package domain 是用户中心的业务语义：账号、凭证、错误码。
//
// 这一层刻意不 import 任何 HTTP / SQL / 加密实现：错误码与状态映射是
// 【对外契约】的一部分，必须能脱离框架被单测和复用（假对端就是靠它对齐的）。
package domain

import (
	"errors"
	"fmt"
	"net/http"
)

// Code 是对外稳定的错误码。
//
// 取值与 social-login 的 internal/infrastructure/account/http.go 里的
// CodeUpstream* 一一对应——两边各自写一份字面量，由 test/contract 断言相等。
// 复用同一份常量会让"对端改了码、消费方没改"这种漂移永远测不出来，
// 而跨服务契约最怕的正是这个。
//
// ⚠️ 本包（以及整个 internal/usercenter/**）【不得】import 登录中心的任何包，
// 包括只为了对比常量的测试。跨服务的断言一律放 test/contract/，
// 那是唯一允许同时看到两边的目录。规则与理由见 docs/user-center-mvp-design.md §15，
// 由 scripts/check-service-boundary.sh 强制。
type Code string

const (
	// CodeNotFound：账号或凭证不存在。跨应用访问也返回它（不泄漏存在性）。
	CodeNotFound Code = "ACCOUNT.NOT_FOUND"
	// CodeClaimTaken：该凭证值已被同应用内的其他账号持有。
	CodeClaimTaken Code = "ACCOUNT.CLAIM_TAKEN"
	// CodeMultiple：按凭证反查到多个账号。正常数据下不可能出现，
	// 出现即表示唯一性已坏，必须让调用方走人工排查而不是择一返回。
	CodeMultiple Code = "ACCOUNT.MULTIPLE"
	// CodeMergeRejected：合并被业务规则拒绝（target 已关闭、同 id 等）。
	CodeMergeRejected Code = "ACCOUNT.MERGE_REJECTED"
	// CodeIdemInProgress：同一幂等键的另一请求正在处理中，稍后重试。
	CodeIdemInProgress Code = "ACCOUNT.IDEMPOTENCY_IN_PROGRESS"
	// CodeConflict：并发写冲突（如两个换绑同时提交），可重试。
	CodeConflict Code = "ACCOUNT.CONFLICT"

	// CodeAppUnknown：应用未注册。用 400 而不是 409——
	// 409 会被消费方译成"凭证被占用"，把排障方向彻底带偏（§2.5）。
	CodeAppUnknown Code = "APP.UNKNOWN"
	// CodeAppDisabled：应用已停用。
	CodeAppDisabled Code = "APP.DISABLED"

	// CodeInvalid 是请求本身不合法（缺字段、类型不支持、幂等键复用于不同请求体）。
	CodeInvalid Code = "INVALID.REQUEST"
	// CodeInternal 是本服务内部故障（DB 不可用等）。
	CodeInternal Code = "INTERNAL.ERROR"
	// CodeUnauthorized 是服务间鉴权失败。
	CodeUnauthorized Code = "AUTH.UNAUTHORIZED"
)

// Error 是带 HTTP 语义的业务错误。
//
// 不直接复用 social-login 的 pkg/errs：那张默认表里没有 ACCOUNT.* 的码，
// 未知码会退化成 500——而 409 与 500 对调用方的含义（要不要重试、
// 是不是凭证被占用）完全不同。本服务的错误码与状态码是一起设计的，
// 所以放在一起。
type Error struct {
	Code      Code
	Message   string
	Status    int
	Retryable bool
	// Details 只进日志，不进响应体（可能含内部信息）。
	Details map[string]any
	cause   error
}

// Error 实现 error。
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap 暴露底层错误，供 errors.Is/As 使用。
func (e *Error) Unwrap() error { return e.cause }

// WithCause 附加底层错误（只用于日志，不进响应）。
func (e *Error) WithCause(err error) *Error {
	e.cause = err
	return e
}

// WithDetail 附加排障信息（只用于日志）。
func (e *Error) WithDetail(k string, v any) *Error {
	if e.Details == nil {
		e.Details = make(map[string]any, 2)
	}
	e.Details[k] = v
	return e
}

// New 按错误码构造错误，状态码与可重试性取自下面的权威表。
func New(code Code, message string) *Error {
	m := metaOf(code)
	return &Error{Code: code, Message: message, Status: m.status, Retryable: m.retryable}
}

// Newf 是 New 的格式化版本。
func Newf(code Code, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

// As 从错误链里取出 *Error。
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// meta 是错误码的默认 HTTP 语义。
type meta struct {
	status    int
	retryable bool
}

// defaults 是错误码 → HTTP 语义的权威表。
//
// retryable 的口径是"调用方是否可以原样重试这次写操作"：
//   - 凭证被占用、参数非法、应用未注册：重试一百次结果一样 → false
//   - 并发冲突、幂等处理中、内部故障：等一会儿可能就好了 → true
//
// 这张表和 social-login 适配层的 classify() 是【双向约束】：
// 这里选的状态码，会被对方按 code 翻译成对应业务语义。
var defaults = map[Code]meta{
	CodeNotFound:       {http.StatusNotFound, false},
	CodeClaimTaken:     {http.StatusConflict, false},
	CodeMultiple:       {http.StatusConflict, false},
	CodeMergeRejected:  {http.StatusConflict, false},
	CodeIdemInProgress: {http.StatusConflict, true},
	CodeConflict:       {http.StatusConflict, true},
	CodeAppUnknown:     {http.StatusBadRequest, false},
	CodeAppDisabled:    {http.StatusForbidden, false},
	CodeInvalid:        {http.StatusBadRequest, false},
	CodeInternal:       {http.StatusInternalServerError, true},
	CodeUnauthorized:   {http.StatusUnauthorized, false},
}

// metaOf 查表；未登记的码按内部错误处理（宁可 500 也不要静默 200）。
func metaOf(code Code) meta {
	if m, ok := defaults[code]; ok {
		return m
	}
	return meta{http.StatusInternalServerError, false}
}
