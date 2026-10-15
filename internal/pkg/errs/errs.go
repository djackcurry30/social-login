// Package errs 定义本服务对外稳定的错误码契约。
//
// 为什么自研而不是用 github.com/pkg/errors：
// 本服务的错误码是【对外产品契约】——业务方按 code 做分支，并按 retryable
// 决定是否重新发起授权流程（约束 C6，架构 §5.5）。pkg/errors 解决的是错误
// 包装与堆栈，不解决"稳定的业务错误码"这件事。
package errs

import (
	"errors"
	"fmt"
	"net/http"
)

// Code 是对外稳定的业务错误码，形如 AUTH.INVALID_STATE。
// 命名规则：<域>.<原因>，域固定为大写单词，原因固定为大写下划线单词。
// 一旦发布不得改名——业务方会按它写分支。
type Code string

const (
	CodeInternal       Code = "INTERNAL.ERROR"
	CodeInvalidRequest Code = "REQUEST.INVALID"
	CodeRequestTimeout Code = "REQUEST.TIMEOUT"
	CodeRateLimited    Code = "RATE.LIMITED"
	CodeUnauthorized   Code = "AUTH.UNAUTHORIZED"
	CodeForbidden      Code = "AUTH.FORBIDDEN"
	CodeNotFound       Code = "RESOURCE.NOT_FOUND"
	CodeConfigInvalid  Code = "CONFIG.INVALID"

	CodeAuthInvalidState  Code = "AUTH.INVALID_STATE"
	CodeAuthTicketExpired Code = "AUTH.TICKET_EXPIRED"
	CodeAuthInvalidNonce  Code = "AUTH.INVALID_NONCE"
	CodeAuthNeedRegister  Code = "AUTH.NEED_REGISTER"
	CodeAuthInvalidConfig Code = "AUTH.INVALID_CONFIG"
	CodeAuthAppDisabled   Code = "AUTH.APP_DISABLED"
	CodeAuthReplay        Code = "AUTH.REPLAY_DETECTED"

	CodeBindIdentityTaken Code = "BIND.IDENTITY_TAKEN"
	CodeBindTicketInvalid Code = "BIND.TICKET_INVALID"
	CodeBindNotFound      Code = "BIND.NOT_FOUND"
	CodeBindDuplicate     Code = "BIND.DUPLICATE"

	CodeTokenExpired Code = "TOKEN.EXPIRED"
	CodeTokenRevoked Code = "TOKEN.REVOKED"
	CodeTokenInvalid Code = "TOKEN.INVALID"

	CodeProviderUnavailable   Code = "PROVIDER.UNAVAILABLE"
	CodeProviderTimeout       Code = "PROVIDER.TIMEOUT"
	CodeProviderRejected      Code = "PROVIDER.REJECTED"
	CodeProviderQuotaExceeded Code = "PROVIDER.QUOTA_EXCEEDED"
	CodeProviderNotSupported  Code = "PROVIDER.NOT_SUPPORTED"
	CodeProviderNotFound      Code = "PROVIDER.NOT_FOUND"
	CodeProviderCircuitOpen   Code = "PROVIDER.CIRCUIT_OPEN"

	CodeAccountUnavailable  Code = "ACCOUNT.UNAVAILABLE"
	CodeAccountNotFound     Code = "ACCOUNT.NOT_FOUND"
	CodeAccountNotSupported Code = "ACCOUNT.NOT_SUPPORTED"

	// 管理端专用（§15）。CodeAuthAdmin* 与 CodeAuth* 业务端解耦：
	// 管理端请求的鉴权失败走 CodeUnauthorized 与 CodeForbidden 即可，
	// 业务语义错误（如 token 过期、token 撤销）才有必要单列。
	CodeAdminSessionExpired Code = "ADMIN.SESSION_EXPIRED"
	CodeAdminSessionRevoked Code = "ADMIN.SESSION_REVOKED"
	CodeAdminReasonRequired Code = "ADMIN.REASON_REQUIRED"
	CodeAdminVerifyFailed   Code = "ADMIN.VERIFY_FAILED"
	CodeAdminConflict       Code = "ADMIN.CONFLICT"
)

// meta 是错误码的默认元信息。默认值可以被具体错误实例覆盖。
type meta struct {
	status    int  // 对外 HTTP 状态码
	retryable bool // 接入方是否应重开授权流程（约束 C6 的核心契约）
}

// defaults 是错误码 → 默认元信息 的权威表。
//
// retryable 的判定口径（架构 §5.5）：这个错误能否通过"重新发起一次 /v1/authorize"
// 解决。注意它不是"换个时间再来一次 HTTP 请求"——本服务对三方渠道不做重试。
var defaults = map[Code]meta{
	CodeInternal:       {http.StatusInternalServerError, false},
	CodeInvalidRequest: {http.StatusBadRequest, false},
	CodeRequestTimeout: {http.StatusGatewayTimeout, true},
	CodeRateLimited:    {http.StatusTooManyRequests, false},
	CodeUnauthorized:   {http.StatusUnauthorized, false},
	CodeForbidden:      {http.StatusForbidden, false},
	CodeNotFound:       {http.StatusNotFound, false},
	CodeConfigInvalid:  {http.StatusBadRequest, false},

	CodeAuthInvalidState:  {http.StatusBadRequest, false},
	CodeAuthTicketExpired: {http.StatusBadRequest, false},
	CodeAuthInvalidNonce:  {http.StatusBadRequest, false},
	CodeAuthNeedRegister:  {http.StatusConflict, false},
	CodeAuthInvalidConfig: {http.StatusInternalServerError, false},
	CodeAuthAppDisabled:   {http.StatusForbidden, false},
	CodeAuthReplay:        {http.StatusBadRequest, false},

	CodeBindIdentityTaken: {http.StatusConflict, false},
	CodeBindTicketInvalid: {http.StatusBadRequest, false},
	CodeBindNotFound:      {http.StatusNotFound, false},
	CodeBindDuplicate:     {http.StatusConflict, false},

	CodeTokenExpired: {http.StatusUnauthorized, false},
	CodeTokenRevoked: {http.StatusUnauthorized, false},
	CodeTokenInvalid: {http.StatusUnauthorized, false},

	CodeProviderUnavailable:   {http.StatusBadGateway, true},
	CodeProviderTimeout:       {http.StatusGatewayTimeout, true},
	CodeProviderRejected:      {http.StatusBadRequest, false},
	CodeProviderQuotaExceeded: {http.StatusServiceUnavailable, true},
	CodeProviderNotSupported:  {http.StatusNotImplemented, false},
	CodeProviderNotFound:      {http.StatusNotFound, false},
	CodeProviderCircuitOpen:   {http.StatusServiceUnavailable, true},

	CodeAccountUnavailable:  {http.StatusServiceUnavailable, true},
	CodeAccountNotFound:     {http.StatusNotFound, false},
	CodeAccountNotSupported: {http.StatusNotImplemented, false},
}

// Error 是本服务统一的错误类型。所有跨越层边界的错误都应归一化为它。
type Error struct {
	Code      Code
	Message   string // 面向接入方的可读信息，不泄漏内部细节
	Retryable bool
	Status    int
	// RetryAfterMs 是建议退避时间，0 表示未给建议。
	RetryAfterMs int
	// Details 承载排障上下文（三方原始错误等）。允许包含平台原始错误码，
	// 但【不得包含】凭据、token、session_key 等敏感值。
	Details map[string]any

	cause error
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap 支持 errors.Is / errors.As 向下追溯原因。
func (e *Error) Unwrap() error { return e.cause }

// New 构造一个错误。元信息（HTTP 状态、retryable）取自默认表。
func New(code Code, message string) *Error {
	m, ok := defaults[code]
	if !ok {
		m = defaults[CodeInternal]
	}
	return &Error{
		Code:      code,
		Message:   message,
		Retryable: m.retryable,
		Status:    m.status,
	}
}

// Newf 是 New 的格式化版本。
func Newf(code Code, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

// Wrap 在保留 err 作为 cause 的同时，归一化为本服务的错误码。
// err 为 nil 时返回 nil，便于 `return errs.Wrap(code, msg, err)` 的直写风格。
func Wrap(code Code, message string, err error) *Error {
	if err == nil {
		return nil
	}
	e := New(code, message)
	e.cause = err
	return e
}

// WithDetail 追加排障上下文，返回自身以便链式调用。
func (e *Error) WithDetail(key string, value any) *Error {
	if e.Details == nil {
		e.Details = make(map[string]any, 4)
	}
	e.Details[key] = value
	return e
}

// WithDetails 批量追加排障上下文。
func (e *Error) WithDetails(d map[string]any) *Error {
	for k, v := range d {
		e.WithDetail(k, v)
	}
	return e
}

// WithRetryable 显式覆盖 retryable（用于少数需要按场景区分的错误）。
func (e *Error) WithRetryable(v bool) *Error {
	e.Retryable = v
	return e
}

// WithRetryAfter 设置建议退避时间。
func (e *Error) WithRetryAfter(ms int) *Error {
	e.RetryAfterMs = ms
	return e
}

// WithCause 设置底层原因。
func (e *Error) WithCause(err error) *Error {
	e.cause = err
	return e
}

// From 把任意 error 归一化为 *Error。已是 *Error 则原样返回；
// 否则包装为 CodeInternal（不泄漏内部细节）。
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Wrap(CodeInternal, "内部错误", err)
}

// As 尝试取出 *Error。
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Is 判断 err 链上是否存在指定错误码。
func Is(err error, code Code) bool {
	e, ok := As(err)
	return ok && e.Code == code
}

// CodeOf 返回错误码；非本服务错误返回 CodeInternal。
func CodeOf(err error) Code {
	e, ok := As(err)
	if !ok {
		return CodeInternal
	}
	return e.Code
}

// Retryable 判断错误是否可重试（约束 C6 的对外契约）。
func Retryable(err error) bool {
	e, ok := As(err)
	return ok && e.Retryable
}

// Status 返回对外 HTTP 状态码。
func Status(err error) int {
	e, ok := As(err)
	if !ok {
		return http.StatusInternalServerError
	}
	if e.Status == 0 {
		return http.StatusInternalServerError
	}
	return e.Status
}
