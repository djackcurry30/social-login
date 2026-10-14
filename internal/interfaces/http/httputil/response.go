// Package httputil 是 HTTP 接入层的公共部分：统一响应、错误映射与绑定助手。
//
// 单独成包而不是放在 httpapi 里，是为了避免依赖环：
// httpapi 需要引用 middleware（装配路由），middleware 又需要写统一错误响应。
// 把响应助手抽到最底层即可同时满足两者。
package httputil

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// TraceIDHeader 是贯穿全链路的追踪标识响应头。
const TraceIDHeader = "X-Trace-Id"

// ErrorBody 是统一的错误响应体。
//
// retryable 是【必带字段】（约束 C6 的核心契约）：本服务对三方渠道不做重试，
// 因此必须明确告知接入方"这个错误能否通过重开授权流程解决"，
// 而不是让接入方凭错误码猜。
type ErrorBody struct {
	Code         string         `json:"code"`
	Message      string         `json:"message"`
	Retryable    bool           `json:"retryable"`
	RetryAfterMs int            `json:"retry_after_ms,omitempty"`
	TraceID      string         `json:"trace_id,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

// OK 输出成功响应。
func OK(c *gin.Context, status int, data any) {
	c.JSON(status, data)
}

// Fail 把错误按统一契约输出。
func Fail(c *gin.Context, logger *zap.Logger, err error) {
	// 入站超时（§5.7 的中间件把 deadline 放进了 request context）会以
	// context.DeadlineExceeded 冒泡上来。它需要映射为明确的 504 + retryable，
	// 否则会被归一化成 500，接入方就分不清"我们超时了"和"我们崩了"。
	if errors.Is(err, context.DeadlineExceeded) {
		var already *errs.Error
		if !errors.As(err, &already) {
			err = errs.Wrap(errs.CodeRequestTimeout, "请求处理超时", err)
		}
	}

	e := errs.From(err)
	if e == nil {
		e = errs.New(errs.CodeInternal, "内部错误")
	}

	// trace_id 优先取 gin context（由 RequestID 中间件写入），
	// 回退到 request context——中间件之前的失败只有后者可用。
	traceID := ""
	if v, ok := c.Get("social_login.trace_id"); ok {
		traceID, _ = v.(string)
	}
	if traceID == "" {
		traceID = reqmeta.TraceID(c.Request.Context())
	}

	status := e.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}

	if status >= 500 && logger != nil {
		logger.Error("请求处理失败",
			zap.String("code", string(e.Code)),
			zap.String("trace_id", traceID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.FullPath()),
			zap.Error(err))
	}

	c.AbortWithStatusJSON(status, ErrorBody{
		Code:         string(e.Code),
		Message:      e.Message,
		Retryable:    e.Retryable,
		RetryAfterMs: e.RetryAfterMs,
		TraceID:      traceID,
		Details:      e.Details,
	})
}

// FailBadRequest 是参数校验失败的快捷方式。
func FailBadRequest(c *gin.Context, logger *zap.Logger, message, field string) {
	e := errs.New(errs.CodeInvalidRequest, message)
	if field != "" {
		e.WithDetail("field", field)
	}
	Fail(c, logger, e)
}

// BindQuery 绑定查询参数，失败时已写出响应。
func BindQuery(c *gin.Context, dst any, logger *zap.Logger) bool {
	if err := c.ShouldBindQuery(dst); err != nil {
		FailBadRequest(c, logger, "请求参数不合法: "+err.Error(), "")
		return false
	}
	return true
}

// BindJSON 绑定 JSON 请求体，失败时已写出响应。
func BindJSON(c *gin.Context, dst any, logger *zap.Logger) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		FailBadRequest(c, logger, "请求体不合法: "+err.Error(), "")
		return false
	}
	return true
}
