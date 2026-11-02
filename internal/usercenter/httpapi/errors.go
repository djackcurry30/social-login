// Package httpapi 是用户中心的 HTTP 接入层：路由、鉴权、错误信封。
//
// 报文格式是【对外契约】，不是实现细节。改动前先看
// docs/user-center-integration.md 与 social-login 的
// internal/infrastructure/account/http.go 文件头——那边是消费方，
// 它按这些字面量做解析与错误翻译。
package httpapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// ErrorBody 是统一错误信封（契约 v1.1）。
//
// 只有三个字段，刻意不多：
//   - code      机器可读，消费方优先按它翻译
//   - message   人可读，只用于日志与排障
//   - retryable 调用方是否可以原样重试
//
// 不带 trace_id / details：跨服务的排障信息应该进日志，而不是塞进响应体
// 让每个调用方都去解析一遍。status 由 HTTP 状态码表达，不重复。
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// requestIDHeader 是请求标识头。有则透传（便于跨服务串联），无则新生成。
const requestIDHeader = "X-Request-Id"

// fail 把错误写成契约信封。
func fail(c *gin.Context, logger *zap.Logger, err error) {
	e, ok := domain.As(err)
	if !ok {
		// 未包装的错误说明是编程疏漏（比如忘了个 if err != nil）。
		// 对外一律 500，但日志里必须能看出原始错误。
		if logger != nil {
			logger.Error("未包装的内部错误",
				zap.String("route", c.FullPath()),
				zap.Error(err))
		}
		e = domain.New(domain.CodeInternal, "内部错误")
		err = e
	}

	status := e.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}

	// 5xx 与鉴权失败都值得记 warn/error：前者是故障，后者是配置或攻击信号。
	if logger != nil && (status >= 500 || status == http.StatusUnauthorized) {
		logger.Warn("请求失败",
			zap.String("code", string(e.Code)),
			zap.Int("status", status),
			zap.String("route", c.FullPath()),
			zap.Error(err))
	}

	c.AbortWithStatusJSON(status, ErrorBody{
		Code:      string(e.Code),
		Message:   e.Message,
		Retryable: e.Retryable,
	})
}

// failBadRequest 是参数错误的快捷方式。
func failBadRequest(c *gin.Context, logger *zap.Logger, msg string) {
	fail(c, logger, domain.New(domain.CodeInvalid, msg))
}

// bindJSON 解析请求体。
//
// 用 ShouldBindJSON 而不是 BindJSON：后者会自动写 400 并 Abort，
// 那样我们就没法套上统一的错误信封，消费方只能按状态码猜原因。
func bindJSON(c *gin.Context, logger *zap.Logger, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		// 不把 encoding/json 的原文透出去（它含结构体字段名），但保留一句人话。
		failBadRequest(c, logger, "请求体不是合法的 JSON 或字段类型不符")
		return false
	}
	return true
}

// appFromContext 取出中间件解析好的应用。
func appFromContext(c *gin.Context) (domain.App, bool) {
	v, ok := c.Get(ctxKeyApp)
	if !ok {
		return domain.App{}, false
	}
	app, ok := v.(domain.App)
	return app, ok
}

// trimParam 去掉路径/查询参数两端空白。
//
// URL 里出现首尾空格几乎总是复制粘贴带来的，直接当成"值的一部分"去查，
// 会得到"账号不存在"，而真正原因是那个空格——排障成本远高于这里 trim 的成本。
func trimParam(s string) string { return strings.TrimSpace(s) }
