// Package middleware 提供业务端 HTTP 中间件。
//
// 管理端中间件（管理员鉴权 + RBAC、IP 白名单、高危操作审计）刻意放在
// 独立的 adminmw 包，不在这里——两套鉴权体系的信任边界完全不同，
// 混在一个包里迟早会出现"给业务端路由挂上管理端中间件"或相反的接线错误
// （架构 §15.2）。
package middleware

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
	"github.com/djackcurry30/social-login/internal/pkg/tracing"
)

// gin context 中使用的键。用常量而非字面量，避免拼写不一致造成的静默失效。
const (
	ctxKeyTraceID   = "social_login.trace_id"
	ctxKeyStartedAt = "social_login.started_at"
)

// TraceIDHeader 是追踪标识的请求/响应头名。
const TraceIDHeader = reqmeta.TraceIDHeader

// TraceID 读取当前请求的追踪标识。
func TraceID(c *gin.Context) string {
	if v, ok := c.Get(ctxKeyTraceID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// RequestID 为每个请求分配追踪标识，并写入请求 context 供审计与日志使用。
//
// 取值的优先级（顺序不能改）：
//
//  1. 当前 span 的 trace id —— 追踪开启时。这是唯一能让"日志里的 trace_id"
//     与"Jaeger 里的那一条链路"对上的取值：审计表、访问日志、响应头、
//     trace 存储四处的标识必须完全一致，否则排障时仍要在两个系统之间手工比对。
//  2. 调用方传入的 X-Trace-Id —— 追踪未开启时。跨服务调用靠它把两边日志串起来。
//  3. 自建 ULID —— 前两者都没有。
//
// 注意顺序带来一个副作用（正面的）：追踪开启后，日志与审计里的 trace_id
// 不再是客户端可以任意指定的字符串，而是由本服务（或上游 span）生成的
// 32 位十六进制。这堵掉了"客户端塞一段伪造文本进审计表"的路径。
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceID := tracing.TraceID(c.Request.Context())
		if traceID == "" {
			traceID = c.GetHeader(TraceIDHeader)
		}
		if traceID == "" {
			traceID = ids.New(ids.PrefixTrace)
		}
		c.Set(ctxKeyTraceID, traceID)
		c.Set(ctxKeyStartedAt, time.Now())
		c.Writer.Header().Set(TraceIDHeader, traceID)

		// 把请求元信息放进 context，供应用层写审计时不依赖 gin。
		ctx := reqmeta.With(c.Request.Context(), reqmeta.Meta{
			TraceID:   traceID,
			ClientIP:  clientIP(c),
			UserAgent: c.Request.UserAgent(),
		})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// Recovery 捕获 panic 并输出统一的 500。
//
// 这里有一个必须保留的行为：持久化层的 app_id 隔离回调会【故意 panic】
// （架构 §9.1，让隔离漏洞在开发阶段暴露）。本中间件把它转成 500 而不是让进程
// 退出——生产环境宁可单请求失败，也不要整个实例挂掉；但日志级别是 Error，
// 且带完整堆栈，保证不会被忽略。
func Recovery(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				traceID := TraceID(c)
				if logger != nil {
					logger.Error("请求处理发生 panic",
						zap.Any("panic", r),
						zap.String("trace_id", traceID),
						zap.String("method", c.Request.Method),
						zap.String("path", c.FullPath()),
						zap.ByteString("stack", debug.Stack()))
				}
				c.AbortWithStatusJSON(500, gin.H{
					"code":      "INTERNAL.ERROR",
					"message":   "服务内部错误",
					"retryable": false,
					"trace_id":  traceID,
				})
			}
		}()
		c.Next()
	}
}

// AccessLog 记录访问日志。
func AccessLog(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if logger == nil {
			return
		}
		started, _ := c.Get(ctxKeyStartedAt)
		dur := time.Duration(0)
		if t, ok := started.(time.Time); ok {
			dur = time.Since(t)
		}
		logger.Info("http_request",
			zap.String("trace_id", TraceID(c)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.FullPath()),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", dur),
			zap.String("client_ip", clientIP(c)),
		)
	}
}

// Timeout 给请求 context 加 deadline（§5.7 的第二段超时）。
//
// ⚠️ 它本身不会"中断"处理器——Go 没有办法强行终止一个 goroutine。
// 它的作用是让 deadline 通过 context 传到下游（数据库、三方 HTTP 调用），
// 由下游真正取消；下游返回 context.DeadlineExceeded 后由统一错误映射输出 504。
//
// 这也解释了为什么"返回 504 但 goroutine 还在跑"是必须避免的反模式：
// 那样只是把超时从用户视角藏了起来，资源仍然被占着。
func Timeout(d time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if d <= 0 {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), d)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// clientIP 取出客户端 IP。
//
// 刻意【不】信任 X-Forwarded-For：它可被客户端伪造，直接采信会让基于 IP 的
// 限流与风控形同虚设。真实部署中应由入口网关覆写该头，并在网关层做信任判定；
// 届时这里改为读取网关注入的可信头。
func clientIP(c *gin.Context) string {
	return c.ClientIP()
}
