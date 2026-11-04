package httpapi

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/pkg/tracing"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/observe"
)

// 上下文键。
const (
	ctxKeyApp       = "uc.app"
	ctxKeyRequestID = "uc.request_id"
)

// requestID 为每个请求分配标识，并回写响应头。
//
// 取值优先级（顺序不能改）：
//
//  1. 当前 span 的 trace id —— 追踪开启时。这样本服务的日志、响应头
//     与 Jaeger 里的那条链路是同一个标识。
//  2. 上游的 X-Trace-Id —— 登录中心即使没开追踪也会带（pkg/httpx 注入）。
//  3. 上游的 X-Request-Id —— 历史调用方的习惯头，保留兼容。
//  4. 自建 ULID —— 前面都没有。
//
// 顺序的意义：一旦追踪可用，就用"跨服务、跨系统都认"的那个 id；退化路径
// 保证任何调用方都能被串起来，不会因为对方没接追踪就丢掉关联能力。
func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := tracing.TraceID(c.Request.Context())
		if id == "" {
			id = trimParam(c.GetHeader(traceIDHeader))
		}
		if id == "" {
			id = trimParam(c.GetHeader(requestIDHeader))
		}
		if id == "" {
			id = ids.ULID()
		}
		c.Set(ctxKeyRequestID, id)
		c.Header(requestIDHeader, id)
		c.Next()
	}
}

// recoverPanic 把 panic 变成 500 JSON，而不是 gin 默认的纯文本。
//
// 用自定义的而不是 gin.Recovery()：后者直接写 500 且格式与契约不符，
// 消费方会把它当成"对端返回了非预期响应"，而真相是我们的 bug。
func recoverPanic(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("请求处理 panic",
					zap.Any("panic", r),
					zap.String("path", c.Request.URL.Path),
					zap.String("request_id", c.GetString(ctxKeyRequestID)))
				fail(c, logger, domain.New(domain.CodeInternal, "内部错误"))
			}
		}()
		c.Next()
	}
}

// accessLog 记录每个请求。
//
// 只记路由模板（c.FullPath()）而不是原始路径：原始路径里含 user_id 与
// 凭证反查的值，手机号明文进日志是不能接受的（§8 安全）。
func accessLog(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("route", route),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("took", time.Since(start)),
			zap.String("request_id", c.GetString(ctxKeyRequestID)),
		}
		// app_key 是排障的第一维度（"是某个应用挂了还是全挂"），单独提出来。
		if key := c.Param("app_key"); key != "" {
			fields = append(fields, zap.String("app_key", key))
		}
		if len(c.Errors) > 0 {
			fields = append(fields, zap.String("errors", c.Errors.String()))
		}
		logger.Info("http", fields...)
	}
}

// measure 记录请求数与耗时。
func measure(m *observe.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		if m == nil {
			return
		}
		route := c.FullPath()
		if route == "" {
			// 未匹配的路径不做标签：那是任意字符串（扫描器会打出成千上万个），
			// 直接当标签会让指标基数爆炸。
			route = "unmatched"
		}
		m.Requests.Inc(c.Request.Method, route, statusClass(c.Writer.Status()))
		m.DurationMS.Add(float64(time.Since(start).Milliseconds()), route)
	}
}

// statusClass 把状态码压成 2xx/4xx/5xx。
//
// 用类别而不是精确码：契约里 409 有三个含义，但"有多少 4xx"才是运维要看的东西；
// 精确分布可以从访问日志里取，不必让指标承担。
func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// requireToken 校验服务间 Bearer token。
//
// 用 ConstantTimeCompare：普通字符串比较会在第一个不同的字节就返回，
// 攻击者可以用响应时间逐字节猜出 token。内网也不是绝对安全的地方。
//
// token 为空时直接拒绝启动（由配置校验保证），这里再兜一层：
// 若真为空，宁可全部 401 也不要变成"无鉴权开放"。
func requireToken(token string) gin.HandlerFunc {
	expected := []byte(token)
	return func(c *gin.Context) {
		got := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if len(got) <= len(prefix) || got[:len(prefix)] != prefix {
			fail(c, nil, domain.New(domain.CodeUnauthorized, "缺少 Bearer 凭证"))
			return
		}
		actual := []byte(got[len(prefix):])
		if len(expected) == 0 ||
			subtle.ConstantTimeCompare(expected, actual) != 1 {
			fail(c, nil, domain.New(domain.CodeUnauthorized, "服务间 token 无效"))
			return
		}
		c.Next()
	}
}

// maxBody 限制请求体大小，防止单个请求分配大量内存。
func maxBody(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limit > 0 && c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}
