package tracing

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

// 不追踪的路径。
//
// 探针与抓取端点是"机器每几秒问一次"的流量：K8s 的 /healthz、/readyz
// 加 Prometheus 的 /metrics，一天能产生几十万条完全相同的 span。
// 它们会把 1% 的采样额度吃掉大半，让真正需要看的业务链路采不到——
// 这是"trace 开着但查不到问题"的常见成因，比不采更误导。
var untracedPaths = map[string]struct{}{
	"/healthz": {},
	"/readyz":  {},
	"/metrics": {},
}

// GinMiddleware 返回入站追踪中间件，必须是【第一个】挂载的中间件。
//
// 为什么必须最外层：
//   - span 要覆盖后续所有中间件（含 Recovery），否则 panic 的那个请求
//     在 trace 里没有耗时，故障现场直接丢失；
//   - 内层中间件（鉴权、限流）产生的属性才能挂到同一个 span 上。
//
// 关闭追踪时返回一个空处理器而不是 nil：调用点不必到处写 if，
// 也不会因为漏判而 panic（gin 对 nil handler 会直接崩）。
func GinMiddleware(serviceName string) gin.HandlerFunc {
	if !globalEnabled.Load() {
		return func(c *gin.Context) { c.Next() }
	}
	return otelgin.Middleware(serviceName, otelgin.WithFilter(traceable))
}

// traceable 过滤掉探针与抓取端点。
func traceable(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	_, skip := untracedPaths[r.URL.Path]
	return !skip
}
