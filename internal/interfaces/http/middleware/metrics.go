// metrics.go 是 HTTP 层指标采集中间件。
//
// 只做两件事：请求计数与耗时总量。业务指标（登录结果、积压、漂移数）
// 由各自的用例层注册，不在这里猜。
//
// 两条必须守住的规则：
//
//  1. 【标签基数】route 标签取 gin 的路由模板（c.FullPath()），不是原始路径。
//     用原始路径会让 /admin/v1/apps/1、/apps/2 … 每个 id 变成一条时间序列，
//     几百个应用就能把 Prometheus 打爆——这是"指标比业务先挂"的典型原因。
//  2. 【不 panic 也不阻塞】中间件里任何异常都不能影响业务请求。指标采集是
//     旁路，宁可少一条数据，不能多一次失败。
package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/pkg/metrics"
)

// 指标名。
const (
	metricHTTPRequests = "social_login_http_requests_total"
	metricHTTPDurSum   = "social_login_http_request_duration_seconds_sum"
	metricHTTPDurCount = "social_login_http_request_duration_seconds_count"
)

// Metrics 采集中 HTTP 请求数与耗时。
//
// 注册位置在 Recovery 之外层：这样 panic 被 Recovery 转成 500 之后，
// 本中间件仍能读到最终状态码。如果放在内层，panic 请求会被记成 200。
func Metrics(reg *metrics.Registry) gin.HandlerFunc {
	reqs := reg.Counter(metricHTTPRequests,
		"HTTP 请求数（按方法、路由模板、状态码）", "method", "route", "status")
	durSum := reg.Counter(metricHTTPDurSum,
		"HTTP 请求耗时总和（秒），配合 _count 求平均", "method", "route")
	durCount := reg.Counter(metricHTTPDurCount,
		"HTTP 请求次数，用于计算平均耗时", "method", "route")

	return func(c *gin.Context) {
		started := time.Now()

		defer func() {
			// 即使 c.Next() 里 panic（被外层 Recovery 捕获），这个 defer 仍会执行。
			route := c.FullPath()
			if route == "" {
				// 未命中任何路由（404）。用固定值而不是原始路径：
				// 扫描器会构造大量随机路径，那些都是同一类"未命中"。
				route = "unmatched"
			}
			method := c.Request.Method
			status := strconv.Itoa(c.Writer.Status())

			reqs.Inc(method, route, status)
			durCount.Inc(method, route)
			durSum.Add(time.Since(started).Seconds(), method, route)
		}()

		c.Next()
	}
}
