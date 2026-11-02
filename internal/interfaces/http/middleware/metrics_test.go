package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/pkg/metrics"
)

func init() { gin.SetMode(gin.TestMode) }

// 标签基数控制是这套指标的生命线：不同 id 必须合并到同一个 route 模板，
// 否则几百个应用就能把 Prometheus 打爆。
func TestMetricsUsesRouteTemplateNotRawPath(t *testing.T) {
	reg := metrics.NewRegistry()
	r := gin.New()
	r.Use(Metrics(reg))
	r.GET("/apps/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, id := range []string{"1", "2", "3"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/"+id, nil))
	}

	var b strings.Builder
	_, _ = reg.WriteTo(&b)
	out := b.String()

	if !strings.Contains(out, `route="/apps/:id"`) {
		t.Fatalf("应使用路由模板作为标签:\n%s", out)
	}
	// 一条序列、计数 3 —— 如果按原始路径记，这里会出现三条。
	if !strings.Contains(out, `social_login_http_requests_total{method="GET",route="/apps/:id",status="200"} 3`) {
		t.Fatalf("同一路由模板应合并为一条序列:\n%s", out)
	}
}

// 未命中路由（404）必须归到固定标签，否则扫描器的随机路径会无限建序列。
func TestMetricsCollapsesUnmatchedPaths(t *testing.T) {
	reg := metrics.NewRegistry()
	r := gin.New()
	r.Use(Metrics(reg))

	for _, p := range []string{"/nope-1", "/nope-2", "/admin/.env"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
	}

	var b strings.Builder
	_, _ = reg.WriteTo(&b)
	out := b.String()

	if !strings.Contains(out, `route="unmatched"`) {
		t.Fatalf("未命中路由应归为 unmatched:\n%s", out)
	}
	if strings.Contains(out, "nope-1") {
		t.Fatalf("不得把原始路径写进标签:\n%s", out)
	}
}

// panic 请求必须被记成 500，而不是 200。
// 这依赖 Metrics 挂在 Recovery 外层——本测试就是那个顺序的回归。
func TestMetricsRecordsPanicAsServerError(t *testing.T) {
	reg := metrics.NewRegistry()
	r := gin.New()

	chain := []gin.HandlerFunc{Metrics(reg)}
	chain = append(chain, Recovery(nil))
	r.Use(chain...)

	r.GET("/boom", func(c *gin.Context) { panic("boom") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))

	var b strings.Builder
	_, _ = reg.WriteTo(&b)
	out := b.String()

	if !strings.Contains(out, `status="500"`) {
		t.Fatalf("panic 请求应记成 500:\n%s", out)
	}
}

// 耗时指标必须有 sum 与 count 两条，且 count 与请求数一致。
func TestMetricsRecordsDuration(t *testing.T) {
	reg := metrics.NewRegistry()
	r := gin.New()
	r.Use(Metrics(reg))
	r.GET("/t", func(c *gin.Context) { c.Status(http.StatusOK) })

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/t", nil))
	}

	var b strings.Builder
	_, _ = reg.WriteTo(&b)
	out := b.String()

	if !strings.Contains(out, `social_login_http_request_duration_seconds_count{method="GET",route="/t"} 2`) {
		t.Fatalf("耗时 count 不符:\n%s", out)
	}
	if !strings.Contains(out, `social_login_http_request_duration_seconds_sum{method="GET",route="/t"}`) {
		t.Fatalf("耗时 sum 缺失:\n%s", out)
	}
}
