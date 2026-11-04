package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/djackcurry30/social-login/internal/pkg/tracing"
)

// 固定的 W3C traceparent（来自规范示例），方便逐字节断言。
const (
	sampleTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	sampleSpanID  = "00f067aa0ba902b7"
	sampleParent  = "00-" + sampleTraceID + "-" + sampleSpanID + "-01"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// startTracing 按给定配置初始化追踪，返回刷盘函数。
func startTracing(t *testing.T, enabled bool) (*tracetest.InMemoryExporter, func()) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	p, err := tracing.Init(context.Background(), tracing.Config{
		Enabled:     enabled,
		ServiceName: "middleware-test",
		SampleRatio: 1,
		Endpoint:    "collector:4318",
		Exporter:    exp,
	}, nil)
	if err != nil {
		t.Fatalf("初始化追踪失败: %v", err)
	}
	flush := func() {
		if err := p.Flush(context.Background()); err != nil {
			t.Fatalf("刷盘失败: %v", err)
		}
	}
	t.Cleanup(func() {
		_ = p.Shutdown(context.Background())
		otel.SetTracerProvider(oteltrace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
	return exp, flush
}

// buildRouter 复刻生产的路由中间件顺序（Tracing 最外层，其次 RequestID）。
func buildRouter() (*gin.Engine, *string) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(tracing.GinMiddleware("middleware-test"), RequestID())
	var seen string
	r.GET("/probe", func(c *gin.Context) {
		seen = TraceID(c)
		c.String(http.StatusOK, "ok")
	})
	return r, &seen
}

func do(r *gin.Engine, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestRequestIDFollowsIncomingTraceparent 是本次接入最关键的一条：
// 上游已经开了链路时，本服务的 trace_id 必须等于上游的 trace id，
// 否则日志、审计表与 Jaeger 三者对不上，等于没接。
func TestRequestIDFollowsIncomingTraceparent(t *testing.T) {
	_, flush := startTracing(t, true)
	r, seen := buildRouter()

	w := do(r, map[string]string{"traceparent": sampleParent})
	if got := w.Header().Get(TraceIDHeader); got != sampleTraceID {
		t.Fatalf("响应头 X-Trace-Id = %q，期望上游 trace id %q", got, sampleTraceID)
	}
	if *seen != sampleTraceID {
		t.Fatalf("处理器内读到的 trace_id = %q，期望 %q", *seen, sampleTraceID)
	}

	flush()
}

// TestRequestIDUsesSpanWhenNoUpstream 覆盖"没有上游 traceparent"的情况：
// trace_id 必须取自本请求的 span，而不是客户端随便塞的 X-Trace-Id。
//
// 这条同时是一个安全性改善：追踪开启后，客户端无法再把任意文本写进
// 审计表的 trace_id 字段。
func TestRequestIDUsesSpanWhenNoUpstream(t *testing.T) {
	_, flush := startTracing(t, true)
	r, seen := buildRouter()

	w := do(r, map[string]string{TraceIDHeader: "client-supplied-garbage"})
	got := w.Header().Get(TraceIDHeader)
	if !hex32.MatchString(got) {
		t.Fatalf("开启追踪后 X-Trace-Id 应是 32 位十六进制 trace id，实际 %q", got)
	}
	if got == "client-supplied-garbage" {
		t.Fatal("不应沿用客户端伪造的 X-Trace-Id")
	}
	if *seen != got {
		t.Fatalf("处理器与响应头的 trace_id 不一致：%q vs %q", *seen, got)
	}

	flush()
}

// TestRequestIDKeepsLegacyFallbackWhenTracingDisabled 守住关闭态的兼容性：
// 没有 span 时仍按老规则走（透传 X-Trace-Id，没有就生成 ULID）。
// 这条保证"关掉追踪不会改变任何既有行为"。
func TestRequestIDKeepsLegacyFallbackWhenTracingDisabled(t *testing.T) {
	startTracing(t, false)
	r, seen := buildRouter()

	w := do(r, map[string]string{TraceIDHeader: "legacy-id-123"})
	if got := w.Header().Get(TraceIDHeader); got != "legacy-id-123" {
		t.Fatalf("关闭追踪时应透传 X-Trace-Id，实际 %q", got)
	}
	if *seen != "legacy-id-123" {
		t.Fatalf("处理器内读到的 trace_id = %q", *seen)
	}

	// 没有任何入参时回落到自建 ULID（长度 26、带前缀），保持与历史一致。
	w = do(r, nil)
	if got := w.Header().Get(TraceIDHeader); got == "" || got == "legacy-id-123" {
		t.Fatalf("应生成新的 trace id，实际 %q", got)
	}
}

// TestTracingDisabledProducesNoSpans 确认关闭态真的不产生 span（不是"产生了不发"）。
func TestTracingDisabledProducesNoSpans(t *testing.T) {
	exp, _ := startTracing(t, false)
	r, _ := buildRouter()
	do(r, nil)
	if n := len(exp.GetSpans()); n != 0 {
		t.Fatalf("关闭追踪时不应产生 span，实际 %d 条", n)
	}
}
