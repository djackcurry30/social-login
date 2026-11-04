package httpapi

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

const (
	ucSampleTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	ucSampleParent  = "00-" + ucSampleTraceID + "-00f067aa0ba902b7-01"
)

var ucHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// startUCTracing 初始化追踪（内存导出器），返回清理函数。
func startUCTracing(t *testing.T, enabled bool) {
	t.Helper()
	p, err := tracing.Init(context.Background(), tracing.Config{
		Enabled:     enabled,
		ServiceName: "usercenter-test",
		SampleRatio: 1,
		Endpoint:    "collector:4318",
		Exporter:    tracetest.NewInMemoryExporter(),
	}, nil)
	if err != nil {
		t.Fatalf("初始化追踪失败: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Shutdown(context.Background())
		otel.SetTracerProvider(oteltrace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
}

// newProbeRouter 只装"追踪 + requestID"，用于验证标识透传，不触达业务。
func newProbeRouter(t *testing.T) (*gin.Engine, *string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(tracing.GinMiddleware("usercenter-test"), requestID())
	var seen string
	r.GET("/probe", func(c *gin.Context) {
		seen = c.GetString(ctxKeyRequestID)
		c.String(http.StatusOK, "ok")
	})
	return r, &seen
}

// TestRequestIDInheritsTraceparent 是"登录中心 → 用户中心"这一跳的断言：
// 上游已经开了追踪时，本服务的 request_id 必须是同一个 trace id，
// 否则一次登录失败要在两套日志之间手工比对。
func TestRequestIDInheritsTraceparent(t *testing.T) {
	startUCTracing(t, true)
	r, seen := newProbeRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("traceparent", ucSampleParent)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get(requestIDHeader); got != ucSampleTraceID {
		t.Fatalf("响应头 X-Request-Id = %q，期望 %q", got, ucSampleTraceID)
	}
	if *seen != ucSampleTraceID {
		t.Fatalf("处理器内 request_id = %q，期望 %q", *seen, ucSampleTraceID)
	}
}

// TestRequestIDFallsBackToTraceHeader 覆盖"上游没开追踪"：
// 登录中心的 pkg/httpx 仍会带 X-Trace-Id，这一条保证退化路径可用。
func TestRequestIDFallsBackToTraceHeader(t *testing.T) {
	startUCTracing(t, false)
	r, seen := newProbeRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(traceIDHeader, "upstream-trace-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if *seen != "upstream-trace-1" {
		t.Fatalf("应沿用上游 X-Trace-Id，实际 %q", *seen)
	}
}

// TestRequestIDGeneratesWhenAbsent 覆盖"什么头都没带"：生成 ULID，
// 保证任何调用方都能被串起来。
func TestRequestIDGeneratesWhenAbsent(t *testing.T) {
	startUCTracing(t, false)
	r, seen := newProbeRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if *seen == "" {
		t.Fatal("没有上游标识时应生成 request_id")
	}
	if ucHex32.MatchString(*seen) {
		t.Fatalf("关闭追踪时不应生成 trace id 形状的标识：%q", *seen)
	}
}
