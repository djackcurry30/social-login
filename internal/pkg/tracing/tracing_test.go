package tracing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// newTestProvider 用内存导出器初始化追踪，返回导出器与清理函数。
//
// 用注入的 Exporter 而不是真起一个 collector：单测要验证的是"span 之间的
// 父子关系与属性"，不是网络。collector 是否收得到属于部署验证（见 docs）。
func newTestProvider(t *testing.T, sampleRatio float64) (*Provider, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	p, err := Init(context.Background(), Config{
		Enabled:     true,
		ServiceName: "unit-test",
		SampleRatio: sampleRatio,
		Exporter:    exp,
	}, nil)
	if err != nil {
		t.Fatalf("初始化追踪失败: %v", err)
	}
	t.Cleanup(func() {
		// 刷盘顺带把全局状态收回：同一包内多个用例共享 otel 的全局变量，
		// 不清会让"关闭追踪"的用例拿到上一个用例的 provider。
		_ = p.Shutdown(context.Background())
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
	return p, exp
}

func TestInitDisabledIsNoop(t *testing.T) {
	p, err := Init(context.Background(), Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("关闭状态不应报错: %v", err)
	}
	if Enabled() {
		t.Fatal("关闭状态却报告已启用")
	}
	if got := TraceID(context.Background()); got != "" {
		t.Fatalf("没有 span 时应返回空 trace id，实际 %q", got)
	}
	// Transport 必须原样返回底层实现：关闭追踪时不该多一层函数调用与分配。
	base := &http.Transport{}
	if got := Transport(base); got != http.RoundTripper(base) {
		t.Fatal("关闭追踪时 Transport 不应包装底层实现")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("空壳 Provider 的 Shutdown 应是无操作: %v", err)
	}
}

func TestInitRequiresEndpoint(t *testing.T) {
	_, err := Init(context.Background(), Config{Enabled: true, ServiceName: "x"}, nil)
	if err == nil {
		t.Fatal("开启追踪但未给 endpoint 时必须报错（否则只是静默不发数据）")
	}
}

func TestEndpointNormalization(t *testing.T) {
	cases := map[string]string{
		"http://otel-collector:4318": "otel-collector:4318",
		"https://collector.example/": "collector.example",
		"otel-collector:4318":        "otel-collector:4318",
		"  http://127.0.0.1:4318/  ": "127.0.0.1:4318",
		"http://collector:4318/otlp": "collector:4318/otlp",
	}
	for in, want := range cases {
		cfg := Config{Endpoint: in}.withDefaults()
		if got := cfg.endpoint(); got != want {
			t.Errorf("endpoint(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.ServiceName != DefaultServiceName {
		t.Errorf("ServiceName 默认值 = %q", cfg.ServiceName)
	}
	if cfg.ExportTimeout != DefaultExportTimeout || cfg.BatchTimeout != DefaultBatchTimeout {
		t.Error("导出超时默认值不对")
	}
	if cfg.SampleRatio != DefaultSampleRatio {
		t.Errorf("SampleRatio 默认值 = %v，期望 %v", cfg.SampleRatio, DefaultSampleRatio)
	}
	// 超过 1 的采样率要被夹到 1，而不是原样传给 SDK（SDK 会静默当成 1，
	// 但配置里留个 3.0 会让人以为"采了三次"）。
	if got := (Config{SampleRatio: 3}).withDefaults().SampleRatio; got != 1 {
		t.Errorf("SampleRatio 未夹紧: %v", got)
	}
}

// TestPropagationAcrossServices 是这套接入的核心断言：
//
//	A（有 span）→ HTTP → B（otelgin）之后，B 侧的 span 必须是 A 侧 span 的子节点，
//	且两边 trace id 相同。这正是"一次登录横跨用户中心 → 本服务 → 渠道"
//	能在 Jaeger 里连成一棵树的前提。
func TestPropagationAcrossServices(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p, exp := newTestProvider(t, 1)

	var seenByB string
	b := gin.New()
	b.Use(GinMiddleware("service-b"))
	b.GET("/inner", func(c *gin.Context) {
		seenByB = TraceID(c.Request.Context())
		c.String(http.StatusOK, "ok")
	})
	serverB := httptest.NewServer(b)
	defer serverB.Close()

	client := &http.Client{Transport: Transport(http.DefaultTransport), Timeout: 5 * time.Second}

	ctx, parent := Start(context.Background(), "call-b")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverB.URL+"/inner", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("调用 B 失败: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	parent.End()

	if seenByB == "" {
		t.Fatal("B 侧没有拿到 trace id：traceparent 没注入成功")
	}
	if want := TraceID(ctx); seenByB != want {
		t.Fatalf("跨服务 trace id 不一致：B=%s A=%s", seenByB, want)
	}
	parent.End()

	// 刷盘后才能断言父子关系（批量导出器是异步的）。
	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	var clientSpanID string
	var serverParent, serverTrace string
	for _, s := range exp.GetSpans() {
		switch s.SpanKind {
		case trace.SpanKindClient:
			clientSpanID = s.SpanContext.SpanID().String()
		case trace.SpanKindServer:
			serverParent = s.Parent.SpanID().String()
			serverTrace = s.SpanContext.TraceID().String()
		}
	}
	if clientSpanID == "" || serverParent == "" {
		t.Fatalf("span 缺失：client=%q server.parent=%q", clientSpanID, serverParent)
	}
	if serverParent != clientSpanID {
		t.Errorf("B 的 server span 应挂在 A 的 client span 下：server.parent=%s client=%s",
			serverParent, clientSpanID)
	}
	if serverTrace != seenByB {
		t.Errorf("server span 的 trace id 与 B 侧读到的 trace_id 不一致：%s vs %s",
			serverTrace, seenByB)
	}
}

// TestSpanParentChild 用内存导出器断言父子关系与属性，独立于 HTTP 层。
func TestSpanParentChild(t *testing.T) {
	p, exp := newTestProvider(t, 1)

	ctx, parent := Start(context.Background(), "parent")
	_, child := Start(ctx, "child")
	child.End()
	parent.End()

	// 必须刷盘：WithBatcher 在后台攒批，不刷就看不到 span。
	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}

	var parentID, childParentID string
	var childTraceID, parentTraceID string
	for _, s := range exp.GetSpans() {
		switch s.Name {
		case "parent":
			parentID = s.SpanContext.SpanID().String()
			parentTraceID = s.SpanContext.TraceID().String()
		case "child":
			childParentID = s.Parent.SpanID().String()
			childTraceID = s.SpanContext.TraceID().String()
		}
	}
	if parentID == "" || childParentID == "" {
		t.Fatalf("span 未导出：parent=%q childParent=%q", parentID, childParentID)
	}
	if childParentID != parentID {
		t.Errorf("child 的父 span 应为 parent：child.parent=%s parent=%s", childParentID, parentID)
	}
	if childTraceID != parentTraceID {
		t.Errorf("同一棵树里的 trace id 必须相同：%s vs %s", childTraceID, parentTraceID)
	}
}

// TestTransportDoesNotLeakQuery 守住脱敏红线。
//
// 本服务的查询串里带手机号（by-claim?type=phone&value=138...）。
// 日志侧为此做了 MaskURL，trace 侧同样不能把 query 写进 span，
// 否则等于换一个系统继续泄漏。
func TestTransportDoesNotLeakQuery(t *testing.T) {
	p, exp := newTestProvider(t, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: Transport(http.DefaultTransport), Timeout: 5 * time.Second}
	const phone = "13800000000"
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/apps/demo/accounts/by-claim?type=phone&value="+phone, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	_ = resp.Body.Close()

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("client span 未导出")
	}
	for _, kv := range spans[0].Attributes {
		if strings.Contains(kv.Value.Emit(), phone) {
			t.Fatalf("span 属性 %s 里出现了手机号：%s", kv.Key, kv.Value.Emit())
		}
		if kv.Key == "url.full" || kv.Key == "url.query" {
			t.Fatalf("不应写 %s（含查询串，可能带手机号）", kv.Key)
		}
	}
}

// TestGinMiddlewareSkipsProbes 确认探针与抓取端点不产生 span。
//
// 不做的后果很具体：K8s 每 5s 探一次 /healthz、Prometheus 每 15s 抓一次
// /metrics，两者加起来能吃掉全部采样额度，而真正的业务链路反而采不到。
func TestGinMiddlewareSkipsProbes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p, exp := newTestProvider(t, 1)

	r := gin.New()
	r.Use(GinMiddleware("probe-test"))
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/metrics", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/v1/userinfo", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	for _, path := range []string{"/healthz", "/metrics", "/v1/userinfo"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}

	var names []string
	for _, s := range exp.GetSpans() {
		names = append(names, s.Name)
	}
	if len(names) != 1 || names[0] != "GET /v1/userinfo" {
		t.Fatalf("应只记录业务请求的 span，实际 %v", names)
	}
}
