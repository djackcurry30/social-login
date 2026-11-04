package tracing

import (
	"fmt"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Transport 用追踪用的 RoundTripper 包装底层 transport。
//
// 未开启追踪时原样返回 base（不额外分配），开启后每次出站调用产生一个
// client span，并把 W3C traceparent 注入请求头——这是下游服务能与本次
// 请求续成同一条 trace 的唯一依据。
//
// ⚠️ 为什么不用 otelhttp.NewTransport：
//
//	otelhttp 会给每个 client span 写 url.full，也就是把完整 URL（含 query）
//	落进 trace 存储。本服务的查询串里带手机号——
//	  GET /v1/apps/{app}/accounts/by-claim?type=phone&value=13800000000
//	日志侧为此专门做了 MaskURL，如果 trace 侧原样记录，那脱敏就只是
//	"换个地方泄漏"。这里只写 url.path 与 server.address，不写 query。
//
// 另一个差异是可预期性：本实现不给请求加 resend_count、不处理重定向
// （httpx 本来就禁止跟随重定向，见 pkg/httpx 的 CheckRedirect），
// span 上的字段就是读代码能数出来的那几个。
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if !globalEnabled.Load() {
		return base
	}
	return &transport{base: base}
}

type transport struct {
	base http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return t.base.RoundTrip(req)
	}

	// span 名取 "方法 主机 路径"。不把 query 拼进去：一是脱敏，
	// 二是 span 名在 Jaeger 里会被当成聚合维度，带参数的名称会把
	// 同一个接口拆成上万条。
	spanName := req.Method + " " + req.URL.Host + req.URL.Path
	ctx, span := otel.Tracer(instrumentationName).Start(req.Context(), spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(clientAttrs(req)...),
	)
	defer span.End()

	// 注入 traceparent。注意这一步在 base.RoundTrip 之前：
	// 请求一旦发出就没机会补头了。
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		// 传输层错误（连接失败/超时/取消）。上层 httpx 会把它翻译成
		// PROVIDER.* 业务错误码，这里只负责让 trace 上看出"这步失败了"。
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return resp, err
	}
	if resp == nil {
		return nil, fmt.Errorf("transport 返回了空响应")
	}

	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	// 只有 5xx 记为 span 错误：4xx 是"对方拒绝了这个请求"，
	// 属于正常业务分支（凭证失效、参数不合法），标成错误会让
	// 错误率指标失去意义。
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, resp.Status)
	}
	return resp, nil
}

// clientAttrs 组装 client span 的属性。
//
// 刻意不写 url.full / url.query —— 理由见 Transport 的注释。
func clientAttrs(req *http.Request) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("http.request.method", req.Method),
		attribute.String("url.path", req.URL.Path),
		attribute.String("server.address", req.URL.Hostname()),
	}
	if scheme := req.URL.Scheme; scheme != "" {
		attrs = append(attrs, attribute.String("url.scheme", scheme))
	}
	if port := req.URL.Port(); port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			attrs = append(attrs, attribute.Int("server.port", n))
		}
	}
	return attrs
}
