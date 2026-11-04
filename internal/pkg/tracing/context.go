package tracing

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TraceID 返回当前 context 所属的 trace id（32 位小写十六进制）。
//
// 没有有效 span 时返回空串——调用方据此回退到自建标识
// （登录侧是 ULID，用户中心是 X-Request-Id），而不是拿到一串 0。
// "00000000000000000000000000000000" 这种值一旦进日志和审计表，
// 就会变成"看起来有 trace_id、实际什么都关联不上"的假线索。
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// SpanID 返回当前 span 的 id，用于把同一 trace 内的多行日志归到具体一步。
func SpanID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.SpanID().String()
}

// Sampled 报告当前 span 是否被采样记录。
//
// 用途：某些"代价明显但只对排障有用"的操作（例如把三方原始报文
// 附到 span 上）可以据此跳过。未采样时 SpanContext 仍然有效、trace id
// 也照样向下传，只是不落盘。
func Sampled(ctx context.Context) bool {
	return trace.SpanContextFromContext(ctx).IsSampled()
}

// Start 开一个内部 span，供后台任务（outbox 投递、对账、合并补偿）使用。
//
// 后台任务没有入站请求，如果不显式开根 span，它们内部发出的 HTTP 调用
// 会各自变成一条"只有一个 span 的 trace"——在 Jaeger 里看得到、但看不出
// 是哪一轮任务、处理的是哪条记录。开根 span 之后，同一轮任务的所有
// 出站调用自然挂在同一棵树下。
//
// 调用方必须 defer span.End()。
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(instrumentationName).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
}

// StartServer 供传输层以外的地方模拟"服务端 span"（测试与特殊接入用）。
func StartServer(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(instrumentationName).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attrs...),
	)
}

// Fail 把错误记到 span 上，并把 span 状态标成 Error。
//
// 后台任务用：它们的错误不会经过 HTTP 状态码，SDK 无从得知失败，
// 必须显式标注，否则 Jaeger 里所有任务 span 都是"成功"。
func Fail(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
