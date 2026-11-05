// Package reqmeta 承载审计与遥测所需的请求元信息。
//
// 单独成包而不是塞进每个入参结构：审计字段（trace_id / client_ip / user_agent）
// 与业务字段的变更频率和用途完全不同，混在一起会让业务入参变得嘈杂。
package reqmeta

import "context"

// TraceIDHeader 是跨服务传递追踪标识的请求/响应头。
//
// 与 W3C 的 traceparent 并存，不是替代关系：
//   - traceparent 供 OpenTelemetry 使用（采样位、span 父子关系都在里面）；
//   - X-Trace-Id 供"没有接追踪的调用方"与运维手工排查使用
//     （curl 一句就能带上，不必拼 55 个字符的 traceparent）。
//
// 两者取值在开启追踪时是同一个 trace id，见 middleware.RequestID。
const TraceIDHeader = "X-Trace-Id"

type key struct{}

// Meta 是请求元信息。
type Meta struct {
	TraceID   string
	ClientIP  string
	UserAgent string
	// Actor 是"这次调用以谁的身份发起"。
	//
	// 跨服务调用时它是调用方的服务名（由 X-Actor 声明，缺省 "service"）；
	// 本服务内部的用户请求则由中间件填 "user" 或管理员标识。
	// 它与 TraceID 的分工：TraceID 回答"这次调用串到哪了"，
	// Actor 回答"这条审计该记在谁头上"。没有 Actor 时审计只剩时间与动作，
	// 合规口径下无法回答"谁"。
	Actor string
}

// With 把元信息写入 context。
func With(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, key{}, m)
}

// From 取出元信息。
func From(ctx context.Context) Meta {
	if ctx == nil {
		return Meta{}
	}
	m, _ := ctx.Value(key{}).(Meta)
	return m
}

// TraceID 便捷取出 trace_id。
func TraceID(ctx context.Context) string { return From(ctx).TraceID }
