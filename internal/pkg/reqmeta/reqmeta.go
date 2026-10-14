// Package reqmeta 承载审计与遥测所需的请求元信息。
//
// 单独成包而不是塞进每个入参结构：审计字段（trace_id / client_ip / user_agent）
// 与业务字段的变更频率和用途完全不同，混在一起会让业务入参变得嘈杂。
package reqmeta

import "context"

type key struct{}

// Meta 是请求元信息。
type Meta struct {
	TraceID   string
	ClientIP  string
	UserAgent string
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
