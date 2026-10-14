// Package appctx 承载"当前请求属于哪个业务应用"这一上下文。
//
// 为什么单独抽成 pkg 而不是放在持久化层：应用层需要在调用仓储【之前】建立作用域，
// 若把 WithAppScope 定义在 postgres 包，应用层就要反向依赖基础设施层，破坏分层
// （架构 §3 的依赖方向是 接入层 → 应用层 → 领域层）。
//
// 这个上下文是约束 C1（账号按业务应用隔离）的强制执行手段：持久化层用它的存在
// 与否决定"是否 panic"（架构 §9.1）。
package appctx

import "context"

type scopeKey struct{}

// Scope 描述本次数据访问的应用作用域。
type Scope struct {
	// AppID 是业务应用主键。0 表示未设置。
	AppID int64
	// CrossApp 为 true 表示显式声明的跨应用访问，仅管理端可用。
	//
	// 之所以要显式声明而不是"没设置就放行"：默认放行意味着任何一处忘记设置
	// 作用域的代码都会静默地读到全部应用的数据，这正是要防的串号。
	// 显式声明则让每一处跨应用访问在代码里可见、可审计。
	CrossApp bool
}

// WithAppScope 把作用域写入 context，供业务端链路使用。
func WithAppScope(ctx context.Context, appID int64) context.Context {
	return context.WithValue(ctx, scopeKey{}, Scope{AppID: appID})
}

// WithCrossAppScope 显式声明跨应用访问（管理端）。
func WithCrossAppScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopeKey{}, Scope{CrossApp: true})
}

// From 取出作用域。
func From(ctx context.Context) (Scope, bool) {
	if ctx == nil {
		return Scope{}, false
	}
	s, ok := ctx.Value(scopeKey{}).(Scope)
	if !ok {
		return Scope{}, false
	}
	if !s.CrossApp && s.AppID <= 0 {
		return Scope{}, false
	}
	return s, true
}

// AppID 取出当前应用 ID；跨应用访问或未设置时返回 ok=false。
func AppID(ctx context.Context) (int64, bool) {
	s, ok := From(ctx)
	if !ok || s.CrossApp {
		return 0, false
	}
	return s.AppID, true
}
