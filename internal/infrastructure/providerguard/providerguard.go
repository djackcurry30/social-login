// Package providerguard 把渠道适配器包上熔断器（架构 §5.6）。
//
// 为什么做成装饰器而不是在每个适配器里调用熔断：
// 适配器的职责是"翻译三方协议"，让它关心进程级的资源保护会把两件事耦死，
// 而且新增渠道时容易漏。装饰器保证"所有渠道、所有出站调用"都被同一套规则覆盖。
//
// 不包 AuthURL：它只做字符串拼接，不发网络请求。把纯计算包进熔断没有意义，
// 反而会在熔断打开时让用户连"点授权按钮"都失败——那时候还没有真正调用平台。
package providerguard

import (
	"context"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/guards/breaker"
)

// Wrap 给渠道实现套上熔断保护。guard 为 nil 或未启用时原样返回。
func Wrap(p provider.Provider, g *breaker.Guard) provider.Provider {
	if p == nil || g == nil || !g.Enabled() {
		return p
	}
	return &guarded{inner: p, guard: g}
}

type guarded struct {
	inner provider.Provider
	guard *breaker.Guard
}

var (
	_ provider.Provider         = (*guarded)(nil)
	_ provider.CallbackVerifier = (*guarded)(nil)
	_ provider.CallbackParser   = (*guarded)(nil)
	_ provider.HealthChecker    = (*guarded)(nil)
)

func (g *guarded) Metadata() provider.Metadata { return g.inner.Metadata() }

// AuthURL 不经过熔断：纯 URL 拼接，无网络调用。
func (g *guarded) AuthURL(ctx context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	return g.inner.AuthURL(ctx, req)
}

func (g *guarded) Exchange(ctx context.Context, req provider.ExchangeRequest) (*provider.TokenSet, error) {
	var out *provider.TokenSet
	err := g.do(req.Platform, req.Scene, func() error {
		var callErr error
		out, callErr = g.inner.Exchange(ctx, req)
		return callErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (g *guarded) UserInfo(ctx context.Context, req provider.UserInfoRequest) (*provider.ExternalUser, error) {
	var out *provider.ExternalUser
	err := g.do(req.Platform, req.Scene, func() error {
		var callErr error
		out, callErr = g.inner.UserInfo(ctx, req)
		return callErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (g *guarded) Refresh(ctx context.Context, req provider.RefreshRequest) (*provider.TokenSet, error) {
	var out *provider.TokenSet
	err := g.do(req.Platform, req.Scene, func() error {
		var callErr error
		out, callErr = g.inner.Refresh(ctx, req)
		return callErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (g *guarded) Unbind(ctx context.Context, req provider.UnbindRequest) error {
	return g.do(req.Platform, req.Scene, func() error {
		return g.inner.Unbind(ctx, req)
	})
}

// VerifyCallback 不透传熔断：回调验签是本地密码学运算，不涉及平台可用性。
func (g *guarded) VerifyCallback(ctx context.Context, raw *provider.CallbackPayload) error {
	if v, ok := g.inner.(provider.CallbackVerifier); ok {
		return v.VerifyCallback(ctx, raw)
	}
	return nil
}

// Ping 不透传熔断：健康探测按定义就不参与熔断决策（§5.6.6），
// 而且熔断打开时管理台仍然需要看到"平台到底通不通"。
func (g *guarded) Ping(ctx context.Context) error {
	if h, ok := g.inner.(provider.HealthChecker); ok {
		return h.Ping(ctx)
	}
	return provider.NotSupported("health_check")
}

// ParseCallback 不透传熔断：通知解析是本地报文解析，不涉及平台可用性。
//
// 但必须透传【能力本身】——装饰器若只实现 VerifyCallback 而漏掉 ParseCallback，
// 外层对 Source 的类型断言就会失败，结果是"Apple 明明支持通知，却提示不支持"。
// 这类"装饰器吃掉可选能力"的 bug 不会在编译期暴露，只能靠接口断言与测试兜住。
func (g *guarded) ParseCallback(ctx context.Context, raw *provider.CallbackPayload) (*provider.CallbackEvent, error) {
	if p, ok := g.inner.(provider.CallbackParser); ok {
		return p.ParseCallback(ctx, raw)
	}
	return nil, provider.NotSupported("parse_callback")
}

func (g *guarded) do(platform, scene string, fn func() error) error {
	return g.guard.Do(context.Background(), platform, scene, fn)
}
