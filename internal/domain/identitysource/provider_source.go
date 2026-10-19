package identitysource

import (
	"context"

	"github.com/djackcurry30/social-login/internal/domain/provider"
)

// providerSource 把 provider.Provider 适配为 Source。
//
// 关键在于 Authenticate：它把 SPI 上的两次调用（Exchange + UserInfo）组合成
// 编排层真正需要的语义——"拿凭证换一个归一化身份"。这样编排层就不必知道
// 三方渠道是两步还是三步，也不必在接上游 IdP 时改流程。
type providerSource struct {
	p provider.Provider
}

// NewProviderSource 包装一个渠道实现。
func NewProviderSource(p provider.Provider) Source {
	return &providerSource{p: p}
}

func (s *providerSource) Kind() Kind                  { return KindProvider }
func (s *providerSource) Key() string                 { return s.p.Metadata().Key() }
func (s *providerSource) Metadata() provider.Metadata { return s.p.Metadata() }

func (s *providerSource) BeginAuth(ctx context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	return s.p.AuthURL(ctx, req)
}

// Authenticate 组合 Exchange 与 UserInfo。
//
// 注意 ctx 的传递：调用方（authflow）在 Exchange 阶段必须传入用 httpx.Detach
// 构造的 context，本方法不改变这一语义——它只做组合，不做超时决策。
//
// 组合动作放在这一层而不是让编排层自己调两次，正是 D8 的收益：
// 将来换成上游 IdP 时，"用凭证换身份"仍是一个动作，编排层的代码不用动。
func (s *providerSource) Authenticate(ctx context.Context, req provider.ExchangeRequest) (*provider.ExternalUser, *provider.TokenSet, error) {
	tokens, err := s.p.Exchange(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.p.UserInfo(ctx, provider.UserInfoRequest{
		AppID:     req.AppID,
		Platform:  req.Platform,
		Scene:     req.Scene,
		ConfigKey: req.ConfigKey,
		Creds:     req.Creds,
		Token:     tokens,
		// 平台私有入参随 Exchange 一路带到 UserInfo：小程序的手机号解密 /
		// Apple 的 id_token 都出现在回调参数里，而不是 Exchange 的产出。
		Extra: req.Extra,
	})
	if err != nil {
		return nil, nil, err
	}
	return user, tokens, nil
}

func (s *providerSource) Revoke(ctx context.Context, req provider.UnbindRequest) error {
	return s.p.Unbind(ctx, req)
}

// VerifyCallback 透传底层 Provider 的回调验签能力（如果实现了的话）。
func (s *providerSource) VerifyCallback(ctx context.Context, raw *provider.CallbackPayload) error {
	if v, ok := s.p.(provider.CallbackVerifier); ok {
		return v.VerifyCallback(ctx, raw)
	}
	// 未实现验签的渠道视为"无需验签"，返回 nil 而非错误。
	return nil
}

// SupportsCallbackVerify 报告底层渠道是否真的实现了验签。
//
// 与 VerifyCallback 的 nil 语义分开是【安全要求】：
// "渠道不需要验签"（如通用 OAuth2 的回调）与"渠道本应验签但我们没实现"
// 在回调场景下都返回 nil，无从区分。服务端通知入口（notify）必须用本方法
// 先确认能力存在——否则一个未实现验签的适配器就能让伪造报文通过。
func (s *providerSource) SupportsCallbackVerify() bool {
	_, ok := s.p.(provider.CallbackVerifier)
	return ok
}

// ParseCallback 透传底层 Provider 的服务端通知解析能力。
func (s *providerSource) ParseCallback(ctx context.Context, raw *provider.CallbackPayload) (*provider.CallbackEvent, error) {
	if p, ok := s.p.(provider.CallbackParser); ok {
		return p.ParseCallback(ctx, raw)
	}
	return nil, provider.NotSupported("parse_callback")
}

// SupportsCallbackParse 报告底层渠道是否实现了通知解析。
func (s *providerSource) SupportsCallbackParse() bool {
	_, ok := s.p.(provider.CallbackParser)
	return ok
}

// Ping 透传底层 Provider 的健康探测能力（如果实现了的话）。
func (s *providerSource) Ping(ctx context.Context) error {
	if h, ok := s.p.(provider.HealthChecker); ok {
		return h.Ping(ctx)
	}
	return provider.NotSupported("health_check")
}
