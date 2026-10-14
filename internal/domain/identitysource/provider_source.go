package identitysource

import (
	"context"

	"github.com/alex/social-login/internal/domain/provider"
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

// Ping 透传底层 Provider 的健康探测能力（如果实现了的话）。
func (s *providerSource) Ping(ctx context.Context) error {
	if h, ok := s.p.(provider.HealthChecker); ok {
		return h.Ping(ctx)
	}
	return provider.NotSupported("health_check")
}
