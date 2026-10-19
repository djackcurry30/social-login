// Package identitysource 是决策 D8 的落地：把 Provider 上提一层。
//
// 为什么现在做：架构 §1.3 承诺"架构上预留 IAM / 企业 SSO 扩展位"，但如果没有
// 这一层，编排层就直接依赖 Provider，将来接 OIDC / SAML 上游 IdP 时必须改核心
// 编排——那是有回归风险的数天工作量。现在只多一个接口与一个适配器。
//
// 分工：
//
//	IdentitySource        ← 编排层唯一依赖的抽象（本包）
//	  ├── Provider        ← 三方渠道（当前实现，见 provider 包）
//	  ├── UpstreamIdP     ← OIDC / SAML 企业 SSO（预留）
//	  └── LocalCredential ← 密码 / 短信（预留）
package identitysource

import (
	"context"

	"github.com/djackcurry30/social-login/internal/domain/provider"
)

// Kind 区分身份来源的种类。
type Kind string

const (
	// KindProvider 是三方渠道（微信 / 支付宝 / Apple / 通用 OAuth2）。
	KindProvider Kind = "provider"
	// KindUpstreamIdP 是上游身份提供方（OIDC / SAML），预留。
	KindUpstreamIdP Kind = "upstream_idp"
	// KindLocalCredential 是本地凭证（密码 / 短信），预留。
	KindLocalCredential Kind = "local_credential"
)

// Source 是编排层依赖的身份来源抽象。
//
// 编排层只认这三个动作：生成授权入口、用凭证换身份、在来源侧撤销授权。
// 至于背后是三方渠道还是企业 IdP，编排层不关心。
type Source interface {
	// Kind 返回来源种类。
	Kind() Kind
	// Key 返回来源的路由键。三方渠道为 "platform:scene"。
	Key() string
	// Metadata 返回静态描述与能力声明。
	Metadata() provider.Metadata
	// BeginAuth 生成跳转地址（或返回"无需跳转"的提示）。
	BeginAuth(ctx context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error)
	// Authenticate 用授权凭证换取归一化的外部身份与三方令牌。
	Authenticate(ctx context.Context, req provider.ExchangeRequest) (*provider.ExternalUser, *provider.TokenSet, error)
	// Revoke 在来源侧解除授权。来源不支持时返回 errs.CodeProviderNotSupported。
	Revoke(ctx context.Context, req provider.UnbindRequest) error
}

// CallbackVerifier 由需要回调验签的来源实现（Apple / 支付宝）。
//
// 定义成独立接口而非 Source 的方法，是为了不让所有来源被迫实现空方法；
// 编排层用类型断言探测。
type CallbackVerifier interface {
	VerifyCallback(ctx context.Context, raw *provider.CallbackPayload) error
}

// CallbackParser 由能解析服务端通知的来源实现（Apple / 支付宝）。
type CallbackParser interface {
	ParseCallback(ctx context.Context, raw *provider.CallbackPayload) (*provider.CallbackEvent, error)
}

// CallbackCapability 报告来源是否【真的】具备验签与解析能力。
//
// 为什么需要它：VerifyCallback 对"无需验签"返回 nil，对"未实现"也返回 nil。
// 在授权回调（/v1/oauth/callback）里这是合理的宽容，但在服务端通知
// （/v1/oauth/notify）里是致命的——通知入口没有 state 票据兜底，验签是唯一
// 信任基础，必须显式确认能力存在，不能靠 nil 推断。
type CallbackCapability interface {
	SupportsCallbackVerify() bool
	SupportsCallbackParse() bool
}

// HealthChecker 由支持健康探测的来源实现（可选）。
//
// 仅用于管理台展示与告警，【不参与熔断决策】（架构 §5.6.6）。
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// Registry 是编排层看到的路由表。
type Registry struct {
	inner *provider.Registry
	// wrap 是可选的渠道装饰器（当前用于套熔断器）。
	//
	// 放在查找时应用而不是注册时：注册发生在各适配器的 init()，
	// 那时配置与 logger 都还不存在；而 Lookup 发生在请求路径上，
	// 依赖已经装配完毕。这个时机差是"编译期注册、运行期查找"（D7）
	// 必然带来的，绕开它反而要改注册模型。
	wrap func(provider.Provider) provider.Provider
}

// NewRegistry 包装一个渠道注册表。
func NewRegistry(inner *provider.Registry) *Registry {
	return &Registry{inner: inner}
}

// GlobalRegistry 包装全局渠道注册表。
func GlobalRegistry() *Registry {
	return &Registry{inner: provider.Global()}
}

// SetWrapper 设置渠道装饰器。必须在服务开始处理请求前调用。
func (r *Registry) SetWrapper(w func(provider.Provider) provider.Provider) {
	r.wrap = w
}

// Lookup 按 (平台, 场景) 查找身份来源。
func (r *Registry) Lookup(platform, scene string) (Source, error) {
	p, err := r.inner.Lookup(platform, scene)
	if err != nil {
		return nil, err
	}
	if r.wrap != nil {
		p = r.wrap(p)
	}
	return NewProviderSource(p), nil
}

// List 返回全部来源的元信息。
func (r *Registry) List() []provider.Metadata { return r.inner.List() }
