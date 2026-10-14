package provider

import (
	"net/http"
	"net/url"
	"strings"
)

// Metadata 是渠道的静态描述，用于路由与能力查询。
type Metadata struct {
	Platform     string // 权威枚举见 platform.go
	Scene        string
	DisplayName  string
	Capabilities CapabilitySet
	// APIVersion 是适配器所对接的三方 API 版本，用于灰度与兼容分支（扩展性 E10）。
	APIVersion string
}

// Key 返回路由键 "platform:scene"。
func (m Metadata) Key() string { return Key(m.Platform, m.Scene) }

// CapabilitySet 声明渠道支持的能力，使编排层无需按平台写分支。
type CapabilitySet struct {
	// ServerSideFlow 表示是否存在服务端授权码流程。
	ServerSideFlow bool
	// RequiresPKCE 表示是否必须使用 PKCE。
	RequiresPKCE bool
	// HasCrossSceneID 表示是否提供跨接入场景的归并标识（如微信 unionid）。
	//
	// 注意与 C1/C3 的关系：C1 禁止跨业务应用归并，C3 下微信 unionid 实际不可用，
	// 因此本字段当前所有渠道均为 false，保留以备未来开通开放平台账号绑定。
	HasCrossSceneID bool
	ProvidesEmail   bool
	ProvidesPhone   bool
	SupportsUnbind  bool
	// Immediate 表示无授权页（如微信小程序 code2session），AuthURL 返回空 URL。
	Immediate bool
}

// Credentials 是渠道调用所需的凭据与端点，由【应用层】从渠道配置解密后注入。
//
// 这是实现层对 SPI 的一处补全：架构 §4.1 的请求结构中未说明适配器如何拿到
// 平台密钥。三种做法里选了"凭据随请求下发"，理由：
//
//   - 适配器在 init() 注册时无需依赖任何仓储，保住了决策 D7 的
//     "新增渠道 = 新增一个包 + 一行 import"这一特性。若让适配器自己查配置，
//     注册就必须改成带依赖的工厂，D7 的收益立刻打折。
//   - 密文解密的调用点收敛到应用层一处，便于审计（决策 D6）。
//   - 密钥轮换过渡期的"新旧凭据同时有效"逻辑集中在应用层，
//     不需要每个适配器各自实现一遍。
//
// ⚠️ 本结构承载明文密钥，【禁止写入日志、trace attribute 或错误 details】。
type Credentials struct {
	// ProviderAppID 是平台侧应用标识（wx_appid / alipay_app_id / apple_client_id）。
	ProviderAppID string
	// Secret 是当前有效的平台密钥。公开客户端（PKCE）场景可为空。
	Secret string
	// PreviousSecret 是上一版密钥，仅在轮换过渡期非空（扩展性 E6）。
	PreviousSecret string
	// Extra 是渠道配置中的平台私有配置（端点、scope、字段映射等）。
	Extra map[string]any
}

// String 从 Extra 中读取字符串配置。
func (c Credentials) String(key string) string {
	if c.Extra == nil {
		return ""
	}
	v, ok := c.Extra[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// Strings 从 Extra 中读取字符串数组配置（如 scopes）。
func (c Credentials) Strings(key string) []string {
	if c.Extra == nil {
		return nil
	}
	raw, ok := c.Extra[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	default:
		return nil
	}
}

// Bool 从 Extra 中读取布尔配置。
func (c Credentials) Bool(key string) bool {
	if c.Extra == nil {
		return false
	}
	v, ok := c.Extra[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// AuthorizeRequest 是一次授权发起的入参。全部字段来自服务端票据，前端无法篡改。
type AuthorizeRequest struct {
	AppID     string // 业务应用的对外 app_code
	Platform  string
	Scene     string
	ConfigKey string
	// Creds 是解密后的渠道凭据与端点（见 Credentials 的说明）。
	Creds Credentials
	// Client 是承载形态，仅用于遥测，不参与路由（规则 2）。
	Client string
	// Mode 是 login | bind。
	Mode string
	// RedirectURI 是最终回到业务方的地址，由票据中的服务端配置决定。
	RedirectURI string
	// State 是【服务端票据 ID】。回调时凭它反查全部上下文，前端的业务 state 在票据内。
	State string
	// BusinessState 是业务侧透传的 state，仅原样回传，本服务不解释。
	BusinessState string

	CodeChallenge       string
	CodeChallengeMethod string

	// Nonce 用于 Apple 的防重放（架构 §4.4）。
	Nonce string

	// Extra 承载平台私有参数，由实现自行解释。
	Extra map[string]string
}

// AuthorizeResult 是授权发起的结果。
type AuthorizeResult struct {
	// URL 是三方授权跳转地址。Immediate 场景为空。
	URL string
	// Immediate 为 true 表示无需跳转（如小程序需由前端调用 wx.login 取得 code）。
	Immediate bool
	// Params 在 Immediate 场景下返回给前端的提示参数（如需要前端调用的 SDK 方法名）。
	Params map[string]string
}

// ExchangeRequest 是用授权凭证换取三方令牌的入参。
type ExchangeRequest struct {
	AppID     string
	Platform  string
	Scene     string
	ConfigKey string
	// Creds 是解密后的渠道凭据与端点。
	//
	// 采用"显式字段"而非藏在 Extra 里的保留键，是刻意的：凭据是高频误用点，
	// 放在显式字段上，允许在日志与调试输出里对它做统一脱敏。
	Creds Credentials
	// Code 是三方授权码（小程序场景为 js_code）。
	Code string
	// State 是三方原样回传的 state，用于校验。
	State string
	// RedirectURI 必须与授权时一致，部分平台强校验。
	RedirectURI string
	// CodeVerifier 是 PKCE 的 verifier。
	CodeVerifier string
	// Extra 承载平台私有入参（如支付宝的 auth_code、Apple 的 code + id_token）。
	Extra map[string]string
}

// UserInfoRequest 是拉取三方用户信息的入参。
//
// 这是实现层对 SPI 的一处必要补全：架构 §4.1 的原始签名为
// `UserInfo(ctx, token *TokenSet)`，看似够用——微信、支付宝的 userinfo 确实
// 只需要 access_token。但通用 OAuth2 需要 userinfo_url 与字段映射配置，
// Apple 需要 client_id 参与，这些都只能从渠道配置来。
//
// 修正在此而非退化为"把配置塞进 TokenSet.Raw"：后者会让配置与平台真实返回字段
// 混在一个 map 里，是典型的隐式耦合，排障时会分不清某个键到底是谁写的。
type UserInfoRequest struct {
	AppID     string
	Platform  string
	Scene     string
	ConfigKey string
	Creds     Credentials
	Token     *TokenSet
}

// RefreshRequest 是刷新三方令牌的入参。
type RefreshRequest struct {
	AppID     string
	Platform  string
	Scene     string
	ConfigKey string
	Creds     Credentials
	Token     *TokenSet
}

// UnbindRequest 是在三方平台侧解除授权的入参。
type UnbindRequest struct {
	AppID     string
	Platform  string
	Scene     string
	ConfigKey string
	// Creds 是解密后的渠道凭据与端点。
	Creds       Credentials
	OpenID      string
	UnionID     string
	AccessToken string
	Extra       map[string]string
}

// CallbackPayload 是三方回调的原始报文，供需要验签的平台使用。
type CallbackPayload struct {
	Platform string
	Scene    string
	Query    url.Values
	Body     []byte
	Header   http.Header
}

// TokenSet 是三方令牌集合。除标准 OAuth2 字段外，必须能承载平台私有会话态。
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
	// SessionKey 是微信小程序 code2session 返回的会话密钥，是解密 getPhoneNumber
	// 手机号的前提（R4 红线 1 的关键路径）。
	//
	// 生命周期：由适配器按平台规则设置 ExpiresIn；存储于 Redis，TTL 与平台一致；
	// 解密手机号后立即丢弃，【不落库、不进日志】。
	SessionKey string
	// Raw 是平台原始响应，脱敏后入库供排障。
	Raw map[string]any
}

// ExternalUser 是渠道返回的归一化结果，核心流程只认这个结构。
type ExternalUser struct {
	OpenID    string
	UnionID   string
	Nickname  string
	AvatarURL string
	Email     string
	Phone     string

	// PhoneVerifiedBy / EmailVerifiedBy 是凭证来源标记，写入 identity_claims.source
	// 时必须使用这里的取值，保证 R4 红线 1 的白名单校验可判定。
	//
	// 合法取值（与 DDL 注释、§7.5.3 白名单一致）：
	//   wechat_phone | alipay_phone | sms_verified | apple_email  ← 平台已验证，可用于自动归并
	//   ""                                                        ← 未提供或未验证
	PhoneVerifiedBy string
	EmailVerifiedBy string

	// Raw 是原始响应，入库快照供排障。
	Raw map[string]any
}

// ProfileSnapshot 生成用于 identity.profile_snapshot 的最小快照。
//
// 刻意【不含】手机号与邮箱明文：claim 走 identity_claims 的哈希存储，
// 快照只保留展示用资料，降低 PII 暴露面。
func (u *ExternalUser) ProfileSnapshot() map[string]any {
	snap := map[string]any{}
	if u.Nickname != "" {
		snap["nickname"] = u.Nickname
	}
	if u.AvatarURL != "" {
		snap["avatar_url"] = u.AvatarURL
	}
	if u.UnionID != "" {
		snap["union_id"] = u.UnionID
	}
	if u.PhoneVerifiedBy != "" {
		snap["phone_verified_by"] = u.PhoneVerifiedBy
	}
	if u.EmailVerifiedBy != "" {
		snap["email_verified_by"] = u.EmailVerifiedBy
	}
	return snap
}
