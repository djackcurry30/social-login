// Package generic_oauth2 是配置驱动的通用 OAuth2 适配器。
//
// 它的价值不只是"支持任意标准 OAuth2 平台"，更是【验证抽象是否合理】：
// 如果通用适配器能仅靠配置接入一个平台，说明 Provider SPI 没有泄漏具体平台的
// 假设（架构 §13 第一期把它列为骨架验证手段）。
//
// 同时它也是第一期验收的载体——用自建 OAuth2 测试服务走通完整登录链路。
package generic_oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/alex/social-login/internal/domain/provider"
	"github.com/alex/social-login/internal/pkg/errs"
	"github.com/alex/social-login/internal/pkg/httpx"
)

// Extra 配置项名称。全部写在 app_provider_configs.extra 里，改配置不改代码。
const (
	cfgAuthorizeURL = "authorize_url"
	cfgTokenURL     = "token_url"
	cfgUserInfoURL  = "userinfo_url"
	cfgScopes       = "scopes"

	// cfgAuthStyle 决定客户端凭据的传递方式。
	//   client_secret_post  —— 放在请求体（默认，大多数平台）
	//   client_secret_basic —— 放 Authorization: Basic
	//   none                —— 公开客户端（配合 PKCE）
	cfgAuthStyle = "auth_style"

	// 用户信息字段映射。不同平台字段名不同，靠配置对齐，避免为每个平台写代码。
	cfgFieldOpenID   = "field_open_id"
	cfgFieldUnionID  = "field_union_id"
	cfgFieldNickname = "field_nickname"
	cfgFieldAvatar   = "field_avatar"
	cfgFieldEmail    = "field_email"
	cfgFieldPhone    = "field_phone"

	// cfgEmailVerifiedBy / cfgPhoneVerifiedBy 声明"该平台返回的该字段是否已验证"，
	// 取值必须是 identity 包的权威枚举（apple_email / wechat_phone 等）。
	//
	// 这一项直接决定 R4 红线 1 能否成立：只有填了它，该凭证才可能被标记为
	// 已验证并参与自动归并。留空表示"不做任何承诺"——凭证会被记录，
	// 但永不作为归并依据。
	cfgEmailVerifiedBy = "email_verified_by"
	cfgPhoneVerifiedBy = "phone_verified_by"
)

const (
	authStylePost  = "client_secret_post"
	authStyleBasic = "client_secret_basic"
	authStyleNone  = "none"
)

// Adapter 是通用 OAuth2 渠道实现。
//
// scene 固定为 web：通用适配器的端点全部来自配置，而路由键需要 (platform, scene)。
// 若将来需要为同一 platform 注册多个通用场景，应把注册改为工厂模式——当前不做，
// 因为"一个应用接多个通用 OAuth2 平台"的正确做法是配多个 platform，而非多个 scene。
type Adapter struct {
	meta provider.Metadata
	http *httpx.Client
}

// New 构造适配器。logger 可为 nil。
func New(logger *zap.Logger) *Adapter {
	return &Adapter{
		meta: provider.Metadata{
			Platform:    provider.PlatformGenericOAuth2,
			Scene:       provider.SceneWeb,
			DisplayName: "通用 OAuth2（配置驱动）",
			APIVersion:  "rfc6749",
			Capabilities: provider.CapabilitySet{
				ServerSideFlow: true,
				// PKCE 是否强制由配置决定，能力声明取保守值。
				RequiresPKCE:    false,
				HasCrossSceneID: false,
				ProvidesEmail:   true,
				ProvidesPhone:   false,
				SupportsUnbind:  false,
				Immediate:       false,
			},
		},
		http: httpx.New(httpx.Config{
			Name:         provider.PlatformGenericOAuth2,
			TotalTimeout: 5 * time.Second,
			Logger:       logger,
		}),
	}
}

// init 在编译期注册到全局注册表。
//
// 注意这里不带 logger：包初始化阶段日志系统尚未装配。需要带 logger 的实例
// 由 bootstrap 用 New(logger) 单独构造。
func init() {
	provider.Register(New(nil))
}

var _ provider.Provider = (*Adapter)(nil)

// Metadata 返回渠道描述。
func (a *Adapter) Metadata() provider.Metadata { return a.meta }

// AuthURL 生成三方授权跳转地址。
func (a *Adapter) AuthURL(_ context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	authorizeURL := req.Creds.String(cfgAuthorizeURL)
	if authorizeURL == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "通用 OAuth2 渠道缺少 authorize_url 配置").
			WithDetail("platform", a.meta.Platform).
			WithDetail("scene", a.meta.Scene)
	}
	if req.Creds.ProviderAppID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "通用 OAuth2 渠道缺少 provider_app_id（client_id）")
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", req.Creds.ProviderAppID)
	q.Set("redirect_uri", req.RedirectURI)
	// state 是本服务的服务端票据 ID：回调时凭它反查全部上下文（架构 §5.2）。
	q.Set("state", req.State)
	if scopes := req.Creds.Strings(cfgScopes); len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
		method := req.CodeChallengeMethod
		if method == "" {
			method = "S256"
		}
		q.Set("code_challenge_method", method)
	}
	if req.Nonce != "" {
		q.Set("nonce", req.Nonce)
	}

	sep := "?"
	if strings.Contains(authorizeURL, "?") {
		sep = "&"
	}
	return &provider.AuthorizeResult{URL: authorizeURL + sep + q.Encode()}, nil
}

// tokenResponse 是标准 OAuth2 令牌响应。
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// Exchange 用授权码换取令牌。
func (a *Adapter) Exchange(ctx context.Context, req provider.ExchangeRequest) (*provider.TokenSet, error) {
	tokenURL := req.Creds.String(cfgTokenURL)
	if tokenURL == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "通用 OAuth2 渠道缺少 token_url 配置")
	}
	if req.Code == "" {
		return nil, errs.New(errs.CodeProviderRejected, "缺少授权码").
			WithDetail("platform", a.meta.Platform)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	if req.RedirectURI != "" {
		// redirect_uri 必须与授权时完全一致，多数平台强校验。
		form.Set("redirect_uri", req.RedirectURI)
	}
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	style := req.Creds.String(cfgAuthStyle)
	if style == "" {
		style = authStylePost
	}

	var tr tokenResponse
	switch style {
	case authStyleBasic:
		req2, err := a.buildBasicAuthRequest(ctx, tokenURL, form, req.Creds)
		if err != nil {
			return nil, err
		}
		if _, err := a.http.DoJSON(ctx, req2, &tr); err != nil {
			return nil, err
		}
	case authStyleNone:
		// 公开客户端：带上 client_id 但不带 secret。
		form.Set("client_id", req.Creds.ProviderAppID)
		if _, err := a.http.PostFormJSON(ctx, tokenURL, form, &tr); err != nil {
			return nil, err
		}
	default:
		form.Set("client_id", req.Creds.ProviderAppID)
		if req.Creds.Secret != "" {
			form.Set("client_secret", req.Creds.Secret)
		}
		if _, err := a.http.PostFormJSON(ctx, tokenURL, form, &tr); err != nil {
			return nil, err
		}
	}

	if tr.AccessToken == "" {
		return nil, errs.New(errs.CodeProviderRejected, "三方未返回 access_token").
			WithDetail("platform", a.meta.Platform)
	}
	return &provider.TokenSet{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresIn:    tr.ExpiresIn,
		Raw:          sanitizeTokenRaw(tr),
	}, nil
}

// buildBasicAuthRequest 构造带 Basic 认证头的令牌请求。
func (a *Adapter) buildBasicAuthRequest(ctx context.Context, tokenURL string, form url.Values, creds provider.Credentials) (*http.Request, error) {
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body))
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造三方请求失败", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(body))
	// RFC 6749 §2.3.1 要求 client_id 与 client_secret 先做 URL 编码再拼进 Basic。
	req.SetBasicAuth(url.QueryEscape(creds.ProviderAppID), url.QueryEscape(creds.Secret))
	return req, nil
}

// userInfoResponse 是用户信息响应，字段按配置映射。
type userInfoResponse map[string]any

// UserInfo 拉取用户信息并归一化。
func (a *Adapter) UserInfo(ctx context.Context, req provider.UserInfoRequest) (*provider.ExternalUser, error) {
	if req.Token == nil || req.Token.AccessToken == "" {
		return nil, errs.New(errs.CodeProviderRejected, "缺少 access_token，无法拉取用户信息")
	}
	userInfoURL := req.Creds.String(cfgUserInfoURL)
	if userInfoURL == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "通用 OAuth2 渠道缺少 userinfo_url 配置")
	}

	// 注意：UserInfo 是幂等的（GET + Bearer），但仍不做重试——重试责任在接入方，
	// 由它重新发起整个授权流程（约束 C6）。保持与 Exchange 一致的策略，
	// 避免"部分接口重试、部分不重试"这种需要逐个判断的坏抽象。
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造用户信息请求失败", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.Token.AccessToken)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := a.http.Do(ctx, httpReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, errs.Newf(errs.CodeProviderRejected, "拉取用户信息失败，三方返回 %d", resp.StatusCode).
			WithDetail("platform", a.meta.Platform)
	}
	var raw userInfoResponse
	if err := json.Unmarshal(resp.Raw, &raw); err != nil {
		return nil, errs.Wrap(errs.CodeProviderUnavailable, "解析用户信息失败", err)
	}

	out := &provider.ExternalUser{Raw: map[string]any(raw)}
	out.OpenID = fieldString(raw, req.Creds.String(cfgFieldOpenID), "sub")
	out.UnionID = fieldString(raw, req.Creds.String(cfgFieldUnionID), "")
	out.Nickname = fieldString(raw, req.Creds.String(cfgFieldNickname), "name")
	out.AvatarURL = fieldString(raw, req.Creds.String(cfgFieldAvatar), "picture")
	out.Email = fieldString(raw, req.Creds.String(cfgFieldEmail), "email")
	out.Phone = fieldString(raw, req.Creds.String(cfgFieldPhone), "phone_number")

	// 凭证来源标记：只有配置显式声明了"平台已验证"，才允许标记；
	// 否则留空，该凭证被记录但【永不参与自动归并】（R4 红线 1）。
	out.EmailVerifiedBy = verifiedBy(req.Creds, cfgEmailVerifiedBy, out.Email)
	out.PhoneVerifiedBy = verifiedBy(req.Creds, cfgPhoneVerifiedBy, out.Phone)

	if out.OpenID == "" {
		return nil, errs.New(errs.CodeProviderRejected, "用户信息中缺少用户标识字段").
			WithDetail("platform", a.meta.Platform).
			WithDetail("field_open_id", req.Creds.String(cfgFieldOpenID))
	}
	return out, nil
}

// Refresh 刷新令牌。
func (a *Adapter) Refresh(ctx context.Context, req provider.RefreshRequest) (*provider.TokenSet, error) {
	if req.Token == nil || req.Token.RefreshToken == "" {
		return nil, provider.NotSupported("refresh（无 refresh_token）")
	}
	tokenURL := req.Creds.String(cfgTokenURL)
	if tokenURL == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "通用 OAuth2 渠道缺少 token_url 配置")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.Token.RefreshToken)
	form.Set("client_id", req.Creds.ProviderAppID)
	if req.Creds.Secret != "" {
		form.Set("client_secret", req.Creds.Secret)
	}

	var tr tokenResponse
	if _, err := a.http.PostFormJSON(ctx, tokenURL, form, &tr); err != nil {
		return nil, err
	}
	return &provider.TokenSet{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresIn:    tr.ExpiresIn,
		Raw:          sanitizeTokenRaw(tr),
	}, nil
}

// Unbind 在平台侧解除授权。通用 OAuth2 无标准撤销端点，声明不支持。
func (a *Adapter) Unbind(_ context.Context, _ provider.UnbindRequest) error {
	return provider.NotSupported("unbind")
}

// --- 辅助函数 ---

// fieldString 按"配置字段名 → 回退字段名"的顺序取值。
func fieldString(raw map[string]any, field, fallback string) string {
	names := make([]string, 0, 2)
	if field != "" {
		names = append(names, field)
	}
	if fallback != "" && fallback != field {
		names = append(names, fallback)
	}
	for _, n := range names {
		v, ok := raw[n]
		if !ok {
			continue
		}
		switch s := v.(type) {
		case string:
			if s != "" {
				return s
			}
		case float64:
			// 有些平台的 user_id 是数字类型。
			return strconv.FormatFloat(s, 'f', -1, 64)
		case json.Number:
			return s.String()
		case bool:
			return strconv.FormatBool(s)
		}
	}
	return ""
}

// verifiedBy 只有在"平台确实返回了该字段"且"配置声明了已验证来源"时才给出标记。
func verifiedBy(creds provider.Credentials, cfgKey, value string) string {
	if value == "" {
		return ""
	}
	return creds.String(cfgKey)
}

// sanitizeTokenRaw 去掉令牌响应中的敏感字段后再进内存。
//
// 为什么必须做：TokenSet.Raw 会被写入排障日志与快照。access_token / refresh_token
// 一旦落进日志，任何有日志读取权限的人都能冒充用户——这类泄漏在事故复盘里极常见。
func sanitizeTokenRaw(tr tokenResponse) map[string]any {
	out := map[string]any{}
	if tr.TokenType != "" {
		out["token_type"] = tr.TokenType
	}
	if tr.ExpiresIn > 0 {
		out["expires_in"] = tr.ExpiresIn
	}
	if tr.Scope != "" {
		out["scope"] = tr.Scope
	}
	// 保留"是否拿到"这个排障信息，但不保留令牌值本身。
	if tr.RefreshToken != "" {
		out["has_refresh_token"] = true
	}
	if tr.IDToken != "" {
		out["has_id_token"] = true
	}
	return out
}
