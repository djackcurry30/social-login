// Package alipay 实现支付宝三场景适配器（app / mini_program / web）。
//
// 与微信最大的差异：支付宝的每一个接口都是【带签名的网关调用】，
// 不是"几个固定 URL + query"。因此本包的核心不是拼 URL，而是签名与验签：
//
//	请求 → 参数排序拼接 → RSA2 签名 → 表单 POST 到 gateway
//	响应 → 取节点原始字节 → 用支付宝公钥验签 → 再反序列化
//
// ⚠️ 验签必须用【节点的原始字节】。反序列化后再序列化会改变空白与字段顺序，
// 签名必然对不上——这是接支付宝时最常见的踩坑点。
package alipay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

const (
	cfgGateway   = "gateway"
	cfgAuthBase  = "auth_base"
	cfgPublicKey = "alipay_public_key" // 支付宝公钥，用于响应验签
	cfgSignType  = "sign_type"

	defaultGateway  = "https://openapi.alipay.com/gateway.do"
	defaultAuthBase = "https://openauth.alipay.com"

	apiTimeout = 5 * time.Second

	// methodOAuthToken 是 code / refresh_token 换令牌的接口。
	methodOAuthToken = "alipay.system.oauth.token"
	// methodUserInfo 是取用户资料（昵称、头像）。
	methodUserInfo = "alipay.user.info.share"
)

// Adapter 是支付宝渠道实现（一个实例对应一个 scene）。
type Adapter struct {
	meta provider.Metadata
	http *httpx.Client
}

// NewApp 构造 App 登录（客户端 SDK 拿 auth_code）。
func NewApp(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneApp, "支付宝 App 登录", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      true,
		SupportsUnbind: false,
	}, logger)
}

// NewMiniProgram 构造支付宝小程序登录。
func NewMiniProgram(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneMiniProgram, "支付宝小程序登录", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      true,
		SupportsUnbind: false,
	}, logger)
}

// NewWeb 构造支付宝网页登录。
func NewWeb(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneWeb, "支付宝网页登录", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      false,
		SupportsUnbind: false,
	}, logger)
}

func newAdapter(scene, display string, caps provider.CapabilitySet, logger *zap.Logger) *Adapter {
	return &Adapter{
		meta: provider.Metadata{
			Platform:     provider.PlatformAlipay,
			Scene:        scene,
			DisplayName:  display,
			APIVersion:   "alipay-openapi-1.0",
			Capabilities: caps,
		},
		http: httpx.New(httpx.Config{
			Name:         "alipay-" + scene,
			TotalTimeout: apiTimeout,
			Logger:       logger,
		}),
	}
}

func init() {
	provider.Register(NewApp(nil))
	provider.Register(NewMiniProgram(nil))
	provider.Register(NewWeb(nil))
}

var _ provider.Provider = (*Adapter)(nil)

// Metadata 返回渠道描述。
func (a *Adapter) Metadata() provider.Metadata { return a.meta }

func gatewayOf(creds provider.Credentials) string {
	if v := creds.String(cfgGateway); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultGateway
}

func authBaseOf(creds provider.Credentials) string {
	if v := creds.String(cfgAuthBase); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultAuthBase
}

// AuthURL 生成授权跳转地址。
//
// App 与小程序由客户端 SDK 拉起授权，服务端没有可跳转地址（Immediate）。
func (a *Adapter) AuthURL(_ context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	if req.Creds.ProviderAppID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "支付宝渠道缺少 provider_app_id（app_id）")
	}
	if a.meta.Scene != provider.SceneWeb {
		return &provider.AuthorizeResult{
			Immediate: true,
			Params: map[string]string{
				"sdk":    "alipay",
				"method": "auth",
				"scope":  "auth_user",
			},
		}, nil
	}

	q := url.Values{}
	q.Set("app_id", req.Creds.ProviderAppID)
	q.Set("scope", "auth_user")
	q.Set("redirect_uri", req.RedirectURI)
	// state 是服务端票据 ID（业务方 state 在票据里），回调时凭它还原上下文。
	q.Set("state", req.State)
	return &provider.AuthorizeResult{
		URL: authBaseOf(req.Creds) + "/oauth2/publicAppAuthorize.htm?" + q.Encode(),
	}, nil
}

// --- 网关调用 ---

type apiError struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	SubCode string `json:"sub_code"`
	SubMsg  string `json:"sub_msg"`
}

// call 发起一次带签名的网关调用，返回业务节点的原始字节。
func (a *Adapter) call(ctx context.Context, creds provider.Credentials, method string, biz map[string]string) ([]byte, error) {
	priv, err := loadPrivateKey(creds.Secret)
	if err != nil {
		return nil, err
	}

	params := map[string]string{
		"app_id":    creds.ProviderAppID,
		"method":    method,
		"format":    "JSON",
		"charset":   "utf-8",
		"sign_type": "RSA2",
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		"version":   "1.0",
	}
	if v := creds.String(cfgSignType); v != "" {
		params["sign_type"] = v
	}
	for k, v := range biz {
		params[k] = v
	}

	sign, err := signParams(params, priv)
	if err != nil {
		return nil, err
	}
	params["sign"] = sign

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}

	body := form.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayOf(creds), strings.NewReader(body))
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造支付宝请求失败", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := a.http.Do(ctx, httpReq)
	if err != nil {
		return nil, err
	}
	return a.decodeResponse(resp.Raw, method, creds)
}

// decodeResponse 解析网关响应、处理错误、验签，并返回业务节点。
func (a *Adapter) decodeResponse(raw []byte, method string, creds provider.Credentials) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, errs.Wrap(errs.CodeProviderUnavailable, "支付宝响应不是合法 JSON", err)
	}

	// 网关级错误优先：它的字段结构与业务响应不同。
	if errNode, ok := envelope["error_response"]; ok {
		var e apiError
		_ = json.Unmarshal(errNode, &e)
		return nil, mapAPIError(e)
	}

	nodeKey := strings.ReplaceAll(method, ".", "_") + "_response"
	node, ok := envelope[nodeKey]
	if !ok {
		return nil, errs.Newf(errs.CodeProviderUnavailable, "支付宝响应缺少节点 %s", nodeKey).
			WithDetail("method", method)
	}

	// 验签：配置了支付宝公钥就强制校验。
	//
	// 不验签的后果不是"少一层防护"，而是"完全无法发现被篡改或伪造的响应"——
	// 网关返回的 user_id 直接决定账号归属。因此这里选择"配了就必须验"，
	// 没配则在返回的错误里明确提示，而不是静默跳过。
	if pubRaw := creds.String(cfgPublicKey); pubRaw != "" {
		var signB64 string
		if s, ok := envelope["sign"]; ok {
			_ = json.Unmarshal(s, &signB64)
		}
		if signB64 == "" {
			return nil, errs.New(errs.CodeProviderRejected, "支付宝响应缺少 sign，无法验签")
		}
		pub, err := loadPublicKey(pubRaw)
		if err != nil {
			return nil, err
		}
		if err := verifyNode(node, signB64, pub); err != nil {
			return nil, err
		}
	}
	return node, nil
}

// mapAPIError 把支付宝错误归一化。
//
// 分类口径与微信一致：业务拒绝不计入熔断，配置错误计入但单独告警。
func mapAPIError(e apiError) *errs.Error {
	sub := e.SubCode
	switch {
	case strings.Contains(sub, "code-invalid"), strings.Contains(sub, "code-used"),
		strings.Contains(sub, "token-invalid"), strings.Contains(sub, "token-expired"):
		return errs.Newf(errs.CodeProviderRejected, "支付宝授权码或令牌无效: %s", pickMsg(e)).
			WithDetail("alipay_sub_code", sub)

	case strings.Contains(sub, "invalid-signature"), strings.Contains(sub, "invalid-app-id"),
		strings.Contains(sub, "app-not-exist"), strings.Contains(sub, "invalid-public-key"),
		strings.Contains(sub, "isv.missing"):
		// 配置类错误：私钥与 app_id 不匹配、公钥填错等。不会自愈。
		return errs.Newf(errs.CodeAuthInvalidConfig, "支付宝渠道配置有误: %s", pickMsg(e)).
			WithDetail("alipay_sub_code", sub)

	case strings.Contains(sub, "rate-limit"), strings.Contains(sub, "limit"):
		return errs.Newf(errs.CodeProviderQuotaExceeded, "支付宝接口限流: %s", pickMsg(e)).
			WithDetail("alipay_sub_code", sub)

	default:
		return errs.Newf(errs.CodeProviderUnavailable, "支付宝返回错误: %s", pickMsg(e)).
			WithDetail("alipay_code", e.Code).
			WithDetail("alipay_sub_code", sub)
	}
}

func pickMsg(e apiError) string {
	if e.SubMsg != "" {
		return e.SubMsg
	}
	if e.Msg != "" {
		return e.Msg
	}
	return "未知错误"
}

// --- 令牌 ---

type tokenNode struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	ReExpiresIn  int    `json:"re_expires_in"`
	AuthMethods  string `json:"auth_methods"`
}

// Exchange 用 auth_code 换令牌。
func (a *Adapter) Exchange(ctx context.Context, req provider.ExchangeRequest) (*provider.TokenSet, error) {
	if req.Creds.ProviderAppID == "" || req.Creds.Secret == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "支付宝渠道缺少 app_id 或应用私钥").
			WithDetail("scene", a.meta.Scene)
	}
	if req.Code == "" {
		return nil, errs.New(errs.CodeProviderRejected, "缺少授权码 auth_code").
			WithDetail("platform", provider.PlatformAlipay)
	}

	node, err := a.call(ctx, req.Creds, methodOAuthToken, map[string]string{
		"grant_type": "authorization_code",
		"code":       req.Code,
	})
	if err != nil {
		return nil, err
	}
	var out tokenNode
	if err := json.Unmarshal(node, &out); err != nil {
		return nil, errs.Wrap(errs.CodeProviderUnavailable, "解析支付宝令牌响应失败", err)
	}
	if out.AccessToken == "" || out.UserID == "" {
		return nil, errs.New(errs.CodeProviderRejected, "支付宝未返回 access_token 或 user_id").
			WithDetail("platform", provider.PlatformAlipay)
	}
	return &provider.TokenSet{
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
		ExpiresIn:    out.ExpiresIn,
		Raw: map[string]any{
			"user_id": out.UserID,
		},
	}, nil
}

// Refresh 用 refresh_token 续期。
func (a *Adapter) Refresh(ctx context.Context, req provider.RefreshRequest) (*provider.TokenSet, error) {
	if req.Token == nil || req.Token.RefreshToken == "" {
		return nil, provider.NotSupported("refresh（无 refresh_token）")
	}
	node, err := a.call(ctx, req.Creds, methodOAuthToken, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": req.Token.RefreshToken,
	})
	if err != nil {
		return nil, err
	}
	var out tokenNode
	if err := json.Unmarshal(node, &out); err != nil {
		return nil, errs.Wrap(errs.CodeProviderUnavailable, "解析支付宝刷新响应失败", err)
	}
	return &provider.TokenSet{
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
		ExpiresIn:    out.ExpiresIn,
		Raw:          map[string]any{"user_id": out.UserID},
	}, nil
}

// --- 用户信息 ---

type userInfoNode struct {
	UserID    string `json:"user_id"`
	NickName  string `json:"nick_name"`
	Avatar    string `json:"avatar"`
	Province  string `json:"province"`
	City      string `json:"city"`
	Gender    string `json:"gender"`
	IsStudent bool   `json:"is_student"`
}

// UserInfo 拉取用户资料。
//
// 支付宝的 user.info.share 不返回手机号与邮箱——这是平台策略，不是我们没实现。
// 因此本渠道的 ProvidesPhone / ProvidesEmail 都是 false，
// 也就不会产生任何可用于自动归并的 claim（R4 红线 1 自然成立）。
func (a *Adapter) UserInfo(ctx context.Context, req provider.UserInfoRequest) (*provider.ExternalUser, error) {
	if req.Token == nil || req.Token.AccessToken == "" {
		return nil, errs.New(errs.CodeProviderRejected, "缺少 access_token，无法拉取用户信息")
	}
	userID, _ := req.Token.Raw["user_id"].(string)

	node, err := a.call(ctx, req.Creds, methodUserInfo, map[string]string{
		"auth_token": req.Token.AccessToken,
	})
	if err != nil {
		return nil, err
	}
	var out userInfoNode
	if err := json.Unmarshal(node, &out); err != nil {
		return nil, errs.Wrap(errs.CodeProviderUnavailable, "解析支付宝用户信息失败", err)
	}
	if out.UserID == "" {
		out.UserID = userID
	}
	if out.UserID == "" {
		return nil, errs.New(errs.CodeProviderRejected, "支付宝未返回 user_id").
			WithDetail("platform", provider.PlatformAlipay)
	}
	return &provider.ExternalUser{
		// 支付宝的 user_id 是 app 维度唯一的，语义等价于微信 openid。
		OpenID:    out.UserID,
		Nickname:  out.NickName,
		AvatarURL: out.Avatar,
		Raw: map[string]any{
			"user_id":   out.UserID,
			"nick_name": out.NickName,
			"province":  out.Province,
			"city":      out.City,
			"gender":    out.Gender,
		},
	}, nil
}

// Unbind 支付宝未提供面向 App/网页的通用解绑接口，声明不支持。
func (a *Adapter) Unbind(_ context.Context, _ provider.UnbindRequest) error {
	return provider.NotSupported("unbind")
}

// Ping 探测开放平台网关可达性。
func (a *Adapter) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultGateway, nil)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "构造健康探测请求失败", err)
	}
	resp, err := a.http.Do(ctx, req)
	if err != nil {
		return err
	}
	// 网关对无签名请求也会返回 200/400 的 JSON，能连上就算可达。
	if resp.StatusCode >= 500 {
		return errs.Newf(errs.CodeProviderUnavailable, "支付宝网关返回 %d", resp.StatusCode).
			WithDetail("platform", provider.PlatformAlipay)
	}
	return nil
}
