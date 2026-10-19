// Package wechat 实现微信四类接入场景的适配器（架构 §13 第二期）。
//
// 四个场景共用同一套 sns 接口，但路由键、授权入口与用户信息来源不同：
//
//	wechat:app            移动应用（iOS/Android 共用）  原生 SDK 拿 code
//	wechat:mini_program   小程序                        wx.login 拿 code
//	wechat:official_account 公众号内 H5                 网页授权跳转
//	wechat:pc_qr          PC 扫码                       扫码跳转
//
// ⚠️ 约束 C3（无 unionid 归并）：即使微信返回了 unionid，本适配器也【不写入】
// ExternalUser.UnionID。归并键退化为 open_id，跨场景同一用户会被识别成不同账号，
// 后续靠 §7 的引导绑定 + 合并流程处理。把 unionid 悄悄写进去会制造"看起来能归并、
// 实际口径不一致"的假象，比不写更危险。
package wechat

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// Extra 配置键（写在 app_provider_configs.extra）。
const (
	cfgAPIBase  = "api_base"
	cfgOpenBase = "open_base"
	// cfgScope 用于公众号网页授权：snsapi_userinfo（默认，可拿昵称头像）
	// 或 snsapi_base（静默授权，只能拿 openid）。
	cfgScope = "scope"
)

const (
	defaultAPIBase  = "https://api.weixin.qq.com"
	defaultOpenBase = "https://open.weixin.qq.com"

	apiTimeout = 5 * time.Second
)

// Adapter 是微信渠道实现（一个实例对应一个 scene）。
type Adapter struct {
	meta   provider.Metadata
	scene  string
	apiBase string
	openBase string
	http   *httpx.Client
	tokens *accessTokenCache
}

// --- 场景构造 ---

// NewApp 构造移动应用登录（iOS 与 Android 共用同一场景与 appid）。
func NewApp(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneApp, "微信移动应用登录", "wechat-openapi-v1", provider.CapabilitySet{
		// 原生 SDK 取 code，服务端仍需 code→token，但没有浏览器跳转。
		ServerSideFlow: true,
		Immediate:      true,
		ProvidesPhone:  false,
		SupportsUnbind: false,
	}, logger)
}

// NewMiniProgram 构造小程序登录。
func NewMiniProgram(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneMiniProgram, "微信小程序登录", "wechat-mini-v1", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      true,
		// 小程序是唯一能拿到【平台已验证】手机号的场景（getPhoneNumber）。
		// 这条能力直接决定 R4 红线的自动归并能否成立。
		ProvidesPhone:  true,
		SupportsUnbind: false,
	}, logger)
}

// NewOfficialAccount 构造公众号网页授权。
func NewOfficialAccount(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneOfficialAccount, "微信公众号网页授权", "wechat-openapi-v1", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      false,
		ProvidesPhone:  false,
		SupportsUnbind: false,
	}, logger)
}

// NewPCQR 构造 PC 扫码登录。
func NewPCQR(logger *zap.Logger) *Adapter {
	return newAdapter(provider.ScenePCQR, "微信 PC 扫码登录", "wechat-openapi-v1", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      false,
		ProvidesPhone:  false,
		SupportsUnbind: false,
	}, logger)
}

func newAdapter(scene, display, apiVersion string, caps provider.CapabilitySet, logger *zap.Logger) *Adapter {
	return &Adapter{
		scene: scene,
		meta: provider.Metadata{
			Platform:     provider.PlatformWeChat,
			Scene:        scene,
			DisplayName:  display,
			APIVersion:   apiVersion,
			Capabilities: caps,
		},
		apiBase:  defaultAPIBase,
		openBase: defaultOpenBase,
		http: httpx.New(httpx.Config{
			Name:         "wechat-" + scene,
			TotalTimeout: apiTimeout,
			Logger:       logger,
		}),
		tokens: newAccessTokenCache(),
	}
}

// init 注册四个场景。
//
// 注意：包级 init 里不带 logger（此时日志系统尚未装配），
// 因此注册的是 New(nil) 版本；需要日志的实例由 bootstrap 另行构造不会重复注册——
// 适配器本身是并发安全的，全局实例的 logger 只影响 provider_call 调试日志。
func init() {
	provider.Register(NewApp(nil))
	provider.Register(NewMiniProgram(nil))
	provider.Register(NewOfficialAccount(nil))
	provider.Register(NewPCQR(nil))
}

var _ provider.Provider = (*Adapter)(nil)

// Metadata 返回渠道描述。
func (a *Adapter) Metadata() provider.Metadata { return a.meta }

// --- 端点解析 ---

func (a *Adapter) apiBaseOf(creds provider.Credentials) string {
	if v := creds.String(cfgAPIBase); v != "" {
		return strings.TrimRight(v, "/")
	}
	return a.apiBase
}

func (a *Adapter) openBaseOf(creds provider.Credentials) string {
	if v := creds.String(cfgOpenBase); v != "" {
		return strings.TrimRight(v, "/")
	}
	return a.openBase
}

// --- 授权入口 ---

// AuthURL 生成授权跳转地址。
//
// app / mini_program 返回 Immediate：授权动作发生在客户端 SDK 里，
// 服务端没有可跳转的地址。返回 Params 是为了让接入层知道该调哪个 SDK 方法，
// 而不是让前端去猜"为什么 URL 是空的"。
func (a *Adapter) AuthURL(_ context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	if req.Creds.ProviderAppID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "微信渠道缺少 provider_app_id（appid）")
	}

	switch a.scene {
	case provider.SceneApp:
		return &provider.AuthorizeResult{
			Immediate: true,
			Params: map[string]string{
				"sdk":    "wechat",
				"method": "sendAuthReq",
				"scope":  "snsapi_userinfo",
			},
		}, nil

	case provider.SceneMiniProgram:
		return &provider.AuthorizeResult{
			Immediate: true,
			Params: map[string]string{
				"sdk":    "wx",
				"method": "login",
			},
		}, nil
	}

	q := url.Values{}
	q.Set("appid", req.Creds.ProviderAppID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("response_type", "code")
	// state 是本服务的服务端票据 ID，不是业务方 state——业务方 state 在票据里。
	q.Set("state", req.State)

	base := a.openBaseOf(req.Creds)
	switch a.scene {
	case provider.SceneOfficialAccount:
		scope := req.Creds.String(cfgScope)
		if scope == "" {
			scope = "snsapi_userinfo"
		}
		q.Set("scope", scope)
		return &provider.AuthorizeResult{URL: buildAuthURL(base, "/connect/oauth2/authorize", q)}, nil

	case provider.ScenePCQR:
		q.Set("scope", "snsapi_login")
		return &provider.AuthorizeResult{URL: buildAuthURL(base, "/connect/qrconnect", q)}, nil
	}

	return nil, errs.Newf(errs.CodeProviderNotSupported, "微信场景 %s 不支持网页授权", a.scene).
		WithDetail("scene", a.scene)
}

// --- 换取令牌 ---

type snsTokenResponse struct {
	wxError
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

type sessionResponse struct {
	wxError
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid"`
}

// Exchange 用授权码换令牌。
func (a *Adapter) Exchange(ctx context.Context, req provider.ExchangeRequest) (*provider.TokenSet, error) {
	if req.Creds.ProviderAppID == "" || req.Creds.Secret == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig,
			"微信渠道缺少 appid 或 appsecret").WithDetail("scene", a.scene)
	}
	if req.Code == "" {
		return nil, errs.New(errs.CodeProviderRejected, "缺少授权码 code").
			WithDetail("platform", provider.PlatformWeChat).
			WithDetail("scene", a.scene)
	}
	base := a.apiBaseOf(req.Creds)

	if a.scene == provider.SceneMiniProgram {
		return a.code2Session(ctx, base, req)
	}

	q := url.Values{}
	q.Set("appid", req.Creds.ProviderAppID)
	q.Set("secret", req.Creds.Secret)
	q.Set("code", req.Code)
	q.Set("grant_type", "authorization_code")

	var out snsTokenResponse
	if _, err := a.http.GetJSON(ctx, base+"/sns/oauth2/access_token", q, &out); err != nil {
		return nil, err
	}
	if out.failed() {
		return nil, wxErr(out.wxError, provider.PlatformWeChat)
	}
	if out.AccessToken == "" || out.OpenID == "" {
		return nil, errs.New(errs.CodeProviderRejected, "微信未返回 access_token 或 openid").
			WithDetail("platform", provider.PlatformWeChat)
	}

	return &provider.TokenSet{
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
		ExpiresIn:    out.ExpiresIn,
		// openid 不是秘密，放进 Raw 供 UserInfo 使用与排障。
		// unionid 按 C3 刻意不落：见包注释。
		Raw: map[string]any{
			"openid": out.OpenID,
			"scope":  out.Scope,
		},
	}, nil
}

func (a *Adapter) code2Session(ctx context.Context, base string, req provider.ExchangeRequest) (*provider.TokenSet, error) {
	q := url.Values{}
	q.Set("appid", req.Creds.ProviderAppID)
	q.Set("secret", req.Creds.Secret)
	q.Set("js_code", req.Code)
	q.Set("grant_type", "authorization_code")

	var out sessionResponse
	if _, err := a.http.GetJSON(ctx, base+"/sns/jscode2session", q, &out); err != nil {
		return nil, err
	}
	if out.failed() {
		return nil, wxErr(out.wxError, provider.PlatformWeChat)
	}
	if out.OpenID == "" || out.SessionKey == "" {
		return nil, errs.New(errs.CodeProviderRejected, "微信未返回 openid 或 session_key").
			WithDetail("platform", provider.PlatformWeChat)
	}

	// 落共享存储，供【后续独立请求】解密手机号用。
	//
	// 微信不返回 session_key 的过期时间，传 0 表示用默认 TTL。
	// 失败不阻断登录（putSessionKey 内部已处理）：本次登录有效，只是
	// "另一个请求、另一个实例"的解密路径不可用。
	putSessionKey(ctx, req.AppID, out.OpenID, out.SessionKey, 0)

	// 密钥只进 Redis（信封加密后），【不进 Raw、不落库、不打日志】：
	// 它是能解开用户手机号的材料，Raw 会被脱敏入库供排障，绝不能带上它。
	return &provider.TokenSet{
		SessionKey: out.SessionKey,
		ExpiresIn:  2 * 3600,
		Raw: map[string]any{
			"openid": out.OpenID,
		},
	}, nil
}

// --- 用户信息 ---

type snsUserInfoResponse struct {
	wxError
	OpenID     string `json:"openid"`
	Nickname   string `json:"nickname"`
	HeadImgURL string `json:"headimgurl"`
	UnionID    string `json:"unionid"`
	Sex        int    `json:"sex"`
	Country    string `json:"country"`
	Province   string `json:"province"`
	City       string `json:"city"`
}

// UserInfo 拉取并归一化用户信息。
func (a *Adapter) UserInfo(ctx context.Context, req provider.UserInfoRequest) (*provider.ExternalUser, error) {
	if req.Token == nil {
		return nil, errs.New(errs.CodeProviderRejected, "缺少令牌，无法拉取用户信息")
	}
	openID, _ := req.Token.Raw["openid"].(string)

	if a.scene == provider.SceneMiniProgram {
		// 小程序没有昵称/头像（微信已下线），身份就是 openid，
		// 手机号只在接入方主动提交 phone_code / encrypted_data 时才有。
		user := &provider.ExternalUser{
			OpenID: openID,
			Raw:    map[string]any{"openid": openID},
		}
		if err := a.fillPhone(ctx, req.AppID, req.Creds, req.Extra, req.Token.SessionKey, user); err != nil {
			return nil, err
		}
		return user, nil
	}

	if openID == "" {
		return nil, errs.New(errs.CodeProviderRejected, "令牌上下文缺少 openid，无法拉取用户信息")
	}
	q := url.Values{}
	q.Set("access_token", req.Token.AccessToken)
	q.Set("openid", openID)
	q.Set("lang", "zh_CN")

	var out snsUserInfoResponse
	base := a.apiBaseOf(req.Creds)
	if _, err := a.http.GetJSON(ctx, base+"/sns/userinfo", q, &out); err != nil {
		return nil, err
	}
	if out.failed() {
		// 公众号用 snsapi_base 静默授权时没有 userinfo 权限（48001）。
		// 这时身份仍然是成立的（openid 已拿到），不能因为拿不到昵称就让登录失败——
		// 那会把"静默授权"这个合法用法直接判死。
		if out.ErrCode == codeAPIUnauthorized {
			return &provider.ExternalUser{
				OpenID: openID,
				Raw: map[string]any{
					"openid": openID,
					"note":   "snsapi_base 静默授权，无用户资料",
				},
			}, nil
		}
		return nil, wxErr(out.wxError, provider.PlatformWeChat)
	}
	if out.OpenID == "" {
		out.OpenID = openID
	}
	return &provider.ExternalUser{
		OpenID:     out.OpenID,
		Nickname:   out.Nickname,
		AvatarURL:  out.HeadImgURL,
		// UnionID 按 C3 不写入。
		Raw: map[string]any{
			"openid":   out.OpenID,
			"nickname": out.Nickname,
			"sex":      out.Sex,
			"country":  out.Country,
			"province": out.Province,
			"city":     out.City,
		},
	}, nil
}

type phoneResponse struct {
	wxError
	PhoneInfo struct {
		PhoneNumber     string `json:"phoneNumber"`
		PurePhoneNumber string `json:"purePhoneNumber"`
		CountryCode     string `json:"countryCode"`
	} `json:"phone_info"`
}

// fillPhone 为小程序场景补手机号。
//
// 两条路径：
//  1. phone_code（新版 getPhoneNumber 返回的一次性 code）—— 推荐，不依赖 session_key；
//  2. encrypted_data + iv（旧版）—— 依赖本次登录拿到的 session_key。
//
// 都没有时保持"只有 openid"的身份：手机号是可选的归并依据，
// 不是登录的前提，强制要求会让所有没接 getPhoneNumber 的小程序无法登录。
func (a *Adapter) fillPhone(ctx context.Context, appID string, creds provider.Credentials, extra map[string]string, sessionKey string, user *provider.ExternalUser) error {
	code := extra["phone_code"]
	encrypted := extra["encrypted_data"]
	iv := extra["iv"]

	if code != "" {
		token, err := a.componentAccessToken(ctx, creds)
		if err != nil {
			return err
		}
		endpoint := a.apiBaseOf(creds) + "/wxa/business/getuserphonenumber?access_token=" + url.QueryEscape(token)
		var out phoneResponse
		if _, err := a.http.PostJSON(ctx, endpoint, map[string]string{"code": code}, &out); err != nil {
			return err
		}
		if out.failed() {
			// 42001/40001：token 失效，清缓存让下次重新取。
			if out.ErrCode == codeTokenExpired || out.ErrCode == codeInvalidCredential {
				a.tokens.invalidate(creds.ProviderAppID)
			}
			return wxErr(out.wxError, provider.PlatformWeChat)
		}
		pure := out.PhoneInfo.PurePhoneNumber
		if pure == "" {
			pure = out.PhoneInfo.PhoneNumber
		}
		if pure == "" {
			return errs.New(errs.CodeProviderRejected, "微信未返回手机号")
		}
		user.Phone = pure
		// 只有走微信官方解密接口才敢标记"平台已验证"（R4 红线 1）。
		user.PhoneVerifiedBy = "wechat_phone"
		return nil
	}

	if encrypted != "" && iv != "" {
		// 先用本次 code2Session 的密钥解：同一次请求里 code 与 encrypted_data
		// 通常来自同一次登录，这条路最快也最准。
		phone, pure, err := decryptPhone(sessionKey, encrypted, iv, creds.ProviderAppID)
		if err != nil {
			// 本次密钥解不开，说明 encrypted_data 是【上一次登录】加密的：
			// 业务方先拿 code 换登录态、再单独上报手机号，两次请求在负载均衡
			// 下可能落在不同实例。此时必须回查共享存储里上一次的 session_key，
			// 而不是直接失败——只上 Redis 但不想这一步，照样会失败。
			if cached := loadSessionKey(ctx, appID, user.OpenID); cached != "" && cached != sessionKey {
				if p2, pu2, e2 := decryptPhone(cached, encrypted, iv, creds.ProviderAppID); e2 == nil {
					phone, pure, err = p2, pu2, nil
				}
			}
		}
		if err != nil {
			// 必须显式失败，不能降级成"没有手机号"：否则下游会拿一个未经
			// 校验的号码继续用，R4 红线 1 就被悄悄绕过了。
			return errs.Wrap(errs.CodeAuthInvalidState,
				"手机号解密失败：会话密钥已失效，请重新调用 getPhoneNumber 获取加密数据", err).
				WithDetail("platform", provider.PlatformWeChat).
				WithDetail("scene", a.scene).
				WithDetail("hint", "encrypted_data 必须是最近一次登录之后产生的")
		}

		// 解密成功即丢弃密钥，缩小它在共享存储里的存活窗口。
		dropSessionKey(ctx, appID, user.OpenID)

		if pure != "" {
			user.Phone = pure
		} else {
			user.Phone = phone
		}
		user.PhoneVerifiedBy = "wechat_phone"
	}
	return nil
}

// --- 刷新 / 解绑 / 健康 ---

// Refresh 刷新微信令牌。小程序无 refresh_token，声明不支持。
func (a *Adapter) Refresh(ctx context.Context, req provider.RefreshRequest) (*provider.TokenSet, error) {
	if a.scene == provider.SceneMiniProgram {
		return nil, provider.NotSupported("refresh（小程序无 refresh_token）")
	}
	if req.Token == nil || req.Token.RefreshToken == "" {
		return nil, provider.NotSupported("refresh（无 refresh_token）")
	}
	q := url.Values{}
	q.Set("appid", req.Creds.ProviderAppID)
	q.Set("grant_type", "refresh_token")
	q.Set("refresh_token", req.Token.RefreshToken)

	var out snsTokenResponse
	if _, err := a.http.GetJSON(ctx, a.apiBaseOf(req.Creds)+"/sns/oauth2/refresh_token", q, &out); err != nil {
		return nil, err
	}
	if out.failed() {
		return nil, wxErr(out.wxError, provider.PlatformWeChat)
	}
	return &provider.TokenSet{
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
		ExpiresIn:    out.ExpiresIn,
		Raw: map[string]any{
			"openid": out.OpenID,
			"scope":  out.Scope,
		},
	}, nil
}

// Unbind 微信未提供标准的解除授权接口，声明不支持。
//
// 调用方（解绑流程）应降级为"只解除本地绑定"，并在文档里告知用户
// 需要到微信侧手动取消授权（架构 §13 第四期的"Unbind 不支持降级提示"）。
func (a *Adapter) Unbind(_ context.Context, _ provider.UnbindRequest) error {
	return provider.NotSupported("unbind")
}

// Ping 探测微信 API 域名可达性。
//
// 只判断"能不能连上、有没有 5xx"。不用带凭据的接口做探测：
// 健康探测不该消耗配额，也不该因为 appsecret 过期而把平台判成不可用——
// 那是配置问题，由 secret:verify 负责发现。
func (a *Adapter) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.apiBase+"/", nil)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "构造健康探测请求失败", err)
	}
	resp, err := a.http.Do(ctx, req)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 500 {
		return errs.Newf(errs.CodeProviderUnavailable, "微信 API 返回 %d", resp.StatusCode).
			WithDetail("platform", provider.PlatformWeChat).
			WithDetail("status", resp.StatusCode)
	}
	return nil
}
