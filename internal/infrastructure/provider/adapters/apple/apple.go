// Package apple 实现 Sign in with Apple（约束 C2 必做项）。
//
// 四件 Apple 特有、且最容易做错的事：
//
//  1. client_secret 不是一个固定字符串，而是用 .p8 私钥签出的【ES256 JWT】，
//     有效期最长 6 个月，必须自动续期（见 clientSecret）。
//  2. id_token 必须用 Apple 的 JWKS 验签；kid 未命中时要重取一次——
//     这是协议语义要求，不受"不重试"约束（C6）限制。
//  3. nonce 必须回比对。没有它，被截获的 id_token 可以无限重放登录。
//  4. 姓名与邮箱【只在首次授权】返回，之后再也拿不到。丢了就永久丢了，
//     所以 UserInfo 必须把 Extra["user"] 里的 name 落到资料里。
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

const (
	cfgTeamID   = "team_id"
	cfgKeyID    = "key_id"
	cfgJWKSURL  = "jwks_url"
	cfgTokenURL = "token_url"
	cfgRevokeURL = "revoke_url"

	defaultJWKSURL   = "https://appleid.apple.com/auth/keys"
	defaultTokenURL  = "https://appleid.apple.com/auth/token"
	defaultRevokeURL = "https://appleid.apple.com/auth/revoke"

	appleIssuer = "https://appleid.apple.com"

	apiTimeout = 5 * time.Second

	// clientSecretTTL 取 30 天：Apple 允许最长 6 个月，但短一些能让
	// 私钥轮换在可接受的时间内生效，也不会造成频繁重签。
	clientSecretTTL = 30 * 24 * time.Hour
)

// Adapter 是 Apple 渠道实现。
type Adapter struct {
	meta provider.Metadata
	http *httpx.Client

	secretMu    sync.Mutex
	secretCache map[string]cachedSecret

	jwks *jwksCache

	// notifyJWKSURL 是服务端通知验签使用的 JWKS 地址。
	//
	// 独立于租户配置里的 jwks_url：通知报文不携带任何租户上下文，Apple 的
	// JWKS 也是全局唯一的，按租户配置去取反而会取错。设为字段而非常量，
	// 只是为了让单测能指向本地假端点。
	notifyJWKSURL string
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// NewApp 构造 iOS 原生登录。
func NewApp(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneApp, "Apple 登录（iOS）", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      true, // 由 ASAuthorizationController 在客户端完成
		ProvidesEmail:  true,
		ProvidesPhone:  false,
		SupportsUnbind: true,
	}, logger)
}

// NewWeb 构造 Web 登录（Services ID）。
func NewWeb(logger *zap.Logger) *Adapter {
	return newAdapter(provider.SceneWeb, "Apple 登录（Web）", provider.CapabilitySet{
		ServerSideFlow: true,
		Immediate:      false,
		ProvidesEmail:  true,
		ProvidesPhone:  false,
		SupportsUnbind: true,
	}, logger)
}

func newAdapter(scene, display string, caps provider.CapabilitySet, logger *zap.Logger) *Adapter {
	hc := httpx.New(httpx.Config{
		Name:         "apple-" + scene,
		TotalTimeout: apiTimeout,
		Logger:       logger,
	})
	return &Adapter{
		meta: provider.Metadata{
			Platform:     provider.PlatformApple,
			Scene:        scene,
			DisplayName:  display,
			APIVersion:   "appleid-v1",
			Capabilities: caps,
		},
		http:          hc,
		secretCache:   make(map[string]cachedSecret),
		jwks:          newJWKSCache(defaultJWKSURL, hc),
		notifyJWKSURL: defaultJWKSURL,
	}
}

func init() {
	provider.Register(NewApp(nil))
	provider.Register(NewWeb(nil))
}

var _ provider.Provider = (*Adapter)(nil)

// Metadata 返回渠道描述。
func (a *Adapter) Metadata() provider.Metadata { return a.meta }

func (a *Adapter) jwksURL(creds provider.Credentials) string {
	if v := creds.String(cfgJWKSURL); v != "" {
		return v
	}
	return defaultJWKSURL
}

// AuthURL 生成授权地址。
func (a *Adapter) AuthURL(_ context.Context, req provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	if req.Creds.ProviderAppID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "Apple 渠道缺少 provider_app_id（client_id）")
	}
	if a.meta.Scene != provider.SceneWeb {
		// iOS 由 ASAuthorizationController 拉起，服务端无跳转地址。
		return &provider.AuthorizeResult{
			Immediate: true,
			Params: map[string]string{
				"sdk":    "apple",
				"method": "ASAuthorizationAppleIDProvider",
				// nonce 必须由客户端带进授权请求，并在回调的 id_token 里原样返回。
				"nonce": req.Nonce,
			},
		}, nil
	}

	q := url.Values{}
	q.Set("client_id", req.Creds.ProviderAppID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("response_type", "code id_token")
	q.Set("response_mode", "form_post")
	q.Set("scope", "name email")
	q.Set("state", req.State)
	if req.Nonce != "" {
		q.Set("nonce", req.Nonce)
	}
	return &provider.AuthorizeResult{URL: appleIssuer + "/auth/authorize?" + q.Encode()}, nil
}

// --- client_secret ---

// clientSecret 返回缓存的 ES256 JWT；过期或不存在时重新签发。
func (a *Adapter) clientSecret(creds provider.Credentials) (string, error) {
	key := creds.ProviderAppID
	a.secretMu.Lock()
	if c, ok := a.secretCache[key]; ok && time.Now().Before(c.expiresAt) {
		a.secretMu.Unlock()
		return c.value, nil
	}
	a.secretMu.Unlock()

	teamID := creds.String(cfgTeamID)
	keyID := creds.String(cfgKeyID)
	if teamID == "" || keyID == "" {
		return "", errs.New(errs.CodeAuthInvalidConfig,
			"Apple 渠道缺少 team_id 或 key_id，无法签发 client_secret").
			WithDetail("hint", "extra 里配置 team_id 与 key_id，secret 里放置 .p8 私钥")
	}
	priv, err := parseP8(creds.Secret)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(clientSecretTTL).Unix(),
		"aud": appleIssuer,
		"sub": creds.ProviderAppID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = keyID
	signed, err := tok.SignedString(priv)
	if err != nil {
		return "", errs.Wrap(errs.CodeInternal, "签发 Apple client_secret 失败", err)
	}

	a.secretMu.Lock()
	a.secretCache[key] = cachedSecret{value: signed, expiresAt: now.Add(clientSecretTTL - time.Hour)}
	a.secretMu.Unlock()
	return signed, nil
}

// parseP8 解析 Apple 的 .p8 私钥（PKCS#8 的 EC 私钥）。
func parseP8(raw string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig,
			"Apple 私钥不是合法 PEM（应为 .p8 文件的原始内容）")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "解析 Apple .p8 私钥失败", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "Apple 私钥不是 EC 私钥（P-256）")
	}
	return ec, nil
}

// --- 令牌交换 ---

// idTokenClaims 是验签后的声明。
type idTokenClaims struct {
	Iss            string `json:"iss"`
	Aud            string `json:"aud"`
	Sub            string `json:"sub"`
	Email          string `json:"email"`
	EmailVerified  any    `json:"email_verified"`
	Nonce          string `json:"nonce"`
	IsPrivateEmail any    `json:"is_private_email"`
}

// Exchange 验证 id_token（优先）或用 code 换令牌。
func (a *Adapter) Exchange(ctx context.Context, req provider.ExchangeRequest) (*provider.TokenSet, error) {
	if req.Creds.ProviderAppID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "Apple 渠道缺少 client_id")
	}

	idToken := req.Extra["id_token"]
	if idToken == "" {
		// 没有 id_token 时退化到标准 authorization_code 流程（Web 场景常见）。
		var err error
		idToken, err = a.exchangeCode(ctx, req)
		if err != nil {
			return nil, err
		}
	}

	claims, err := a.verifyIDToken(ctx, req.Creds, idToken, req.Nonce)
	if err != nil {
		return nil, err
	}
	return &provider.TokenSet{
		IDToken: idToken,
		Raw: map[string]any{
			"sub":              claims.Sub,
			"email":            claims.Email,
			"email_verified":   claims.EmailVerified,
			"is_private_email": claims.IsPrivateEmail,
		},
	}, nil
}

// exchangeCode 用 authorization_code 换 id_token。
func (a *Adapter) exchangeCode(ctx context.Context, req provider.ExchangeRequest) (string, error) {
	secret, err := a.clientSecret(req.Creds)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("client_id", req.Creds.ProviderAppID)
	form.Set("client_secret", secret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	if req.RedirectURI != "" {
		form.Set("redirect_uri", req.RedirectURI)
	}

	var out struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	endpoint := req.Creds.String(cfgTokenURL)
	if endpoint == "" {
		endpoint = defaultTokenURL
	}
	if _, err := a.http.PostFormJSON(ctx, endpoint, form, &out); err != nil {
		return "", err
	}
	if out.Error != "" {
		// invalid_grant 通常是 code 已被使用或已过期——业务拒绝，不计入熔断。
		if out.Error == "invalid_grant" || out.Error == "invalid_request" {
			return "", errs.Newf(errs.CodeProviderRejected, "Apple 授权码无效: %s", out.ErrorDesc).
				WithDetail("apple_error", out.Error)
		}
		return "", errs.Newf(errs.CodeProviderUnavailable, "Apple 令牌交换失败: %s", out.ErrorDesc).
			WithDetail("apple_error", out.Error)
	}
	if out.IDToken == "" {
		return "", errs.New(errs.CodeProviderRejected, "Apple 未返回 id_token")
	}
	return out.IDToken, nil
}

// verifyIDToken 完成验签与声明校验。
func (a *Adapter) verifyIDToken(ctx context.Context, creds provider.Credentials, raw, expectNonce string) (*idTokenClaims, error) {
	kid, alg, err := jwtHeader(raw)
	if err != nil {
		return nil, err
	}
	if alg != "RS256" {
		// alg 必须是 RS256。接受其它算法等于允许 alg 混淆攻击。
		return nil, errs.Newf(errs.CodeAuthInvalidState, "Apple id_token 的签名算法必须是 RS256，实际=%s", alg).
			WithDetail("alg", alg)
	}

	pub, err := a.jwks.get(ctx, a.jwksURL(creds), kid)
	if err != nil {
		return nil, err
	}

	// 用 MapClaims 解析：jwt/v5 的 Claims 接口要求实现 6 个取值方法，
	// 为一份只读的声明集写这些样板没有收益；MapClaims 已原生支持
	// issuer / audience / exp 的校验，我们只需要把字段取出来。
	mc := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(appleIssuer),
		jwt.WithAudience(creds.ProviderAppID),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if _, err := parser.ParseWithClaims(raw, mc, func(t *jwt.Token) (any, error) {
		return pub, nil
	}); err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidState, "Apple id_token 验签或声明校验失败", err)
	}

	claims := &idTokenClaims{
		Iss:            strClaim(mc, "iss"),
		Aud:            strClaim(mc, "aud"),
		Sub:            strClaim(mc, "sub"),
		Email:          strClaim(mc, "email"),
		EmailVerified:  mc["email_verified"],
		Nonce:          strClaim(mc, "nonce"),
		IsPrivateEmail: mc["is_private_email"],
	}
	if claims.Sub == "" {
		return nil, errs.New(errs.CodeProviderRejected, "Apple id_token 缺少 sub")
	}

	// nonce 比对是防重放的关键：没有它，被截获的 id_token 可以反复登录。
	// 只在票据里确实生成过 nonce 时才强制比对（老票据可能没有）。
	if expectNonce != "" && claims.Nonce != expectNonce {
		return nil, errs.New(errs.CodeAuthInvalidNonce, "Apple id_token 的 nonce 与授权请求不一致")
	}
	return claims, nil
}

// UserInfo 从已验签的声明构造身份。
func (a *Adapter) UserInfo(_ context.Context, req provider.UserInfoRequest) (*provider.ExternalUser, error) {
	if req.Token == nil {
		return nil, errs.New(errs.CodeProviderRejected, "缺少令牌")
	}
	sub, _ := req.Token.Raw["sub"].(string)
	if sub == "" {
		return nil, errs.New(errs.CodeProviderRejected, "令牌上下文缺少 sub")
	}
	email, _ := req.Token.Raw["email"].(string)
	verified := boolClaimValue(req.Token.Raw["email_verified"])

	out := &provider.ExternalUser{
		// Apple 的 sub 是同一 App 内稳定的用户标识，语义等价于 openid。
		OpenID: sub,
		Email:  email,
		Raw: map[string]any{
			"sub":   sub,
			"email": email,
		},
	}
	if verified && email != "" {
		// 只有 Apple 明确标记已验证的邮箱才允许参与自动归并（R4 红线 1）。
		out.EmailVerifiedBy = "apple_email"
	}

	// 姓名只在首次授权返回，且不在 id_token 里，而是客户端单独回传的 JSON。
	if rawUser := req.Extra["user"]; rawUser != "" {
		out.Nickname = parseAppleName(rawUser)
	}
	return out, nil
}

// strClaim 从 MapClaims 取字符串（aud 可能是 string 或 []any）。
func strClaim(mc jwt.MapClaims, key string) string {
	switch v := mc[key].(type) {
	case string:
		return v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				return s
			}
		}
	}
	return ""
}

// audienceMatches 判断 JWT 的 aud 是否包含预期客户端标识。
//
// aud 按 JWT 规范可以是单个字符串，也可以是数组。只处理 string 会在
// 平台改成数组时把所有通知判为失败（且表现为"验签失败"，极难排查），
// 所以两种形态都必须支持。
func audienceMatches(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func boolClaimValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	default:
		return false
	}
}

// parseAppleName 解析首次授权回传的 user JSON：{"name":{"firstName":"三","lastName":"张"}}
func parseAppleName(raw string) string {
	var u struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return ""
	}
	return strings.TrimSpace(u.Name.LastName + u.Name.FirstName)
}

// Refresh Apple 不提供第三方刷新用户令牌的能力（refresh_token 只用于撤销）。
func (a *Adapter) Refresh(_ context.Context, _ provider.RefreshRequest) (*provider.TokenSet, error) {
	return nil, provider.NotSupported("refresh（Apple 的 refresh_token 仅用于撤销授权）")
}

// Unbind 调 Apple 的 revoke 端点撤销 refresh_token。
//
// 这是本服务里少数几个"平台侧真能解除授权"的渠道——解绑后用户下次需要重新授权。
func (a *Adapter) Unbind(ctx context.Context, req provider.UnbindRequest) error {
	token := req.Extra["refresh_token"]
	if token == "" {
		return provider.NotSupported("unbind（缺少 refresh_token，Apple 只能凭它撤销）")
	}
	secret, err := a.clientSecret(req.Creds)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("client_id", req.Creds.ProviderAppID)
	form.Set("client_secret", secret)
	form.Set("token", token)
	form.Set("token_type_hint", "refresh_token")

	endpoint := req.Creds.String(cfgRevokeURL)
	if endpoint == "" {
		endpoint = defaultRevokeURL
	}
	if _, err := a.http.PostFormJSON(ctx, endpoint, form, &struct{}{}); err != nil {
		return err
	}
	return nil
}

// Ping 探测 Apple 的 JWKS 端点。健康探测不参与熔断（§5.6.6）。
func (a *Adapter) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultJWKSURL, nil)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "构造健康探测请求失败", err)
	}
	resp, err := a.http.Do(ctx, req)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 500 {
		return errs.Newf(errs.CodeProviderUnavailable, "Apple JWKS 返回 %d", resp.StatusCode).
			WithDetail("platform", provider.PlatformApple)
	}
	return nil
}

// VerifyCallback 供 /v1/oauth/notify/{platform} 使用：校验 Apple 服务端通知的签名。
//
// Apple 的通知体是 JWT（与 id_token 同一套 JWKS），payload 里有 events 字段
// （consent-revoked / account-delete / email-disabled 等）。
func (a *Adapter) VerifyCallback(ctx context.Context, raw *provider.CallbackPayload) error {
	_, err := a.parseNotification(ctx, raw)
	return err
}

// ParseCallback 解析 Apple 服务端通知，归一化为 provider.CallbackEvent。
//
// 内部会先完成验签——解析未经验签的报文等于让任何人都能"替用户解绑"。
// 调用方即使已经单独调过 VerifyCallback，这里也会重算一次：验签开销是本地
// RSA 运算（微秒级），而"解析结果必须来自已验签的报文"是不能被调用方
// 使用姿势破坏的不变式。
func (a *Adapter) ParseCallback(ctx context.Context, raw *provider.CallbackPayload) (*provider.CallbackEvent, error) {
	return a.parseNotification(ctx, raw)
}

// parseNotification 是验签 + 解析的唯一实现，避免两处逻辑漂移。
func (a *Adapter) parseNotification(ctx context.Context, raw *provider.CallbackPayload) (*provider.CallbackEvent, error) {
	if raw == nil {
		return nil, errs.New(errs.CodeAuthInvalidState, "回调载荷为空")
	}
	body := strings.TrimSpace(string(raw.Body))
	token := body
	// form_post 模式下 body 是 form 编码，token 在 "payload" 字段里。
	if v, err := url.ParseQuery(body); err == nil {
		if p := v.Get("payload"); p != "" {
			token = p
		}
	}
	if token == "" {
		return nil, errs.New(errs.CodeAuthInvalidState, "Apple 通知缺少 payload")
	}

	kid, alg, err := jwtHeader(token)
	if err != nil {
		// 复用 jwtHeader 的解析逻辑，但换掉错误措辞：通知入口收到的是
		// 服务端通知而非 id_token，照抄原文会让排障同学去找登录链路。
		return nil, errs.New(errs.CodeAuthInvalidState, "Apple 通知报文不是合法的 JWT").
			WithDetail("parse_error", err.Error())
	}
	if alg != "RS256" {
		return nil, errs.Newf(errs.CodeAuthInvalidState, "Apple 通知签名算法必须是 RS256，实际=%s", alg)
	}
	// 通知里没有凭证上下文，用全局 JWKS（Apple 的 JWKS 与 tenant 无关）。
	pub, err := a.jwks.get(ctx, a.notifyJWKSURL, kid)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(appleIssuer),
		jwt.WithExpirationRequired(),
	)
	if _, err := parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return pub, nil
	}); err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidState, "Apple 通知验签失败", err)
	}

	// aud 比对：Apple 的 JWKS 是全局的，签名有效只证明"这条报文是 Apple 发的"，
	// 不证明"它是发给我们的"。少了这一步，别家 App 的通知可以被原样转发到我们
	// 的端点（重放），而我们会照着去解绑本地账号。
	if raw.Audience != "" && !audienceMatches(claims["aud"], raw.Audience) {
		return nil, errs.New(errs.CodeAuthInvalidState, "Apple 通知的 aud 与本应用 client_id 不一致").
			WithDetail("expected", raw.Audience).
			WithDetail("actual", strClaim(claims, "aud"))
	}

	// events 在 Apple 的报文里是【JSON 字符串】而不是嵌套对象。
	// 直接按 any 取会得到 string，再断言对象必然失败——这是最容易踩的坑。
	ev, err := decodeAppleEvents(claims["events"])
	if err != nil {
		return nil, err
	}

	out := &provider.CallbackEvent{
		Type:     normalizeAppleEventType(ev.Type),
		Platform: provider.PlatformApple,
		Scene:    raw.Scene,
		OpenID:   ev.Sub,
		Detail: map[string]any{
			"apple_event_type": ev.Type,
			// 【刻意不写】email 与 is_private_email：邮箱属于个人信息，
			// 审计表里的 detail 会被长期保留与检索，不必要地扩大暴露面。
			"jti": strClaim(claims, "jti"),
		},
	}
	if ev.EventTime > 0 {
		out.OccurredAt = time.Unix(ev.EventTime, 0).UTC()
	}
	return out, nil
}

// appleEvent 是 Apple 通知 events 字段的结构。
type appleEvent struct {
	Type      string `json:"type"`
	Sub       string `json:"sub"`
	EventTime int64  `json:"event_time"`
}

// decodeAppleEvents 兼容两种编码：JSON 字符串（Apple 实际格式）与嵌套对象
// （部分文档示例如此，平台也可能改）。只支持一种会在平台切换格式时全量失败。
func decodeAppleEvents(v any) (*appleEvent, error) {
	switch raw := v.(type) {
	case string:
		if raw == "" {
			return nil, errs.New(errs.CodeAuthInvalidState, "Apple 通知 events 为空")
		}
		var ev appleEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, errs.Wrap(errs.CodeAuthInvalidState, "Apple 通知 events 解析失败", err)
		}
		return &ev, nil
	case map[string]any:
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "Apple 通知 events 重编码失败", err)
		}
		var ev appleEvent
		if err := json.Unmarshal(b, &ev); err != nil {
			return nil, errs.Wrap(errs.CodeAuthInvalidState, "Apple 通知 events 解析失败", err)
		}
		return &ev, nil
	default:
		return nil, errs.New(errs.CodeAuthInvalidState, "Apple 通知缺少 events 字段")
	}
}

// normalizeAppleEventType 把 Apple 的连字符命名映射为本系统的下划线常量。
//
// 未知类型【不报错】，而是归为 unknown 让上层留痕：Apple 新增事件类型时，
// 我们宁可"收到但不处理"，也不能因为不认识就返回 5xx —— 那会让 Apple 认为
// 我们的端点坏了并在重试队列里堆积。
func normalizeAppleEventType(t string) string {
	switch t {
	case "consent-revoked":
		return provider.CallbackEventConsentRevoked
	case "account-delete":
		return provider.CallbackEventAccountDelete
	case "email-disabled":
		return provider.CallbackEventEmailDisabled
	default:
		return provider.CallbackEventUnknown
	}
}
