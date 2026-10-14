// Package acceptance 是第一期验收测试。
//
// 对应架构 §13 第一期的验收标准：
//
//	接入一个自建 OAuth2 测试服务，走通
//	"授权 → 回调 → 返回 NEED_REGISTER → 模拟业务方登录 → 绑定 → 签发令牌" 完整链路；
//	业务方能从 /v1/jwks 取公钥并成功验签
//
// 依赖真实的 PostgreSQL 与 Redis（部分唯一索引、隔离回调、票据的一次性语义
// 都无法用内存桩验证），通过环境变量指定，未提供时使用本地默认值：
//
//	TEST_DATABASE_URL  (默认 postgres://postgres:postgres@127.0.0.1:5432/social_login?sslmode=disable)
//	TEST_REDIS_ADDR    (默认 127.0.0.1:6379)
package acceptance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/17track/social-login/internal/bootstrap"
	"github.com/17track/social-login/internal/domain/provider"
	"github.com/17track/social-login/internal/domain/tenant"
	"github.com/17track/social-login/internal/infrastructure/crypto"
	"github.com/17track/social-login/internal/infrastructure/persistence/postgres"
	"github.com/17track/social-login/internal/pkg/appctx"
	"github.com/17track/social-login/internal/pkg/ids"
	"github.com/17track/social-login/internal/testsupport/mockoauth2"
)

const (
	testAppSecret = "test-app-secret-0123456789"
	// 业务方回跳地址，必须命中应用白名单。
	testRedirectURI = "http://business.example.com/callback"
	// 平台侧客户端凭据。
	testProviderClientID     = "mock-client"
	testProviderClientSecret = "mock-secret"
)

// harness 是一次完整的运行实例。
type harness struct {
	t *testing.T

	app       *bootstrap.App
	server    *httptest.Server
	serverURL string
	mock      *mockoauth2.Server
	// mockBaseURL 是自建 OAuth2 测试服务的地址，写入渠道配置的端点里。
	mockBaseURL string

	appCode  string
	appID    int64
	db       *postgres.AppRepository
	http     *http.Client
	identity string // mock 平台返回的用户标识
}

// newHarness 装配一次完整运行实例。
func newHarness(t *testing.T) *harness {
	t.Helper()

	// 1) 自建 OAuth2 测试服务。
	mock := mockoauth2.New(mockoauth2.Config{
		ClientID:     testProviderClientID,
		ClientSecret: testProviderClientSecret,
		DefaultProfile: mockoauth2.Profile{
			Subject: "mock-user-acceptance",
			Name:    "验收测试用户",
			Email:   "acceptance@example.com",
			Picture: "https://example.com/a.png",
		},
	})
	mockSrv := httptest.NewServer(mock.Handler())
	t.Cleanup(mockSrv.Close)

	// 2) 预留本服务的监听端口：必须在装配前知道自己的对外地址，
	//    因为 callback_base_url 会参与三方回调地址的拼接。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("预留监听端口失败: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	cfg := &bootstrap.Config{}
	cfg.Server.Addr = ln.Addr().String()
	cfg.Server.Mode = "debug"
	cfg.Server.CallbackBaseURL = baseURL
	cfg.Server.Issuer = baseURL
	cfg.Server.ShutdownTimeout = 5 * time.Second
	cfg.Database.DSN = envOr("TEST_DATABASE_URL",
		"postgres://postgres:postgres@127.0.0.1:5432/social_login?sslmode=disable")
	cfg.Database.MaxOpenConns = 10
	cfg.Cache.Addr = envOr("TEST_REDIS_ADDR", "127.0.0.1:6379")
	cfg.Security.KEKID = "test-kek-v1"
	cfg.Security.ClaimSalt = "test-claim-salt"
	cfg.Security.AppSecretSalt = "test-app-secret-salt"
	cfg.JWT.AccessTokenTTL = 15 * time.Minute
	cfg.JWT.RefreshTokenTTL = time.Hour
	cfg.Account.Provider = "stub"
	cfg.Auth.Env = "test"
	cfg.Auth.ExchangeTimeout = 5 * time.Second
	cfg.Log.Level = "error"
	cfg.Log.Format = "console"
	cfg.Migrate.Enabled = true

	// 主密钥：测试内固定，保证多次运行之间写入的凭据可解密。
	masterKey, err := crypto.DecodeMasterKey("dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLWxvbmchISE=")
	if err != nil {
		// 长度不符时退化为随机生成（不影响本测试，因为每次运行都会重新写入渠道配置）。
		masterKey, err = crypto.GenerateMasterKey()
		if err != nil {
			t.Fatalf("生成主密钥失败: %v", err)
		}
	}
	cfg.Security.MasterKey = crypto.EncodeMasterKey(masterKey)

	// 3) 起真实依赖；不可用时明确跳过而不是伪装通过。
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeDatabase(probeCtx, cfg.Database.DSN); err != nil {
		t.Skipf("跳过验收测试：PostgreSQL 不可用 (%v)", err)
	}
	if err := probeRedis(probeCtx, cfg.Cache.Addr); err != nil {
		t.Skipf("跳过验收测试：Redis 不可用 (%v)", err)
	}

	app, err := bootstrap.New(context.Background(), bootstrap.Options{
		Config: cfg,
		Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("装配运行实例失败: %v", err)
	}

	srv := httptest.NewUnstartedServer(app.Router())
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	h := &harness{
		t:           t,
		app:         app,
		server:      srv,
		serverURL:   baseURL,
		mock:        mock,
		mockBaseURL: mockSrv.URL,
		appCode:     newAppCode("app_acc"),
		http: &http.Client{
			// 验收要检查每一跳的 Location，因此禁止自动跟随重定向。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 10 * time.Second,
		},
		identity: "mock-user-acceptance",
	}
	h.seed()
	t.Cleanup(func() { _ = app.Shutdown(context.Background()) })
	return h
}

// seed 写入业务应用与渠道配置。
func (h *harness) seed() {
	h.t.Helper()
	ctx := context.Background()

	cfg := h.app.Config()
	masterKey, err := crypto.DecodeMasterKey(cfg.Security.MasterKey)
	if err != nil {
		h.t.Fatalf("解析主密钥失败: %v", err)
	}
	keyManager, err := crypto.NewKeyManager(cfg.Security.KEKID, masterKey)
	if err != nil {
		h.t.Fatalf("初始化加密器失败: %v", err)
	}
	secretHasher := crypto.NewAppSecretHasher([]byte(cfg.Security.AppSecretSalt))

	appRepo := postgres.NewAppRepository(h.app.DB())
	policy := tenant.DefaultPolicy()
	// 默认 need_register：这正是验收要覆盖的分支。
	policy.OnUnboundLogin = tenant.OnUnboundNeedRegister
	policy.Merge.Mode = tenant.MergeModeConfirm
	policy.Merge.Verification = tenant.VerificationSMS
	policy.AllowedRedirectURIs = []string{testRedirectURI}

	app, err := appRepo.Upsert(ctx, &tenant.Application{
		AppCode:       h.appCode,
		Name:          "验收测试应用",
		AppSecretHash: secretHasher.Hash(testAppSecret),
		Status:        1,
		AccountMode:   tenant.AccountModeRemote,
		Policy:        policy,
	})
	if err != nil {
		h.t.Fatalf("写入应用失败: %v", err)
	}
	h.appID = app.ID
	h.db = appRepo

	encSecret, err := keyManager.Encrypt(testProviderClientSecret)
	if err != nil {
		h.t.Fatalf("加密渠道凭据失败: %v", err)
	}
	configRepo := postgres.NewProviderConfigRepository(h.app.DB())
	_, err = configRepo.Upsert(ctx, &tenant.ProviderConfig{
		AppID:         app.ID,
		Platform:      provider.PlatformGenericOAuth2,
		Scene:         provider.SceneWeb,
		ConfigKey:     postgres.DefaultConfigKey,
		ProviderAppID: testProviderClientID,
		SecretCipher:  encSecret,
		SecretDEKID:   keyManager.KEKID(),
		Env:           cfg.Auth.Env,
		Extra: map[string]any{
			"authorize_url": h.mockURL() + "/oauth/authorize",
			"token_url":     h.mockURL() + "/oauth/token",
			"userinfo_url":  h.mockURL() + "/oauth/userinfo",
			"scopes":        []any{"openid", "profile", "email"},
			"field_open_id": "sub",
			// 声明 email 为平台已验证来源（取值须为 identity 包的权威枚举）。
			// 没有它，邮箱会被记录但永不参与自动归并（R4 红线 1）。
			"email_verified_by": "apple_email",
		},
		Status: 1,
	})
	if err != nil {
		h.t.Fatalf("写入渠道配置失败: %v", err)
	}
}

func (h *harness) mockURL() string { return h.mockBaseURL }

// newAppCode 生成带随机部分的唯一应用标识。
//
// ⚠️ 不能用 ULID()[:8]：ULID 前 48 位是时间戳，前 10 个字符随时间单调递增，
// 取前 8 位会让"同一秒内创建的不同应用"拿到相同的 app_code——
// 这会让测试之间互相污染数据，而且是那种"单跑通过、连跑失败"的隐蔽故障。
// 必须取尾部的随机部分。
func newAppCode(prefix string) string {
	u := strings.ToLower(ids.ULID())
	return prefix + "_" + u[len(u)-10:]
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func probeDatabase(ctx context.Context, dsn string) error {
	db, err := postgres.Open(ctx, postgres.Config{DSN: dsn, MaxOpenConns: 2}, nil)
	if err != nil {
		return err
	}
	return postgres.Close(db)
}

func probeRedis(ctx context.Context, addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// --- HTTP 辅助 ---

func (h *harness) getNoRedirect(rawURL string) *http.Response {
	h.t.Helper()
	resp, err := h.http.Get(rawURL)
	if err != nil {
		h.t.Fatalf("GET %s 失败: %v", rawURL, err)
	}
	return resp
}

func (h *harness) postJSON(path string, headers map[string]string, body any) (*http.Response, map[string]any) {
	h.t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		h.t.Fatalf("序列化请求体失败: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.serverURL+path, bytes.NewReader(buf))
	if err != nil {
		h.t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatalf("POST %s 失败: %v", path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var decoded map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return resp, decoded
}

func (h *harness) getJSON(path string, headers map[string]string) (*http.Response, map[string]any) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.serverURL+path, nil)
	if err != nil {
		h.t.Fatalf("构造请求失败: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s 失败: %v", path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var decoded map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return resp, decoded
}

func (h *harness) appHeaders() map[string]string {
	return map[string]string{
		"X-App-Id":     h.appCode,
		"X-App-Secret": testAppSecret,
	}
}

// authorizeAndCallback 走完 authorize → 三方授权 → 回调，返回回调的 Location。
func (h *harness) authorizeAndCallback(mode string, bearer string) string {
	h.t.Helper()

	q := url.Values{}
	q.Set("app_id", h.appCode)
	q.Set("platform", provider.PlatformGenericOAuth2)
	q.Set("scene", provider.SceneWeb)
	q.Set("mode", mode)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("state", "biz-state-123")
	q.Set("client", provider.ClientMiniProgram) // 承载形态仅遥测，不参与路由
	q.Set("response_mode", "json")

	req, err := http.NewRequest(http.MethodGet, h.serverURL+"/v1/authorize?"+q.Encode(), nil)
	if err != nil {
		h.t.Fatalf("构造 authorize 请求失败: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatalf("authorize 失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("authorize 期望 200，实际 %d：%s", resp.StatusCode, body)
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		h.t.Fatalf("解析 authorize 响应失败: %v (%s)", err, body)
	}
	if out.RedirectURL == "" {
		h.t.Fatalf("authorize 未返回 redirect_url: %s", body)
	}

	// 到自建 OAuth2 服务完成授权。mock 会立即回跳，Location 即我们的回调地址。
	providerResp := h.getNoRedirect(out.RedirectURL)
	callbackURL := providerResp.Header.Get("Location")
	providerResp.Body.Close()
	if callbackURL == "" {
		h.t.Fatalf("自建 OAuth2 服务未返回回跳地址，状态码 %d", providerResp.StatusCode)
	}

	// 调我们的回调地址。
	cbResp := h.getNoRedirect(callbackURL)
	loc := cbResp.Header.Get("Location")
	cbResp.Body.Close()
	if loc == "" {
		h.t.Fatalf("回调未返回 Location（状态码 %d）", cbResp.StatusCode)
	}
	return loc
}

func mustQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("解析回跳地址失败: %v (%s)", err, rawURL)
	}
	return u.Query()
}

// --- 测试 ---

// TestFullFlowNeedRegisterToToken 是第一期验收的主用例。
func TestFullFlowNeedRegisterToToken(t *testing.T) {
	h := newHarness(t)

	// ① 授权 + 回调：默认 policy=need_register，因此应回跳 NEED_REGISTER 与 bind_ticket。
	loc := h.authorizeAndCallback(provider.ModeLogin, "")
	q := mustQuery(t, loc)
	if got := q.Get("error"); got != "AUTH.NEED_REGISTER" {
		t.Fatalf("期望 AUTH.NEED_REGISTER，实际 error=%q（Location=%s）", got, loc)
	}
	bindTicket := q.Get("bind_ticket")
	if bindTicket == "" {
		t.Fatalf("NEED_REGISTER 分支必须返回 bind_ticket（Location=%s）", loc)
	}
	if got := q.Get("state"); got != "biz-state-123" {
		t.Fatalf("业务侧 state 必须原样回传，实际 %q", got)
	}

	// ② 模拟业务方完成注册/登录，带 bind_ticket 调 /v1/bind。
	const businessUserID = "u_biz_10001"
	resp, body := h.postJSON("/v1/bind", h.appHeaders(), map[string]any{
		"bind_ticket":      bindTicket,
		"external_user_id": businessUserID,
		"device_id":        "dev-acceptance",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/bind 期望 200，实际 %d：%v", resp.StatusCode, body)
	}
	tokenObj, ok := body["token"].(map[string]any)
	if !ok {
		t.Fatalf("/v1/bind 未返回令牌: %v", body)
	}
	accessToken, _ := tokenObj["access_token"].(string)
	refreshToken, _ := tokenObj["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("绑定成功后必须同时签发 access_token 与 refresh_token: %v", tokenObj)
	}
	if sub, _ := tokenObj["sub"].(string); sub != businessUserID {
		t.Fatalf("sub 必须等于业务方账号标识（约束 C4），实际 %q", sub)
	}

	// ③ 业务方从 /v1/jwks 取公钥本地验签（验收标准明确要求）。
	verifyWithJWKS(t, h, accessToken, businessUserID, h.appCode)

	// ④ introspect：应返回 active 以及 sub/scope。
	resp, ires := h.postJSON("/v1/introspect", h.appHeaders(), map[string]any{"token": accessToken})
	if resp.StatusCode != http.StatusOK || ires["active"] != true {
		t.Fatalf("introspect 期望 active=true，实际 %d：%v", resp.StatusCode, ires)
	}
	if sub, _ := ires["sub"].(string); sub != businessUserID {
		t.Fatalf("introspect 的 sub 错误: %v", ires["sub"])
	}

	// ⑤ userinfo：应能查到刚建立的绑定。
	resp, uinfo := h.getJSON("/v1/userinfo", mergeHeaders(h.appHeaders(), map[string]string{
		"Authorization": "Bearer " + accessToken,
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/userinfo 期望 200，实际 %d：%v", resp.StatusCode, uinfo)
	}
	bindings, ok := uinfo["bindings"].([]any)
	if !ok || len(bindings) != 1 {
		t.Fatalf("期望 1 条绑定，实际 %v", uinfo["bindings"])
	}

	// ⑥ 第二次登录同一身份：已有活跃绑定，应直接签发 auth_code 而不走 NEED_REGISTER。
	loc2 := h.authorizeAndCallback(provider.ModeLogin, "")
	q2 := mustQuery(t, loc2)
	if errCode := q2.Get("error"); errCode != "" {
		t.Fatalf("已有绑定时不应返回错误，实际 error=%q（Location=%s）", errCode, loc2)
	}
	code := q2.Get("code")
	if code == "" {
		t.Fatalf("已有绑定时应返回 auth_code（Location=%s）", loc2)
	}

	// ⑦ 用 auth_code 换令牌。
	resp, tok := h.postJSON("/v1/token", nil, map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     h.appCode,
		"client_secret": testAppSecret,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/token 期望 200，实际 %d：%v", resp.StatusCode, tok)
	}
	access2, _ := tok["access_token"].(string)
	refresh2, _ := tok["refresh_token"].(string)
	if access2 == "" || refresh2 == "" {
		t.Fatalf("换令牌未返回完整令牌对: %v", tok)
	}
	if q2.Get("state") != "biz-state-123" {
		t.Fatalf("业务侧 state 未原样回传: %s", loc2)
	}

	// ⑧ auth_code 是一次性的：重放必须失败。
	resp, again := h.postJSON("/v1/token", nil, map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     h.appCode,
		"client_secret": testAppSecret,
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("授权码重放必须失败，实际成功: %v", again)
	}
	if got, _ := again["code"].(string); got != "AUTH.INVALID_STATE" {
		t.Fatalf("授权码重放期望 AUTH.INVALID_STATE，实际 %v", again)
	}
	if retryable, ok := again["retryable"].(bool); !ok || retryable {
		t.Fatalf("AUTH.INVALID_STATE 必须是 retryable=false（约束 C6 的错误契约）: %v", again)
	}
}

// TestRefreshTokenRotationAndReuseDetection 验证 §8.2 的轮转与重放检测。
func TestRefreshTokenRotationAndReuseDetection(t *testing.T) {
	h := newHarness(t)
	_, first := h.bindOnce(t, "u_rotate_1")

	rt1 := first["refresh_token"].(string)

	// 第一次刷新：应换出新令牌。
	resp, second := h.postJSON("/v1/token", nil, map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     h.appCode,
		"client_secret": testAppSecret,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("刷新期望 200，实际 %d：%v", resp.StatusCode, second)
	}
	rt2, _ := second["refresh_token"].(string)
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("刷新必须轮转出新的 refresh_token，实际 old=%q new=%q", rt1, rt2)
	}

	// 重放旧令牌：必须触发 reuse detection，并撤销整条链。
	resp, replay := h.postJSON("/v1/token", nil, map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     h.appCode,
		"client_secret": testAppSecret,
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("重放已轮转的 refresh_token 必须失败，实际成功: %v", replay)
	}
	if got, _ := replay["code"].(string); got != "TOKEN.REVOKED" {
		t.Fatalf("重放期望 TOKEN.REVOKED，实际 %v", replay)
	}

	// 整条链被撤销后，新令牌也必须失效。
	resp, after := h.postJSON("/v1/token", nil, map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt2,
		"client_id":     h.appCode,
		"client_secret": testAppSecret,
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("重放检测后整条链应失效，但 rt2 仍可用: %v", after)
	}
}

// TestAppIsolation 验证约束 C1：同一平台身份在不同业务应用中是两套数据。
func TestAppIsolation(t *testing.T) {
	h := newHarness(t)
	_, first := h.bindOnce(t, "u_iso_shared")

	// 第二个业务应用，接入同一个 mock 平台、同一个平台侧 appid。
	secondAppCode := h.createSecondApp(t)

	q := url.Values{}
	q.Set("app_id", secondAppCode)
	q.Set("platform", provider.PlatformGenericOAuth2)
	q.Set("scene", provider.SceneWeb)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("response_mode", "json")
	resp, err := h.http.Get(h.serverURL + "/v1/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("第二个应用发起授权失败: %v", err)
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解析失败: %v (%s)", err, raw)
	}
	providerResp := h.getNoRedirect(out.RedirectURL)
	providerResp.Body.Close()
	cbResp := h.getNoRedirect(providerResp.Header.Get("Location"))
	loc := cbResp.Header.Get("Location")
	cbResp.Body.Close()

	// 第二个应用下，同一 mock 用户应是【未绑定】状态（NEED_REGISTER），
	// 而不是复用第一个应用的绑定。
	if got := mustQuery(t, loc).Get("error"); got != "AUTH.NEED_REGISTER" {
		t.Fatalf("第二个应用下同一平台用户必须是未绑定状态（约束 C1 隔离），实际 error=%q", got)
	}

	// 且第一个应用的令牌在第二个应用下不可用（aud 校验）。
	access := first["access_token"].(string)
	resp2, ires := h.postJSON("/v1/introspect", map[string]string{
		"X-App-Id":     secondAppCode,
		"X-App-Secret": testAppSecret,
	}, map[string]any{"token": access})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("introspect 期望 200，实际 %d: %v", resp2.StatusCode, ires)
	}
	if ires["active"] != false {
		t.Fatalf("跨应用的令牌必须校验失败（iss/aud），实际 active=%v", ires["active"])
	}
}

// TestAuthorizationRejectsUnlistedRedirectURI 验证开放重定向防护。
//
// 断言两件事，缺一不可：
//  1. 不在白名单的地址被拒绝，且【不返回 302】——一旦回跳，本服务就成了
//     开放重定向器，攻击者可把一次性 auth_code 骗到自己的域名。
//  2. 错误码是 REQUEST.INVALID（4xx）而不是 AUTH.INVALID_CONFIG（5xx）：
//     该应用【已配置】白名单，所以这是调用方的参数问题，不该触发值班告警。
//     只有"应用完全没配白名单"才属于我们的配置缺陷（见下面的反向用例）。
func TestAuthorizationRejectsUnlistedRedirectURI(t *testing.T) {
	h := newHarness(t)

	q := url.Values{}
	q.Set("app_id", h.appCode)
	q.Set("platform", provider.PlatformGenericOAuth2)
	q.Set("scene", provider.SceneWeb)
	q.Set("redirect_uri", "http://evil.example.com/steal")
	resp, err := h.http.Get(h.serverURL + "/v1/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Fatalf("未在白名单内的 redirect_uri 必须被拒绝，实际返回了 302")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("调用方参数问题应返回 4xx，实际 %d：%s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "REQUEST.INVALID") {
		t.Fatalf("期望 REQUEST.INVALID，实际 %s", raw)
	}

	// 反向用例：应用完全没配白名单时，属于我们的配置缺陷，必须是 5xx。
	if err := h.clearRedirectWhitelist(); err != nil {
		t.Fatalf("清空白名单失败: %v", err)
	}
	resp2, err := h.http.Get(h.serverURL + "/v1/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("未配置白名单属于服务端配置问题，应返回 5xx，实际 %d：%s", resp2.StatusCode, raw2)
	}
	if !strings.Contains(string(raw2), "AUTH.INVALID_CONFIG") {
		t.Fatalf("期望 AUTH.INVALID_CONFIG，实际 %s", raw2)
	}
}

// clearRedirectWhitelist 把应用的白名单清空，构造"配置缺失"的场景。
func (h *harness) clearRedirectWhitelist() error {
	ctx := context.Background()
	appRepo := postgres.NewAppRepository(h.app.DB())
	app, err := appRepo.FindByID(ctx, h.appID)
	if err != nil {
		return err
	}
	app.Policy.AllowedRedirectURIs = nil
	// 注意：白名单为空时 Validate 本身是合法的（它校验的是合并策略），
	// 拦截发生在 Authorize 阶段——这正是"失败关闭"的落点。
	_, err = appRepo.Upsert(ctx, app)
	return err
}

// TestAppScopeCallbackEnforced 验证 §9.1 的隔离机制本身。
//
// 这条测试的价值在于：它验证的不是业务行为，而是【机制是否真的生效】。
// 隔离回调一旦被误删、或注册顺序被改坏（比如被挪到 gorm:query 之后），
// 所有业务测试仍然会通过——因为仓储层自己也会显式带上 app_id。
// 只有绕过仓储、直接用 GORM 打表，才能真正测到回调。
//
// 顺带说明为什么要有两层：
//   - 仓储层显式写 app_id：让 SQL 可读，且不依赖回调的隐式行为
//   - 全局回调强制注入：保证任何"漏写"的查询也拿不到别的应用的数据
//
// 少了第二层，一次 code review 的疏忽就是一次线上串号。
func TestAppScopeCallbackEnforced(t *testing.T) {
	h := newHarness(t)
	db := h.app.DB()

	// ① 无作用域：必须 panic。
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatalf("缺少 app_id 作用域时必须 panic，实际正常返回")
			}
			msg := fmt.Sprint(r)
			if !strings.Contains(msg, "app_id 隔离缺失") {
				t.Fatalf("panic 信息应指明隔离缺失，实际: %s", msg)
			}
		}()
		var rows []map[string]any
		// 直接打表，绕过仓储。
		_ = db.WithContext(context.Background()).Table("oauth_identities").Find(&rows).Error
	}()

	// ② 带作用域：应正常执行。
	var rows []map[string]any
	err := db.WithContext(appctx.WithAppScope(context.Background(), h.appID)).
		Table("oauth_identities").Find(&rows).Error
	if err != nil {
		t.Fatalf("带作用域的查询不应失败: %v", err)
	}

	// ③ 显式跨应用：应正常执行（管理端路径，代码里可见的一次声明）。
	err = db.WithContext(appctx.WithCrossAppScope(context.Background())).
		Table("oauth_identities").Find(&rows).Error
	if err != nil {
		t.Fatalf("显式跨应用查询不应失败: %v", err)
	}
}

// --- 辅助 ---

func (h *harness) bindOnce(t *testing.T, businessUserID string) (*http.Response, map[string]any) {
	t.Helper()
	loc := h.authorizeAndCallback(provider.ModeLogin, "")
	q := mustQuery(t, loc)
	ticket := q.Get("bind_ticket")
	if ticket == "" {
		t.Fatalf("期望 NEED_REGISTER + bind_ticket，实际 Location=%s", loc)
	}
	resp, body := h.postJSON("/v1/bind", h.appHeaders(), map[string]any{
		"bind_ticket":      ticket,
		"external_user_id": businessUserID,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/bind 期望 200，实际 %d：%v", resp.StatusCode, body)
	}
	tokens, _ := body["token"].(map[string]any)
	return resp, tokens
}

// createSecondApp 创建第二个业务应用，复用同一份渠道配置。
func (h *harness) createSecondApp(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	cfg := h.app.Config()

	masterKey, err := crypto.DecodeMasterKey(cfg.Security.MasterKey)
	if err != nil {
		t.Fatalf("解析主密钥失败: %v", err)
	}
	keyManager, err := crypto.NewKeyManager(cfg.Security.KEKID, masterKey)
	if err != nil {
		t.Fatalf("初始化加密器失败: %v", err)
	}
	secretHasher := crypto.NewAppSecretHasher([]byte(cfg.Security.AppSecretSalt))

	appCode := newAppCode("app_iso")
	policy := tenant.DefaultPolicy()
	policy.AllowedRedirectURIs = []string{testRedirectURI}

	appRepo := postgres.NewAppRepository(h.app.DB())
	app, err := appRepo.Upsert(ctx, &tenant.Application{
		AppCode:       appCode,
		Name:          "隔离测试应用",
		AppSecretHash: secretHasher.Hash(testAppSecret),
		Status:        1,
		AccountMode:   tenant.AccountModeRemote,
		Policy:        policy,
	})
	if err != nil {
		t.Fatalf("创建第二个应用失败: %v", err)
	}

	encSecret, err := keyManager.Encrypt(testProviderClientSecret)
	if err != nil {
		t.Fatalf("加密凭据失败: %v", err)
	}
	configRepo := postgres.NewProviderConfigRepository(h.app.DB())
	// 刻意复用【同一个】provider_app_id：验证隔离不依赖平台侧 appid 不同，
	// 即使两个业务应用接的是同一个公众号，身份也必须是两条独立记录。
	_, err = configRepo.Upsert(ctx, &tenant.ProviderConfig{
		AppID:         app.ID,
		Platform:      provider.PlatformGenericOAuth2,
		Scene:         provider.SceneWeb,
		ConfigKey:     postgres.DefaultConfigKey,
		ProviderAppID: testProviderClientID,
		SecretCipher:  encSecret,
		SecretDEKID:   keyManager.KEKID(),
		Env:           cfg.Auth.Env,
		Extra: map[string]any{
			"authorize_url": h.mockURL() + "/oauth/authorize",
			"token_url":     h.mockURL() + "/oauth/token",
			"userinfo_url":  h.mockURL() + "/oauth/userinfo",
			"field_open_id": "sub",
		},
		Status: 1,
	})
	if err != nil {
		t.Fatalf("写入第二个应用的渠道配置失败: %v", err)
	}
	return appCode
}

// verifyWithJWKS 用 /v1/jwks 发布的公钥在本地验签。
//
// 这模拟的正是业务方的验签路径：只在启动时拉一次 JWKS 并缓存，
// 之后所有令牌校验都不产生网络请求。
func verifyWithJWKS(t *testing.T, h *harness, token, wantSub, wantAud string) {
	t.Helper()

	resp, err := h.http.Get(h.serverURL + "/v1/jwks")
	if err != nil {
		t.Fatalf("获取 JWKS 失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS 期望 200，实际 %d", resp.StatusCode)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 JWKS 失败: %v (%s)", err, raw)
	}
	if len(doc.Keys) == 0 {
		t.Fatalf("JWKS 不含任何公钥: %s", raw)
	}

	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			t.Fatalf("期望 EC/P-256 公钥，实际 %s/%s", k.Kty, k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			t.Fatalf("解析公钥 X 失败: %v", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			t.Fatalf("解析公钥 Y 失败: %v", err)
		}
		keys[k.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("未知 kid: %s", kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("本地验签失败: %v", err)
	}
	if sub, _ := claims["sub"].(string); sub != wantSub {
		t.Fatalf("验签成功但 sub 不符: 期望 %s，实际 %v", wantSub, claims["sub"])
	}
	aud, _ := claims["aud"].(string)
	if aud == "" {
		if list, ok := claims["aud"].([]any); ok && len(list) > 0 {
			aud, _ = list[0].(string)
		}
	}
	if aud != wantAud {
		t.Fatalf("aud 期望 %s，实际 %v", wantAud, claims["aud"])
	}
	if amr, ok := claims["amr"].([]any); !ok || len(amr) == 0 {
		t.Fatalf("amr 应记录认证方式，实际 %v", claims["amr"])
	}
}

func mergeHeaders(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
