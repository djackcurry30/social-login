package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/djackcurry30/social-login/internal/domain/provider"
)

const testKid = "test-kid-1"

// jwksServer 起一个假的 Apple JWKS 端点。
func jwksServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": testKid, "use": "sig", "alg": "RS256", "n": n, "e": e},
			},
		})
	}))
}

// makeIDToken 用测试私钥签一个 Apple 风格的 id_token。
func makeIDToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func baseClaims(clientID string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            appleIssuer,
		"aud":            clientID,
		"sub":            "001234.abcdef.1234",
		"email":          "user@privaterelay.appleid.com",
		"email_verified": "true",
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func testCreds(jwksURL string) provider.Credentials {
	return provider.Credentials{
		ProviderAppID: "com.example.client",
		Extra:         map[string]any{"jwks_url": jwksURL},
	}
}

func TestRegisteredScenes(t *testing.T) {
	want := map[string]bool{"apple:app": false, "apple:web": false}
	for _, m := range provider.Global().List() {
		if _, ok := want[m.Key()]; ok {
			want[m.Key()] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Fatalf("场景未注册: %s", k)
		}
	}
}

func TestIOSAuthURLIsImmediateWithNonce(t *testing.T) {
	a := NewApp(nil)
	res, err := a.AuthURL(context.Background(), provider.AuthorizeRequest{
		Creds: provider.Credentials{ProviderAppID: "com.example.client"},
		Nonce: "nonce-abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Immediate {
		t.Fatal("iOS 场景应为 Immediate（由 ASAuthorizationController 拉起）")
	}
	if res.Params["nonce"] != "nonce-abc" {
		t.Fatalf("nonce 必须交给客户端带进授权请求，实际=%v", res.Params)
	}
}

func TestWebAuthURL(t *testing.T) {
	a := NewWeb(nil)
	res, err := a.AuthURL(context.Background(), provider.AuthorizeRequest{
		Creds:       provider.Credentials{ProviderAppID: "com.example.client"},
		RedirectURI: "https://biz.example.com/cb",
		State:       "ticket-1",
		Nonce:       "n-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/auth/authorize", "response_mode=form_post", "nonce=n-1", "state=ticket-1"} {
		if !strings.Contains(res.URL, want) {
			t.Fatalf("授权 URL 缺少 %q: %s", want, res.URL)
		}
	}
}

func TestExchangeVerifiesIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksServer(t, key)
	defer srv.Close()

	idToken := makeIDToken(t, key, baseClaims("com.example.client"))
	a := NewApp(nil)
	ts, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: testCreds(srv.URL),
		Code:  "code-1",
		Extra: map[string]string{"id_token": idToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ts.Raw["sub"] != "001234.abcdef.1234" {
		t.Fatalf("sub 未写入 Raw: %v", ts.Raw)
	}
}

// TestExchangeRejectsNonceMismatch 是防重放的核心用例。
// 没有这一条，被截获的 id_token 可以无限次重放登录。
func TestExchangeRejectsNonceMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key)
	defer srv.Close()

	claims := baseClaims("com.example.client")
	claims["nonce"] = "nonce-from-earlier-flow"
	idToken := makeIDToken(t, key, claims)

	a := NewApp(nil)
	_, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: testCreds(srv.URL),
		Code:  "code-1",
		Nonce: "nonce-of-this-flow",
		Extra: map[string]string{"id_token": idToken},
	})
	if err == nil {
		t.Fatal("nonce 不一致必须拒绝")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("错误应指明 nonce: %v", err)
	}
}

func TestExchangeRejectsWrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key)
	defer srv.Close()

	idToken := makeIDToken(t, key, baseClaims("com.other.client"))
	a := NewApp(nil)
	if _, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: testCreds(srv.URL),
		Code:  "c",
		Extra: map[string]string{"id_token": idToken},
	}); err == nil {
		t.Fatal("aud 不匹配必须拒绝（否则别家 App 的 token 能登进我们）")
	}
}

func TestExchangeRejectsExpiredToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key)
	defer srv.Close()

	claims := baseClaims("com.example.client")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	idToken := makeIDToken(t, key, claims)

	a := NewApp(nil)
	if _, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: testCreds(srv.URL),
		Code:  "c",
		Extra: map[string]string{"id_token": idToken},
	}); err == nil {
		t.Fatal("过期 token 必须拒绝")
	}
}

// TestUserInfoMarksVerifiedEmail 验证只有 email_verified 才允许参与自动归并（R4）。
func TestUserInfoMarksVerifiedEmail(t *testing.T) {
	a := NewApp(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		Token: &provider.TokenSet{Raw: map[string]any{
			"sub":            "001234",
			"email":          "a@privaterelay.appleid.com",
			"email_verified": "true",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.OpenID != "001234" {
		t.Fatalf("OpenID 应为 sub，实际=%q", user.OpenID)
	}
	if user.EmailVerifiedBy != "apple_email" {
		t.Fatalf("已验证邮箱应标记 apple_email，实际=%q", user.EmailVerifiedBy)
	}

	// 未验证的邮箱不得标记来源
	user2, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		Token: &provider.TokenSet{Raw: map[string]any{
			"sub": "001234", "email": "x@example.com", "email_verified": "false",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user2.EmailVerifiedBy != "" {
		t.Fatal("未验证邮箱不得标记来源，否则会绕过 R4 红线")
	}
}

// TestFirstAuthNameParsed 验证首次授权的姓名被解析出来。
// Apple 只在第一次返回姓名，丢了就永久丢了。
func TestFirstAuthNameParsed(t *testing.T) {
	a := NewApp(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		Token: &provider.TokenSet{Raw: map[string]any{"sub": "s1"}},
		Extra: map[string]string{
			"user": `{"name":{"firstName":"三","lastName":"张"},"email":"z@example.com"}`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.Nickname != "张三" {
		t.Fatalf("姓名解析失败: %q", user.Nickname)
	}
}

func TestUnbindRequiresRefreshToken(t *testing.T) {
	a := NewApp(nil)
	err := a.Unbind(context.Background(), provider.UnbindRequest{
		Creds: provider.Credentials{ProviderAppID: "com.example.client"},
	})
	if err == nil {
		t.Fatal("缺少 refresh_token 时应明确声明不支持，而不是假装成功")
	}
}

func TestRefreshNotSupported(t *testing.T) {
	a := NewApp(nil)
	if _, err := a.Refresh(context.Background(), provider.RefreshRequest{}); err == nil {
		t.Fatal("Apple 不支持第三方刷新，应返回 NotSupported")
	}
}

// --- 服务端通知（/v1/oauth/notify/{platform}）---

// notifyAdapter 构造一个指向本地假 JWKS 的适配器。
func notifyAdapter(t *testing.T, key *rsa.PrivateKey) *Adapter {
	t.Helper()
	srv := jwksServer(t, key)
	t.Cleanup(srv.Close)
	a := NewApp(nil)
	a.notifyJWKSURL = srv.URL
	return a
}

// makeNotification 签一条 Apple 风格的服务端通知。events 按 Apple 的实际格式
// 編码成【JSON 字符串】而不是嵌套对象。
func makeNotification(t *testing.T, key *rsa.PrivateKey, aud, eventType, sub string) []byte {
	t.Helper()
	events, err := json.Marshal(map[string]any{
		"type":       eventType,
		"sub":        sub,
		"event_time": time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{
		"iss":    appleIssuer,
		"aud":    aud,
		"iat":    time.Now().Add(-time.Minute).Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
		"jti":    "notif-1",
		"events": string(events),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(signed)
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseCallbackConsentRevoked(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	body := makeNotification(t, key, "com.example.client", "consent-revoked", "001234.abcdef")

	ev, err := a.ParseCallback(context.Background(), &provider.CallbackPayload{
		Platform: provider.PlatformApple,
		Scene:    provider.SceneApp,
		Body:     body,
		Audience: "com.example.client",
	})
	if err != nil {
		t.Fatalf("ParseCallback: %v", err)
	}
	if ev.Type != provider.CallbackEventConsentRevoked {
		t.Fatalf("期望 consent_revoked，实际=%s", ev.Type)
	}
	if ev.OpenID != "001234.abcdef" {
		t.Fatalf("期望解析出 sub，实际=%q", ev.OpenID)
	}
	if ev.OccurredAt.IsZero() {
		t.Fatal("期望解析出 event_time")
	}
}

// TestParseCallbackRejectsAudMismatch 是防跨应用重放的关键用例：
// Apple 的 JWKS 是全局的，签名有效不等于"发给我们"。
func TestParseCallbackRejectsAudMismatch(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	body := makeNotification(t, key, "com.other.app", "consent-revoked", "001234.abcdef")

	_, err := a.ParseCallback(context.Background(), &provider.CallbackPayload{
		Platform: provider.PlatformApple,
		Body:     body,
		Audience: "com.example.client",
	})
	if err == nil {
		t.Fatal("aud 与渠道配置不一致时必须拒绝")
	}
}

func TestParseCallbackRejectsBadSignature(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	// 用另一把私钥签，验签必然失败。
	other := testKey(t)
	body := makeNotification(t, other, "com.example.client", "consent-revoked", "001234.abcdef")

	if _, err := a.ParseCallback(context.Background(), &provider.CallbackPayload{
		Body:     body,
		Audience: "com.example.client",
	}); err == nil {
		t.Fatal("签名不匹配必须拒绝")
	}
}

func TestParseCallbackUnknownEventType(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	body := makeNotification(t, key, "com.example.client", "some-brand-new-event", "001234.abcdef")

	ev, err := a.ParseCallback(context.Background(), &provider.CallbackPayload{
		Body:     body,
		Audience: "com.example.client",
	})
	if err != nil {
		t.Fatalf("未知事件类型不应报错: %v", err)
	}
	if ev.Type != provider.CallbackEventUnknown {
		t.Fatalf("期望 unknown，实际=%s", ev.Type)
	}
}

// TestParseCallbackAcceptsFormPost：Apple 的 form_post 模式把 JWT 放在
// payload 参数里，而不是裸 body。
func TestParseCallbackAcceptsFormPost(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	token := string(makeNotification(t, key, "com.example.client", "account-delete", "001234.abcdef"))
	body := []byte("payload=" + url.QueryEscape(token))

	ev, err := a.ParseCallback(context.Background(), &provider.CallbackPayload{
		Body:     body,
		Audience: "com.example.client",
	})
	if err != nil {
		t.Fatalf("form_post 形式应被接受: %v", err)
	}
	if ev.Type != provider.CallbackEventAccountDelete {
		t.Fatalf("期望 account_delete，实际=%s", ev.Type)
	}
}

// TestParseCallbackAcceptsNestedEventsObject：兼容 events 是嵌套对象的编码，
// 平台若切换格式不应全量失败。
func TestParseCallbackAcceptsNestedEventsObject(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	claims := jwt.MapClaims{
		"iss": appleIssuer,
		"aud": "com.example.client",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"events": map[string]any{
			"type": "consent-revoked",
			"sub":  "001234.abcdef",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	ev, err := a.ParseCallback(context.Background(), &provider.CallbackPayload{
		Body:     []byte(signed),
		Audience: "com.example.client",
	})
	if err != nil {
		t.Fatalf("嵌套对象形式应被接受: %v", err)
	}
	if ev.OpenID != "001234.abcdef" {
		t.Fatalf("期望解析出 sub，实际=%q", ev.OpenID)
	}
}

func TestVerifyCallbackStillWorks(t *testing.T) {
	key := testKey(t)
	a := notifyAdapter(t, key)
	body := makeNotification(t, key, "com.example.client", "consent-revoked", "001234.abcdef")
	if err := a.VerifyCallback(context.Background(), &provider.CallbackPayload{
		Body:     body,
		Audience: "com.example.client",
	}); err != nil {
		t.Fatalf("VerifyCallback: %v", err)
	}
}

// TestRegistrationIncludesNotifyCapability 断言 Apple 适配器确实声明了
// 通知验签与解析能力——否则 /v1/oauth/notify 会以"渠道不支持"拒绝。
func TestRegistrationIncludesNotifyCapability(t *testing.T) {
	a := NewApp(nil)
	if _, ok := any(a).(provider.CallbackVerifier); !ok {
		t.Fatal("Apple 必须实现 CallbackVerifier")
	}
	if _, ok := any(a).(provider.CallbackParser); !ok {
		t.Fatal("Apple 必须实现 CallbackParser")
	}
}
