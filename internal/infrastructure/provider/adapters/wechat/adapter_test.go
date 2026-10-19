package wechat

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/djackcurry30/social-login/internal/domain/provider"
)

// newTestCreds 把 api_base 指向测试服务器。
func newTestCreds(baseURL string) provider.Credentials {
	return provider.Credentials{
		ProviderAppID: "wx-test-appid",
		Secret:        "wx-test-secret",
		Extra:         map[string]any{"api_base": baseURL},
	}
}

func TestRegisteredScenes(t *testing.T) {
	want := map[string]bool{
		"wechat:app":              false,
		"wechat:mini_program":     false,
		"wechat:official_account": false,
		"wechat:pc_qr":            false,
	}
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

// TestImmediateScenes 验证 app / 小程序不返回跳转 URL。
// 它们的授权动作在客户端 SDK 里，服务端硬拼一个 URL 只会让前端困惑。
func TestImmediateScenes(t *testing.T) {
	for _, a := range []*Adapter{NewApp(nil), NewMiniProgram(nil)} {
		res, err := a.AuthURL(context.Background(), provider.AuthorizeRequest{
			Creds: newTestCreds("http://127.0.0.1"),
		})
		if err != nil {
			t.Fatalf("%s: %v", a.scene, err)
		}
		if !res.Immediate {
			t.Fatalf("%s 应为 Immediate", a.scene)
		}
		if res.URL != "" {
			t.Fatalf("%s 不应返回 URL，实际=%s", a.scene, res.URL)
		}
		if res.Params["method"] == "" {
			t.Fatalf("%s 应告知前端调用哪个 SDK 方法", a.scene)
		}
	}
}

func TestAuthURLForWebScenes(t *testing.T) {
	cases := []struct {
		adapter *Adapter
		path    string
		scope   string
	}{
		{NewOfficialAccount(nil), "/connect/oauth2/authorize", "snsapi_userinfo"},
		{NewPCQR(nil), "/connect/qrconnect", "snsapi_login"},
	}
	for _, tc := range cases {
		res, err := tc.adapter.AuthURL(context.Background(), provider.AuthorizeRequest{
			Creds:       newTestCreds("http://127.0.0.1"),
			RedirectURI: "https://biz.example.com/cb",
			State:       "ticket-123",
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.adapter.scene, err)
		}
		if res.Immediate {
			t.Fatalf("%s 不应是 Immediate", tc.adapter.scene)
		}
		for _, want := range []string{tc.path, "appid=wx-test-appid", "scope=" + tc.scope, "state=ticket-123"} {
			if !strings.Contains(res.URL, want) {
				t.Fatalf("%s 的授权 URL 缺少 %q: %s", tc.adapter.scene, want, res.URL)
			}
		}
		if !strings.HasSuffix(res.URL, "#wechat_redirect") {
			t.Fatalf("%s 的 URL 必须以 #wechat_redirect 结尾: %s", tc.adapter.scene, res.URL)
		}
	}
}

// TestExchangeMiniProgram 验证 code2session 的解析，并确认 unionid 不落进 Raw（约束 C3）。
func TestExchangeMiniProgram(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sns/jscode2session" {
			t.Errorf("非预期路径: %s", r.URL.Path)
		}
		if r.URL.Query().Get("js_code") != "js-code-1" {
			t.Errorf("js_code 未透传: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"openid":      "openid-1",
			"session_key": "c2Vzc2lvbl9rZXlfMTY=",
			"unionid":     "union-should-not-leak",
		})
	}))
	defer srv.Close()

	a := NewMiniProgram(nil)
	ts, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: newTestCreds(srv.URL),
		Code:  "js-code-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ts.SessionKey == "" {
		t.Fatal("session_key 应写入 TokenSet")
	}
	if ts.Raw["openid"] != "openid-1" {
		t.Fatalf("openid 应写入 Raw，实际=%v", ts.Raw)
	}
	if _, exists := ts.Raw["unionid"]; exists {
		t.Fatal("约束 C3：unionid 不得写入 Raw")
	}
}

// TestExchangeRejectsUsedCode 验证"code 已使用"被归一化为不可重试的业务拒绝。
// 关键点：这类错误【不计入熔断】，否则攻击者可用无效 code 高频打回调来熔断渠道。
func TestExchangeRejectsUsedCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40163, "errmsg": "code been used"})
	}))
	defer srv.Close()

	a := NewOfficialAccount(nil)
	_, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: newTestCreds(srv.URL),
		Code:  "used-code",
	})
	if err == nil {
		t.Fatal("应返回错误")
	}
	e, ok := err.(interface{ Error() string })
	_ = e
	if !ok {
		t.Fatal("错误应为 error")
	}
	if !strings.Contains(err.Error(), "授权码无效或已使用") {
		t.Fatalf("错误信息不符: %v", err)
	}
}

// TestUserInfoSnsapiBaseFallback 验证静默授权拿不到资料时不阻断登录。
// 48001 是"接口未授权"，此时 openid 已经拿到，身份是成立的。
func TestUserInfoSnsapiBaseFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 48001, "errmsg": "api unauthorized"})
	}))
	defer srv.Close()

	a := NewOfficialAccount(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		Creds: newTestCreds(srv.URL),
		Token: &provider.TokenSet{AccessToken: "at", Raw: map[string]any{"openid": "openid-2"}},
	})
	if err != nil {
		t.Fatalf("静默授权不应导致登录失败: %v", err)
	}
	if user.OpenID != "openid-2" {
		t.Fatalf("openid 应保留，实际=%q", user.OpenID)
	}
	if user.Nickname != "" {
		t.Fatal("静默授权不应有昵称")
	}
}

// TestUnbindNotSupported 验证微信侧解绑被明确声明为不支持（而不是假装成功）。
func TestUnbindNotSupported(t *testing.T) {
	a := NewApp(nil)
	err := a.Unbind(context.Background(), provider.UnbindRequest{})
	if err == nil || !strings.Contains(err.Error(), "unbind") {
		t.Fatalf("应返回 NotSupported(unbind)，实际=%v", err)
	}
}

// --- 手机号解密 ---

func encryptPhone(t *testing.T, plain []byte, key, iv []byte, appID string) (string, string, string) {
	t.Helper()
	payload := map[string]any{
		"phoneNumber":     "+8613800000000",
		"purePhoneNumber": "13800000000",
		"countryCode":     "86",
		"watermark":       map[string]any{"appid": appID, "timestamp": 1700000000},
	}
	if plain == nil {
		var err error
		plain, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)

	return base64.StdEncoding.EncodeToString(key),
		base64.StdEncoding.EncodeToString(out),
		base64.StdEncoding.EncodeToString(iv)
}

func TestDecryptPhone(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	keyB64, encB64, ivB64 := encryptPhone(t, nil, key, iv, "wx-test-appid")

	phone, pure, err := decryptPhone(keyB64, encB64, ivB64, "wx-test-appid")
	if err != nil {
		t.Fatal(err)
	}
	if pure != "13800000000" || phone != "+8613800000000" {
		t.Fatalf("解密结果不符: phone=%q pure=%q", phone, pure)
	}
}

// TestDecryptPhoneRejectsForeignAppID 验证 watermark.appid 校验。
// 不校验的话，另一个小程序的密文可以被拿来充数（跨 appid 重放）。
func TestDecryptPhoneRejectsForeignAppID(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	keyB64, encB64, ivB64 := encryptPhone(t, nil, key, iv, "another-appid")

	_, _, err := decryptPhone(keyB64, encB64, ivB64, "wx-test-appid")
	if err == nil {
		t.Fatal("watermark.appid 不一致时必须拒绝")
	}
	if !strings.Contains(err.Error(), "watermark") {
		t.Fatalf("错误信息应指明 watermark: %v", err)
	}
}

func TestDecryptPhoneRejectsBadPadding(t *testing.T) {
	keyB64, encB64, ivB64 := encryptPhone(t, nil, []byte("0123456789abcdef"), []byte("abcdef0123456789"), "wx-test-appid")
	// 用另一把钥匙解密 → 填充校验必须失败，而不是返回乱码。
	_, _, err := decryptPhone(keyB64, encB64, ivB64, "wx-test-appid")
	if err != nil {
		t.Fatal("正常路径不应失败")
	}
	wrongKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	if _, _, err := decryptPhone(wrongKey, encB64, ivB64, "wx-test-appid"); err == nil {
		t.Fatal("错误的 key 解密必须失败")
	}
}

// TestPhoneCodePath 验证新版 phone_code 路径：拿 component token 再换手机号，
// 并把来源标记为 wechat_phone（R4 红线 1 的白名单取值）。
func TestPhoneCodePath(t *testing.T) {
	var tokenCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/stable_token":
			tokenCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "component-token", "expires_in": 7200,
			})
		case "/wxa/business/getuserphonenumber":
			if r.URL.Query().Get("access_token") != "component-token" {
				t.Errorf("access_token 未透传: %s", r.URL.RawQuery)
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "phone-code-1" {
				t.Errorf("phone_code 未透传: %v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"phone_info": map[string]any{
					"phoneNumber":     "+8613900000000",
					"purePhoneNumber": "13900000000",
					"countryCode":     "86",
				},
			})
		default:
			t.Errorf("非预期路径: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	a := NewMiniProgram(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		Creds: newTestCreds(srv.URL),
		Token: &provider.TokenSet{SessionKey: "sk", Raw: map[string]any{"openid": "openid-3"}},
		Extra: map[string]string{"phone_code": "phone-code-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.Phone != "13900000000" {
		t.Fatalf("手机号不符: %q", user.Phone)
	}
	if user.PhoneVerifiedBy != "wechat_phone" {
		t.Fatalf("来源标记必须是 wechat_phone，实际=%q", user.PhoneVerifiedBy)
	}

	// 第二次调用应命中 token 缓存，不再请求 stable_token。
	_, err = a.UserInfo(context.Background(), provider.UserInfoRequest{
		Creds: newTestCreds(srv.URL),
		Token: &provider.TokenSet{SessionKey: "sk", Raw: map[string]any{"openid": "openid-3"}},
		Extra: map[string]string{"phone_code": "phone-code-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokenCalls != 1 {
		t.Fatalf("component token 应被缓存，stable_token 调用次数=%d", tokenCalls)
	}
}

// TestMiniProgramWithoutPhoneStillWorks 验证不接 getPhoneNumber 也能登录。
// 手机号是可选的归并依据，不是登录前提。
func TestMiniProgramWithoutPhoneStillWorks(t *testing.T) {
	a := NewMiniProgram(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		Creds: newTestCreds("http://127.0.0.1:1"), // 不会被访问
		Token: &provider.TokenSet{Raw: map[string]any{"openid": "openid-4"}},
	})
	if err != nil {
		t.Fatalf("无手机号不应报错: %v", err)
	}
	if user.OpenID != "openid-4" || user.Phone != "" || user.PhoneVerifiedBy != "" {
		t.Fatalf("结果不符: %+v", user)
	}
}
