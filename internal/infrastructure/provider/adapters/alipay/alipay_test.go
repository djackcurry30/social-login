package alipay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/djackcurry30/social-login/internal/domain/provider"
)

// genKey 生成测试用 RSA 私钥。
func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func privPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pubPEM(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestSignContent 验证待签名串的构造规则：过滤空值、升序、k=v 用 & 连接。
func TestSignContent(t *testing.T) {
	params := map[string]string{
		"method":    "alipay.system.oauth.token",
		"app_id":    "2021000000",
		"sign":      "should-be-skipped",
		"charset":   "utf-8",
		"empty_val": "",
	}
	got := signContent(params)
	if strings.Contains(got, "sign=") {
		t.Fatalf("sign 必须被排除: %s", got)
	}
	if strings.Contains(got, "empty_val") {
		t.Fatalf("空值必须被排除: %s", got)
	}
	// app_id < charset < method 的字节序
	want := "app_id=2021000000&charset=utf-8&method=alipay.system.oauth.token"
	if got != want {
		t.Fatalf("签名串不符\n got=%s\nwant=%s", got, want)
	}
}

// signNode 用"支付宝私钥"对响应节点签名（测试里模拟支付宝侧）。
func signNode(t *testing.T, node []byte, k *rsa.PrivateKey) string {
	t.Helper()
	s, err := rsaSignRaw(node, k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExchangeWithSignedResponse(t *testing.T) {
	appKey := genKey(t)
	alipayKey := genKey(t)

	node := []byte(`{"user_id":"2088000000000000","access_token":"at-1","expires_in":3600,"refresh_token":"rt-1"}`)
	sign := signNode(t, node, alipayKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.PostForm.Get("method") != methodOAuthToken {
			t.Errorf("method 不符: %s", r.PostForm.Get("method"))
		}
		if r.PostForm.Get("code") != "auth-code-1" {
			t.Errorf("code 未透传: %s", r.PostForm.Get("code"))
		}
		if r.PostForm.Get("sign") == "" {
			t.Error("请求必须带签名")
		}
		// 用应用公钥验请求签名，确认我们签的内容与提交的参数一致。
		params := map[string]string{}
		for k := range r.PostForm {
			params[k] = r.PostForm.Get(k)
		}
		if err := verifyRequest(params, &appKey.PublicKey); err != nil {
			t.Errorf("请求验签失败: %v", err)
		}

		writeEnvelope(t, w, "alipay_system_oauth_token_response", node, sign)
	}))
	defer srv.Close()

	a := NewApp(nil)
	creds := provider.Credentials{
		ProviderAppID: "2021000000",
		Secret:        privPEM(t, appKey),
		Extra: map[string]any{
			"gateway":           srv.URL,
			"alipay_public_key": pubPEM(t, &alipayKey.PublicKey),
		},
	}
	ts, err := a.Exchange(context.Background(), provider.ExchangeRequest{Creds: creds, Code: "auth-code-1"})
	if err != nil {
		t.Fatal(err)
	}
	if ts.AccessToken != "at-1" || ts.RefreshToken != "rt-1" {
		t.Fatalf("令牌不符: %+v", ts)
	}
	if ts.Raw["user_id"] != "2088000000000000" {
		t.Fatalf("user_id 应写入 Raw: %v", ts.Raw)
	}
}

// TestExchangeRejectsTamperedResponse 验证响应验签真的在起作用。
// 如果这里能通过，说明验签是摆设——攻击者改掉 user_id 就能冒用他人身份。
func TestExchangeRejectsTamperedResponse(t *testing.T) {
	appKey := genKey(t)
	alipayKey := genKey(t)

	original := []byte(`{"user_id":"2088-original","access_token":"at-1"}`)
	sign := signNode(t, original, alipayKey)
	tampered := []byte(`{"user_id":"2088-attacker","access_token":"at-1"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(t, w, "alipay_system_oauth_token_response", tampered, sign)
	}))
	defer srv.Close()

	a := NewApp(nil)
	_, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: provider.Credentials{
			ProviderAppID: "2021000000",
			Secret:        privPEM(t, appKey),
			Extra: map[string]any{
				"gateway":           srv.URL,
				"alipay_public_key": pubPEM(t, &alipayKey.PublicKey),
			},
		},
		Code: "c",
	})
	if err == nil {
		t.Fatal("被篡改的响应必须被拒绝")
	}
	if !strings.Contains(err.Error(), "验签失败") {
		t.Fatalf("错误应指明验签失败: %v", err)
	}
}

// TestGatewayErrorMapping 验证业务拒绝被归为不可重试（不计入熔断）。
func TestGatewayErrorMapping(t *testing.T) {
	appKey := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_response": map[string]any{
				"code": "40002", "msg": "Invalid Arguments",
				"sub_code": "isv.code-invalid", "sub_msg": "授权码无效",
			},
		})
	}))
	defer srv.Close()

	a := NewApp(nil)
	_, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		Creds: provider.Credentials{
			ProviderAppID: "2021000000",
			Secret:        privPEM(t, appKey),
			Extra:         map[string]any{"gateway": srv.URL},
		},
		Code: "bad",
	})
	if err == nil || !strings.Contains(err.Error(), "授权码或令牌无效") {
		t.Fatalf("应映射为业务拒绝，实际=%v", err)
	}
}

func TestWebAuthURL(t *testing.T) {
	a := NewWeb(nil)
	res, err := a.AuthURL(context.Background(), provider.AuthorizeRequest{
		Creds:       provider.Credentials{ProviderAppID: "2021000000"},
		RedirectURI: "https://biz.example.com/cb",
		State:       "ticket-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/oauth2/publicAppAuthorize.htm", "app_id=2021000000", "state=ticket-1", "scope=auth_user"} {
		if !strings.Contains(res.URL, want) {
			t.Fatalf("授权 URL 缺少 %q: %s", want, res.URL)
		}
	}
}

func TestAppAndMiniAreImmediate(t *testing.T) {
	for _, a := range []*Adapter{NewApp(nil), NewMiniProgram(nil)} {
		res, err := a.AuthURL(context.Background(), provider.AuthorizeRequest{
			Creds: provider.Credentials{ProviderAppID: "2021000000"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Immediate || res.URL != "" {
			t.Fatalf("%s 应为 Immediate 且无 URL", a.meta.Scene)
		}
	}
}

// --- 测试辅助 ---

func rsaSignRaw(node []byte, k *rsa.PrivateKey) (string, error) {
	sig, err := signRawBytes(node, k)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func writeEnvelope(t *testing.T, w http.ResponseWriter, nodeKey string, node []byte, sign string) {
	t.Helper()
	signJSON, _ := json.Marshal(sign)
	_, _ = w.Write([]byte(`{"` + nodeKey + `":`))
	_, _ = w.Write(node)
	_, _ = w.Write([]byte(`,"sign":`))
	_, _ = w.Write(signJSON)
	_, _ = w.Write([]byte(`}`))
}

// verifyRequest 用应用公钥校验我们发出的请求签名。
func verifyRequest(params map[string]string, pub *rsa.PublicKey) error {
	signB64 := params["sign"]
	sig, err := base64.StdEncoding.DecodeString(signB64)
	if err != nil {
		return err
	}
	return verifyRaw(signContent(params), sig, pub)
}
