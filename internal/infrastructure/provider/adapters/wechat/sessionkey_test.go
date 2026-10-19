package wechat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/sessionkey"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// useStore 注入内存存储并在用例结束后清理，避免包级变量串到其他用例。
func useStore(t *testing.T) *sessionkey.MemoryStore {
	t.Helper()
	st := sessionkey.NewMemoryStore()
	ConfigureSessionStore(st, nil)
	t.Cleanup(func() { ConfigureSessionStore(nil, nil) })
	return st
}

// TestExchangePersistsSessionKey 确认 code2Session 成功后密钥确实落到了共享存储。
// 这是跨请求解密的前提：只写进 TokenSet 是不够的，下一次请求拿不到。
func TestExchangePersistsSessionKey(t *testing.T) {
	st := useStore(t)
	srv := sessionServer(t, "openid-1", "c2Vzc2lvbl9rZXlfMTY=")
	a := NewMiniProgram(nil)

	_, err := a.Exchange(context.Background(), provider.ExchangeRequest{
		AppID: "app-a",
		Creds: newTestCreds(srv),
		Code:  "js-code-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.Get(context.Background(), "app-a", "openid-1")
	if err != nil {
		t.Fatalf("密钥应已落库: %v", err)
	}
	if got != "c2Vzc2lvbl9rZXlfMTY=" {
		t.Fatalf("落库的密钥不对: %q", got)
	}
}

// TestCrossRequestUsesStoredSessionKey 是本组的核心用例：
// 第二次请求带着【上一次登录】加密的手机号，而本次 code2Session 拿到的是新密钥，
// 它解不开旧密文。服务必须回查共享存储，而不是直接失败。
func TestCrossRequestUsesStoredSessionKey(t *testing.T) {
	st := useStore(t)
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	keyB64, encB64, ivB64 := encryptPhone(t, nil, key, iv, "wx-test-appid")

	// 模拟"上一次登录"写下的密钥。
	if err := st.Put(context.Background(), "app-a", "openid-1", keyB64, time.Hour); err != nil {
		t.Fatal(err)
	}

	a := NewMiniProgram(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		AppID: "app-a",
		Creds: newTestCreds("http://127.0.0.1:0"),
		// SessionKey 为空：本次是另一个实例上的独立请求，没有同一次 code2Session 的密钥。
		Token: &provider.TokenSet{Raw: map[string]any{"openid": "openid-1"}},
		Extra: map[string]string{"encrypted_data": encB64, "iv": ivB64},
	})
	if err != nil {
		t.Fatalf("应回退到共享存储里的密钥: %v", err)
	}
	if user.Phone != "13800000000" {
		t.Fatalf("手机号解析错误: %q", user.Phone)
	}
	if user.PhoneVerifiedBy != "wechat_phone" {
		t.Fatalf("必须标记为平台已验证（R4 红线 1），实际=%q", user.PhoneVerifiedBy)
	}

	// 用完即弃：密钥不应继续留在共享存储里。
	if _, err := st.Get(context.Background(), "app-a", "openid-1"); !errors.Is(err, sessionkey.ErrNotFound) {
		t.Fatalf("解密成功后应删除密钥，实际 err=%v", err)
	}
}

// TestSessionKeyScopedPerApp 验证约束 C1：同一 openid 在不同应用下互不可见。
// 同主体的多个小程序可能返回同一个 openid，串用会把 A 应用的手机号解到 B 应用。
func TestSessionKeyScopedPerApp(t *testing.T) {
	st := useStore(t)
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	keyB64, encB64, ivB64 := encryptPhone(t, nil, key, iv, "wx-test-appid")

	// 密钥属于 app-b，却拿 app-a 来解。
	if err := st.Put(context.Background(), "app-b", "openid-1", keyB64, time.Hour); err != nil {
		t.Fatal(err)
	}

	a := NewMiniProgram(nil)
	_, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		AppID: "app-a",
		Creds: newTestCreds("http://127.0.0.1:0"),
		Token: &provider.TokenSet{Raw: map[string]any{"openid": "openid-1"}},
		Extra: map[string]string{"encrypted_data": encB64, "iv": ivB64},
	})
	if err == nil {
		t.Fatal("跨应用不得复用会话密钥")
	}
	if errs.CodeOf(err) != errs.CodeAuthInvalidState {
		t.Fatalf("期望 AUTH.INVALID_STATE，实际=%v", errs.CodeOf(err))
	}
}

// TestMissingSessionKeyFailsLoudly 是 R4 红线 1 的守卫：
// 解不开手机号时必须报错，不能静默返回"没有手机号"——否则下游会拿一个
// 未经校验的号码继续用。
func TestMissingSessionKeyFailsLoudly(t *testing.T) {
	useStore(t)
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	_, encB64, ivB64 := encryptPhone(t, nil, key, iv, "wx-test-appid")

	a := NewMiniProgram(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		AppID: "app-a",
		Creds: newTestCreds("http://127.0.0.1:0"),
		Token: &provider.TokenSet{Raw: map[string]any{"openid": "openid-1"}},
		Extra: map[string]string{"encrypted_data": encB64, "iv": ivB64},
	})
	if err == nil {
		t.Fatalf("会话密钥缺失时必须报错，实际 user.Phone=%q", user.Phone)
	}
	if errs.CodeOf(err) != errs.CodeAuthInvalidState {
		t.Fatalf("期望 AUTH.INVALID_STATE，实际=%v", errs.CodeOf(err))
	}
}

// TestSameRequestStillPreferred 确认同一次请求内的密钥优先：
// 它是这次 code2Session 刚拿到的，比存储里的旧密钥更可能与密文同源。
func TestSameRequestStillPreferred(t *testing.T) {
	st := useStore(t)
	curKey := []byte("fedcba9876543210")
	oldKey := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	// 密文用当前密钥加密；存储里放一份会解错的旧密钥。
	curKeyB64, encB64, ivB64 := encryptPhone(t, nil, curKey, iv, "wx-test-appid")
	oldKeyB64, _, _ := encryptPhone(t, nil, oldKey, iv, "wx-test-appid")
	if err := st.Put(context.Background(), "app-a", "openid-1", oldKeyB64, time.Hour); err != nil {
		t.Fatal(err)
	}

	a := NewMiniProgram(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		AppID: "app-a",
		Creds: newTestCreds("http://127.0.0.1:0"),
		Token: &provider.TokenSet{
			SessionKey: curKeyB64,
			Raw:        map[string]any{"openid": "openid-1"},
		},
		Extra: map[string]string{"encrypted_data": encB64, "iv": ivB64},
	})
	if err != nil {
		t.Fatalf("同请求密钥应能解开: %v", err)
	}
	if user.Phone != "13800000000" {
		t.Fatalf("手机号解析错误: %q", user.Phone)
	}
}

// TestNoStoreKeepsSameRequestWorking 确认未注入存储时（单测 / 不需要跨请求的部署）
// 同请求解密仍然正常，只是跨请求不可用。
func TestNoStoreKeepsSameRequestWorking(t *testing.T) {
	ConfigureSessionStore(nil, nil)
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	keyB64, encB64, ivB64 := encryptPhone(t, nil, key, iv, "wx-test-appid")

	a := NewMiniProgram(nil)
	user, err := a.UserInfo(context.Background(), provider.UserInfoRequest{
		AppID: "app-a",
		Creds: newTestCreds("http://127.0.0.1:0"),
		Token: &provider.TokenSet{
			SessionKey: keyB64,
			Raw:        map[string]any{"openid": "openid-1"},
		},
		Extra: map[string]string{"encrypted_data": encB64, "iv": ivB64},
	})
	if err != nil {
		t.Fatalf("未注入存储不应影响同请求解密: %v", err)
	}
	if user.Phone != "13800000000" {
		t.Fatalf("手机号解析错误: %q", user.Phone)
	}
}

// sessionServer 起一个只回 code2session 的假服务端。
func sessionServer(t *testing.T, openID, sessionKey string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sns/jscode2session" {
			t.Errorf("非预期路径: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"openid":      openID,
			"session_key": sessionKey,
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
