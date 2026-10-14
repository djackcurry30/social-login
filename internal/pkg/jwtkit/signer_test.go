package jwtkit

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestSigner(t *testing.T, kids ...string) *Signer {
	t.Helper()
	keys := make([]Key, 0, len(kids))
	for _, kid := range kids {
		k, err := GenerateKey(kid)
		if err != nil {
			t.Fatalf("生成密钥失败: %v", err)
		}
		keys = append(keys, k)
	}
	s, err := NewSigner(Options{Issuer: "https://auth.test", TTL: time.Minute, Keys: keys})
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}
	return s
}

func TestIssueAndParse(t *testing.T) {
	t.Parallel()

	s := newTestSigner(t, "kid-1")
	token, claims, err := s.Issue(IssueInput{
		Subject:  "u_1001",
		Audience: "app_demo",
		Scope:    "openid profile",
		AMR:      []string{"generic_oauth2:web"},
	})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if claims.ID == "" {
		t.Fatal("必须带 jti，否则无法实现 jti 黑名单撤销（P0-5）")
	}

	got, err := s.Parse(token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if got.Subject != "u_1001" {
		t.Errorf("sub 期望 u_1001，实际 %s", got.Subject)
	}
	if len(got.Audience) == 0 || got.Audience[0] != "app_demo" {
		t.Errorf("aud 期望 app_demo，实际 %v", got.Audience)
	}
	if got.Scope != "openid profile" {
		t.Errorf("scope 期望 openid profile，实际 %s", got.Scope)
	}
}

// TestParseRejectsExpired 验证过期令牌返回明确的 TOKEN.EXPIRED。
//
// 区分"过期"与"无效"不是洁癖：前者接入方应引导用户重新登录，
// 后者可能意味着令牌被篡改，两者的风控处置完全不同。
func TestParseRejectsExpired(t *testing.T) {
	t.Parallel()

	keys := []Key{mustKey(t, "kid-1")}
	s, err := NewSigner(Options{Issuer: "https://auth.test", TTL: -time.Minute, Keys: keys})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	// 直接构造一个已过期的 claims，避开 TTL 的合理范围校验。
	expired := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.test",
			Subject:   "u_1",
			Audience:  jwt.ClaimStrings{"app_demo"},
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, expired)
	tok.Header["kid"] = "kid-1"
	signed, err := tok.SignedString(keys[0].Private)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	if _, err := s.Parse(signed); err == nil {
		t.Fatal("过期令牌必须校验失败")
	}
}

// TestParseRejectsTamperedToken 验证篡改与未知 kid 都被拒绝。
func TestParseRejectsTamperedToken(t *testing.T) {
	t.Parallel()

	s := newTestSigner(t, "kid-1")
	token, _, err := s.Issue(IssueInput{Subject: "u_1", Audience: "app_demo"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	// 换掉签名段。
	tampered := token[:len(token)-4] + "AAAA"
	if _, err := s.Parse(tampered); err == nil {
		t.Fatal("被篡改的签名必须校验失败")
	}

	// 未知 kid：用另一把密钥签、但贴上 kid-1 之外的头。
	other := newTestSigner(t, "kid-other")
	tok2, _, err := other.Issue(IssueInput{Subject: "u_1", Audience: "app_demo"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if _, err := s.Parse(tok2); err == nil {
		t.Fatal("未知 kid 必须校验失败（否则密钥轮换期会接受任意密钥签发的令牌）")
	}
}

// TestJWKSContainsOnlyPublicMaterial 验证 JWKS 不泄漏私钥材料。
func TestJWKSContainsOnlyPublicMaterial(t *testing.T) {
	t.Parallel()

	s := newTestSigner(t, "kid-1")
	raw, err := s.JWKS()
	if err != nil {
		t.Fatalf("生成 JWKS 失败: %v", err)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 JWKS 失败: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("期望 1 把公钥，实际 %d", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k["kty"] != "EC" || k["crv"] != "P-256" || k["alg"] != "ES256" {
		t.Fatalf("JWK 元信息不正确: %v", k)
	}
	for _, forbidden := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := k[forbidden]; ok {
			t.Fatalf("JWKS 中出现了私钥字段 %q —— 这是严重泄漏", forbidden)
		}
	}

	// 用发布的公钥能验签成功，说明 x/y 编码正确（补零逻辑正确）。
	xb, err := base64.RawURLEncoding.DecodeString(k["x"].(string))
	if err != nil {
		t.Fatalf("x 不是合法 base64url: %v", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k["y"].(string))
	if err != nil {
		t.Fatalf("y 不是合法 base64url: %v", err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		t.Fatalf("P-256 坐标必须是 32 字节（含前导零补齐），实际 x=%d y=%d", len(xb), len(yb))
	}
}

// TestKeyRotationKeepsOldTokensVerifiable 验证 §8.3 的密钥轮换四步。
//
// 轮换的第 ② 步是"JWKS 同时发布新旧两把公钥"，第 ③ 步才是"等旧 token 过期"。
// 顺序不可颠倒：提前下线旧公钥会让所有在途令牌瞬间验签失败。
// 这里用两个 Signer 模拟轮换前 / 轮换后的状态。
func TestKeyRotationKeepsOldTokensVerifiable(t *testing.T) {
	t.Parallel()

	oldKey := mustKey(t, "kid-old")
	beforeSigner, err := NewSigner(Options{
		Issuer: "https://auth.test", TTL: time.Minute, Keys: []Key{oldKey},
	})
	if err != nil {
		t.Fatalf("构造轮换前签名器失败: %v", err)
	}

	token, _, err := beforeSigner.Issue(IssueInput{Subject: "u_1", Audience: "app_demo"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	newKey := mustKey(t, "kid-new")
	afterSigner, err := NewSigner(Options{
		Issuer: "https://auth.test", TTL: time.Minute,
		// 新密钥在前（用于签名），旧密钥仍在列表中（继续发布公钥）。
		Keys: []Key{newKey, oldKey},
	})
	if err != nil {
		t.Fatalf("构造轮换后签名器失败: %v", err)
	}

	if afterSigner.ActiveKID() != "kid-new" {
		t.Fatalf("轮换后应用新密钥签名，实际 %s", afterSigner.ActiveKID())
	}
	if len(afterSigner.Kids()) != 2 {
		t.Fatalf("轮换过渡期必须同时发布新旧两把公钥，实际 %v", afterSigner.Kids())
	}
	// 关键断言：旧令牌仍然可验签。
	if _, err := afterSigner.Parse(token); err != nil {
		t.Fatalf("轮换过渡期旧令牌必须仍可验签，实际失败: %v", err)
	}

	// 撤销旧密钥（第 ④ 步）后，旧令牌不再可验签——这正是"必须等旧令牌过期"的理由。
	retired, err := NewSigner(Options{
		Issuer: "https://auth.test", TTL: time.Minute, Keys: []Key{newKey},
	})
	if err != nil {
		t.Fatalf("构造下线后签名器失败: %v", err)
	}
	if _, err := retired.Parse(token); err == nil {
		t.Fatal("旧公钥下线后旧令牌必须验签失败（说明提前下线会造成全局失效）")
	}
}

func mustKey(t *testing.T, kid string) Key {
	t.Helper()
	k, err := GenerateKey(kid)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	return k
}
