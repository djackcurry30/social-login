package jwtkit

import (
	"strings"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

func newRotateSigner(t *testing.T, ttl time.Duration) *Signer {
	t.Helper()
	key, err := GenerateKey("k-initial")
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	s, err := NewSigner(Options{Issuer: "https://auth.test", TTL: ttl, Keys: []Key{key}})
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}
	return s
}

// TestRotateKeepsOldKeyPublished 是 §8.3 第 2 步的核心断言：
// rotate 之后 JWKS 必须【同时】有新旧两把公钥，否则旧 token 立刻验签失败。
func TestRotateKeepsOldKeyPublished(t *testing.T) {
	s := newRotateSigner(t, 15*time.Minute)

	tokenBefore, _, err := s.Issue(IssueInput{Subject: "u-1", Audience: "app-a", Scope: "openid"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	newKey, err := GenerateKey("k-second")
	if err != nil {
		t.Fatalf("生成新密钥失败: %v", err)
	}
	prev, err := s.Rotate(newKey)
	if err != nil {
		t.Fatalf("轮换失败: %v", err)
	}
	if prev != "k-initial" {
		t.Fatalf("应返回上一把 kid，实际 %q", prev)
	}
	if s.ActiveKID() != "k-second" {
		t.Fatalf("应切换到新密钥，实际 %s", s.ActiveKID())
	}
	if kids := s.Kids(); len(kids) != 2 {
		t.Fatalf("JWKS 应同时发布新旧两把，实际 %v", kids)
	}

	// 关键：轮换前签发的 token 仍然能验签通过。
	if _, err := s.Parse(tokenBefore); err != nil {
		t.Fatalf("轮换后旧 token 必须仍能验签: %v", err)
	}

	// 新签发用新 kid。
	tokenAfter, claims, err := s.Issue(IssueInput{Subject: "u-1", Audience: "app-a", Scope: "openid"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if _, err := s.Parse(tokenAfter); err != nil {
		t.Fatalf("新 token 应能验签: %v", err)
	}
	if claims.ID == "" {
		t.Fatal("新 token 应有 jti")
	}
}

// TestRetireRefusesActiveKey：不能下线正在签名的密钥。
func TestRetireRefusesActiveKey(t *testing.T) {
	s := newRotateSigner(t, 15*time.Minute)
	err := s.Retire("k-initial")
	if err == nil {
		t.Fatal("下线当前签名密钥必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminConflict {
		t.Fatalf("应为 ADMIN.CONFLICT，实际 %v", errs.CodeOf(err))
	}
}

// TestRetireRefusesBeforeTokenExpiry：刚降级的旧密钥不能立刻下线。
//
// 这是 F 组存在的全部理由：提前下线 = 所有用它签的 token 立刻验签失败。
func TestRetireRefusesBeforeTokenExpiry(t *testing.T) {
	s := newRotateSigner(t, 15*time.Minute)
	newKey, _ := GenerateKey("k-second")
	if _, err := s.Rotate(newKey); err != nil {
		t.Fatalf("轮换失败: %v", err)
	}

	err := s.Retire("k-initial")
	if err == nil {
		t.Fatal("旧 token 未过期时下线必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminConflict {
		t.Fatalf("应为 ADMIN.CONFLICT，实际 %v", errs.CodeOf(err))
	}
	// 错误里必须说明"什么时候可以下线"，否则运维只能瞎等。
	ee, ok := errs.As(err)
	if !ok {
		t.Fatalf("应为 *errs.Error，实际 %T", err)
	}
	if _, has := ee.Details["retirable_at"]; !has {
		t.Fatalf("应给出可下线时间，实际 details=%v", ee.Details)
	}
	if _, has := ee.Details["wait_seconds"]; !has {
		t.Fatalf("应给出还需等待的秒数，实际 details=%v", ee.Details)
	}
}

// TestRetireAfterTTL：等满 TTL + 宽限后可以下线，且下线后旧 token 失效。
func TestRetireAfterTTL(t *testing.T) {
	// 用 1ms 的 TTL：retire 允许的最早时刻 = DemotedAt + 1ms + 1min 宽限。
	// 宽限是写死的 1 分钟，所以这里直接把 DemotedAt 往前拨。
	s := newRotateSigner(t, time.Millisecond)
	oldToken, _, err := s.Issue(IssueInput{Subject: "u-1", Audience: "app-a", Scope: "openid"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	newKey, _ := GenerateKey("k-second")
	if _, err := s.Rotate(newKey); err != nil {
		t.Fatalf("轮换失败: %v", err)
	}

	// 模拟"已经等了足够久"：把降级时间拨到 10 分钟前。
	s.mu.Lock()
	s.meta["k-initial"].DemotedAt = time.Now().UTC().Add(-10 * time.Minute)
	s.mu.Unlock()

	if err := s.Retire("k-initial"); err != nil {
		t.Fatalf("过期后应可下线: %v", err)
	}
	if kids := s.Kids(); len(kids) != 1 || kids[0] != "k-second" {
		t.Fatalf("下线后只剩新密钥，实际 %v", kids)
	}
	// 下线后旧 token 验签失败——这正是必须等 TTL 的原因。
	if _, err := s.Parse(oldToken); err == nil {
		t.Fatal("下线后旧 token 应验签失败")
	}
}

// TestListReportsRetirableAt：列表要给出"何时可下线"，而不是只标状态。
func TestListReportsRetirableAt(t *testing.T) {
	s := newRotateSigner(t, 15*time.Minute)
	newKey, _ := GenerateKey("k-second")
	if _, err := s.Rotate(newKey); err != nil {
		t.Fatalf("轮换失败: %v", err)
	}

	var old, cur *KeyInfo
	for i := range s.List() {
		info := s.List()[i]
		if info.KID == "k-initial" {
			old = &info
		}
		if info.KID == "k-second" {
			cur = &info
		}
	}
	if old == nil || cur == nil {
		t.Fatal("应同时列出新旧两把密钥")
	}
	if old.Status != KeyStatusPublished || old.RetirableAt == nil {
		t.Fatalf("旧密钥应为 published 且带可下线时间: %+v", old)
	}
	if cur.Status != KeyStatusSigning || cur.RetirableAt != nil {
		t.Fatalf("新密钥应为 signing 且无可下线时间: %+v", cur)
	}
}

// TestFileStoreRoundTrip：轮换状态必须能在重启后完整恢复。
//
// 这是最容易漏的一环：如果只改内存，重启后轮换白做、JWKS 还会少一把公钥。
func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)

	s := newRotateSigner(t, 15*time.Minute)
	newKey, _ := GenerateKey("k-second")
	if _, err := s.Rotate(newKey); err != nil {
		t.Fatalf("轮换失败: %v", err)
	}
	active, states := s.Snapshot()
	if err := store.Save(active, states); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	if !store.Exists() {
		t.Fatal("状态文件应已创建")
	}

	tokenBefore, _, err := s.Issue(IssueInput{Subject: "u-1", Audience: "app-a", Scope: "openid"})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	// 模拟进程重启：从文件重建签名器。
	keys, err := store.Load()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("应加载 2 把密钥，实际 %d", len(keys))
	}
	if keys[0].KID != "k-second" {
		t.Fatalf("active 密钥必须排第一（NewSigner 的约定），实际 %s", keys[0].KID)
	}
	restored, err := NewSigner(Options{Issuer: "https://auth.test", TTL: 15 * time.Minute, Keys: keys})
	if err != nil {
		t.Fatalf("重建签名器失败: %v", err)
	}
	if restored.ActiveKID() != "k-second" {
		t.Fatalf("重启后应继续用新密钥签名，实际 %s", restored.ActiveKID())
	}
	// 旧 token 在重启后仍然验签通过 —— 说明旧公钥被正确持久化。
	if _, err := restored.Parse(tokenBefore); err != nil {
		t.Fatalf("重启后旧 token 应仍能验签: %v", err)
	}
	// 旧密钥的私钥不应被持久化（只有公钥）。
	if keys[1].Private != nil {
		t.Fatal("旧密钥不应持久化私钥：它已经不需要签名")
	}
}

// TestFileStoreNoPrivateKeyLeakInJWKS：JWKS 里绝不能出现私钥字段。
func TestFileStoreNoPrivateKeyLeakInJWKS(t *testing.T) {
	s := newRotateSigner(t, 15*time.Minute)
	raw, err := s.JWKS()
	if err != nil {
		t.Fatalf("JWKS 失败: %v", err)
	}
	body := string(raw)
	for _, banned := range []string{"d=", "priv", "PRIVATE"} {
		if strings.Contains(body, banned) {
			t.Fatalf("JWKS 泄露了私钥字段 %q: %s", banned, body)
		}
	}
}
