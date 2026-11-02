package cryptox

import (
	"bytes"
	"testing"
)

const testSalt = "unit-test-salt-please-ignore"

func newHasher(t *testing.T) *ClaimHasher {
	t.Helper()
	h, err := NewClaimHasher([]byte(testSalt))
	if err != nil {
		t.Fatalf("构造哈希器失败: %v", err)
	}
	return h
}

// TestHashIsStable 同一个应用、同一类型、同一值必须恒等——
// 这是"按手机号反查账号"能成立的全部前提。
func TestHashIsStable(t *testing.T) {
	h := newHasher(t)
	a := h.Hash(1, "phone", "13800000000")
	b := h.Hash(1, "phone", "13800000000")
	if !bytes.Equal(a, b) {
		t.Fatal("同一输入的哈希不稳定，按凭证反查将整体失效")
	}
	if len(a) != 32 {
		t.Fatalf("HMAC-SHA256 应输出 32 字节，实际 %d", len(a))
	}
}

// TestHashIsolatedPerApp 跨应用同值必须不同哈希。
//
// 这不是功能需求，而是 C1 隔离的纵深防御：即使库被拖走，
// 也无法用一张彩虹表把两个业务里的同一个手机号关联起来。
func TestHashIsolatedPerApp(t *testing.T) {
	h := newHasher(t)
	a := h.Hash(1, "phone", "13800000000")
	b := h.Hash(2, "phone", "13800000000")
	if bytes.Equal(a, b) {
		t.Fatal("不同应用的同一凭证得到了相同哈希，跨租户可关联")
	}
}

func TestHashDiffersByType(t *testing.T) {
	h := newHasher(t)
	if bytes.Equal(h.Hash(1, "phone", "x@y.z"), h.Hash(1, "email", "x@y.z")) {
		t.Fatal("不同类型同一值不应得到相同哈希")
	}
}

// TestHashRejectsSeparatorCollision 拼接歧义防护。
//
// 消息布局用 NUL 分隔 type 与 value。若直接字符串拼接，
// ("a", "\x00b") 与 ("a\x00", "b") 会撞成同一条消息。
func TestHashRejectsSeparatorCollision(t *testing.T) {
	h := newHasher(t)
	if bytes.Equal(h.Hash(1, "a", "\x00b"), h.Hash(1, "a\x00", "b")) {
		t.Fatal("拼接歧义未防护：不同 (type,value) 组合产生了相同哈希")
	}
}

func TestNewHasherRejectsShortSalt(t *testing.T) {
	if _, err := NewClaimHasher([]byte("short")); err == nil {
		t.Fatal("过短的盐必须被拒绝：空盐下手机号可被彩虹表反查")
	}
}

// --- 信封加密 ---

func newEnvelope(t *testing.T) *Envelope {
	t.Helper()
	key := bytes.Repeat([]byte{7}, KeySize)
	e, err := NewEnvelope("kek-a", key)
	if err != nil {
		t.Fatalf("构造加密器失败: %v", err)
	}
	return e
}

func TestSealOpenRoundTrip(t *testing.T) {
	e := newEnvelope(t)
	plain := "13800000000"
	ct, err := e.Seal(plain)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if bytes.Contains(ct, []byte(plain)) {
		t.Fatal("密文里出现了明文：加密实际没生效")
	}
	got, err := e.Open(ct, e.CurrentDEKID())
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if got != plain {
		t.Fatalf("解密结果 = %q, want %q", got, plain)
	}
}

// TestSealUsesRandomNonce 同值两次加密必须得到不同密文。
//
// 若相同，说明 nonce 固定——那是 GCM 的致命误用：攻击者可以据此判断
// 两个账号是否绑了同一个手机号，且能伪造密文。
func TestSealUsesRandomNonce(t *testing.T) {
	e := newEnvelope(t)
	a, _ := e.Seal("13800000000")
	b, _ := e.Seal("13800000000")
	if bytes.Equal(a, b) {
		t.Fatal("两次加密结果相同：nonce 没有随机化")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	e := newEnvelope(t)
	ct, _ := e.Seal("13800000000")
	ct[len(ct)-1] ^= 0xFF // 翻转 tag 的一个字节
	if _, err := e.Open(ct, e.CurrentDEKID()); err == nil {
		t.Fatal("篡改后的密文必须解密失败（GCM 认证未被校验）")
	}
}

// TestOpenRejectsWrongDEKID 用错密钥版本时必须明确失败。
//
// 静默返回乱码是最坏的结果：它会以"这个账号的手机号变了"的形式
// 出现在登录链路上，而真正的错误是密钥配置。
func TestOpenRejectsWrongDEKID(t *testing.T) {
	e := newEnvelope(t)
	ct, _ := e.Seal("13800000000")
	if _, err := e.Open(ct, "kek-unknown"); err == nil {
		t.Fatal("未知 dek_id 必须解密失败")
	}
}

// TestKeyRotation 轮换后旧密文仍可解，新密文用新版本。
func TestKeyRotation(t *testing.T) {
	e := newEnvelope(t)
	old, _ := e.Seal("13800000000")

	if err := e.AddKey("kek-b", bytes.Repeat([]byte{9}, KeySize)); err != nil {
		t.Fatalf("登记新密钥失败: %v", err)
	}
	if e.CurrentDEKID() != "kek-b" {
		t.Fatalf("当前密钥版本应为 kek-b，实际 %s", e.CurrentDEKID())
	}

	got, err := e.Open(old, "kek-a")
	if err != nil || got != "13800000000" {
		t.Fatalf("轮换后旧密文应仍可解密，got=%q err=%v", got, err)
	}

	fresh, _ := e.Seal("13900000000")
	if _, err := e.Open(fresh, "kek-a"); err == nil {
		t.Fatal("新密文不应能用旧密钥解开（AAD 不匹配应失败）")
	}
}

func TestDecodeKeyRejectsBadInput(t *testing.T) {
	if _, err := DecodeKey("not-base64!!"); err == nil {
		t.Error("非 Base64 应被拒绝")
	}
	if _, err := DecodeKey("c2hvcnQ="); err == nil { // "short"
		t.Error("长度不足 32 字节应被拒绝")
	}
}
