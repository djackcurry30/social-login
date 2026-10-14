package crypto

import (
	"strings"
	"testing"

	"github.com/djackcurry30/social-login/internal/domain/identity"
)

// TestClaimHasherDeterministicWithinApp 验证 claim 哈希的核心性质。
//
// 如果这条不成立，"按手机号反查身份"就会整体失效——而它正是 C3 下归并判定的
// 全部依据。失败模式很隐蔽：不报错，只是永远匹配不上，表现为"归并功能不工作"。
func TestClaimHasherDeterministicWithinApp(t *testing.T) {
	t.Parallel()

	h := NewClaimHasher([]byte("static-salt"))

	const (
		appID     = int64(42)
		claimType = identity.ClaimTypePhone
		value     = "13800138000"
	)

	first := h.Hash(appID, claimType, value)
	if first == "" {
		t.Fatal("哈希不应为空")
	}
	for i := 0; i < 5; i++ {
		if got := h.Hash(appID, claimType, value); got != first {
			t.Fatalf("同一应用内相同凭证必须哈希稳定：第 %d 次得到 %s，首次为 %s", i, got, first)
		}
	}
	if len(first) != 64 {
		t.Fatalf("期望 64 位十六进制（SHA-256），实际长度 %d", len(first))
	}
	if strings.Contains(first, value) {
		t.Fatal("哈希中不得包含明文")
	}
}

// TestClaimHasherIsolatedPerApp 验证跨应用无法关联同一凭证（约束 C1）。
//
// 这是把盐与 appID 绑定带来的副产品收益：即使两个业务应用接入的是同一个
// 微信公众号、同一个用户、同一个手机号，也无法从哈希看出两者是同一个人。
func TestClaimHasherIsolatedPerApp(t *testing.T) {
	t.Parallel()

	h := NewClaimHasher([]byte("static-salt"))
	const (
		claimType = identity.ClaimTypePhone
		value     = "13800138000"
	)

	a := h.Hash(1, claimType, value)
	b := h.Hash(2, claimType, value)
	if a == b {
		t.Fatal("不同应用下相同凭证必须得到不同哈希（约束 C1 的隔离要求）")
	}
}

// TestClaimHasherDependsOnTypeAndValue 验证输入任何一部分变化都会改变结果。
func TestClaimHasherDependsOnTypeAndValue(t *testing.T) {
	t.Parallel()

	h := NewClaimHasher([]byte("static-salt"))
	const appID = int64(1)

	base := h.Hash(appID, identity.ClaimTypePhone, "13800138000")
	if base == h.Hash(appID, identity.ClaimTypeEmail, "13800138000") {
		t.Error("凭证类型参与哈希：手机号与邮箱即使取值相同也必须不同")
	}
	if base == h.Hash(appID, identity.ClaimTypePhone, "13800138001") {
		t.Error("取值变化必须改变哈希")
	}
}

// TestClaimHasherDifferentSaltDifferentResult 说明盐必须稳定。
func TestClaimHasherDifferentSaltDifferentResult(t *testing.T) {
	t.Parallel()

	a := NewClaimHasher([]byte("salt-a")).Hash(1, identity.ClaimTypePhone, "13800138000")
	b := NewClaimHasher([]byte("salt-b")).Hash(1, identity.ClaimTypePhone, "13800138000")
	if a == b {
		t.Fatal("不同盐必须得到不同哈希——这正是\"变更 claim_salt 会导致历史 claim 全部失配\"的原因")
	}
}

// TestAppSecretHasher 验证应用密钥哈希与恒定时间比较。
func TestAppSecretHasher(t *testing.T) {
	t.Parallel()

	h := NewAppSecretHasher([]byte("secret-salt"))
	secret := "0123456789abcdef0123456789abcdef"

	stored := h.Hash(secret)
	if stored == "" || strings.Contains(stored, secret) {
		t.Fatalf("应用密钥必须以哈希形式存储")
	}
	if !h.Verify(secret, stored) {
		t.Fatal("正确密钥应校验通过")
	}
	if h.Verify(secret+"x", stored) {
		t.Fatal("错误密钥必须校验失败")
	}
	if h.Verify("", stored) {
		t.Fatal("空密钥必须校验失败")
	}
	if h.Verify(secret, "") {
		t.Fatal("空的存储哈希必须校验失败，不能因为两者都空而通过")
	}
}
