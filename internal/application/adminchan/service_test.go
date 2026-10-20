package adminchan

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
)

// TestConfigViewHidesCipherMaterial 是安全回归。
//
// 此前 ListConfigs / GetConfig 直接把 *tenant.ProviderConfig 序列化返回，
// 响应里带着 SecretCipher（信封加密后的密文）、SecretCipherPrev 与
// SecretDEKID（KEK 版本）。密文需要 KEK 才能解开，但把它和 KEK 版本一起
// 下发给 viewer，等于给"KEK 泄露"这个场景补上最后一块拼图；而管理端界面
// 真正需要的只是"是否处于轮换过渡期"。
func TestConfigViewHidesCipherMaterial(t *testing.T) {
	now := time.Now().UTC()
	c := &tenant.ProviderConfig{
		ID:               7,
		AppID:            3,
		Platform:         "wechat",
		Scene:            "mini_program",
		ConfigKey:        "default",
		ProviderAppID:    "wx123",
		SecretCipher:     []byte("cipher-v2"),
		SecretCipherPrev: []byte("cipher-v1"),
		SecretDEKID:      "local-kek-v1",
		Env:              "prod",
		Extra:            map[string]any{"k": "v"},
		Version:          2,
		Status:           1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	raw, err := json.Marshal(toConfigView(c))
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	for _, banned := range []string{"SecretCipher", "SecretCipherPrev", "SecretDEKID"} {
		if _, ok := m[banned]; ok {
			t.Fatalf("%s 不得出现在管理端响应里", banned)
		}
	}
	if m["SecretRotationInProgress"] != true {
		t.Fatal("轮换过渡期标志应置 true（SecretCipherPrev 非空）")
	}
	if m["ProviderAppID"] != "wx123" || m["Platform"] != "wechat" {
		t.Fatalf("白名单字段丢失: %v", m)
	}
}

// TestConfigViewNoRotation 覆盖"没有上一版凭据"的常态。
func TestConfigViewNoRotation(t *testing.T) {
	v := toConfigView(&tenant.ProviderConfig{ID: 1})
	if v.SecretRotationInProgress {
		t.Fatal("无 SecretCipherPrev 时不应标记为轮换中")
	}
	if toConfigView(nil) != nil {
		t.Fatal("nil 输入应返回 nil")
	}
}
