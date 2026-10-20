package adminapp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
)

// TestAppViewDoesNotLeakSecretHash 是一次回归防护。
//
// 真实发生过的问题：GET /admin/v1/apps 直接把 *tenant.Application 序列化出去，
// 于是 app_secret 的哈希连同内部字段一起发给了 viewer 角色。哈希虽不可逆，
// 但它是验签密钥的全部秘密所在，泄露后可离线爆破——属于不必要的暴露。
//
// 修复手段是 AppView 白名单投影。这条断言用 JSON 层面的结果来守：
// 只要有人把领域模型重新塞回响应，它就会红。
func TestAppViewDoesNotLeakSecretHash(t *testing.T) {
	a := &tenant.Application{
		ID:            1,
		AppCode:       "abc",
		Name:          "应用一",
		AppSecretHash: "hmac-sha256:deadbeef",
		Status:        1,
		AccountMode:   tenant.AccountModeRemote,
		CreatedAt:     time.Unix(1_700_000_000, 0).UTC(),
		UpdatedAt:     time.Unix(1_700_000_100, 0).UTC(),
	}
	if _, err := json.Marshal(a); err == nil {
		// 领域模型本身仍可序列化（审计快照等场景可能需要），
		// 但不得出现在管理端响应里——下面用视图断言。
		t.Log("领域模型可序列化，不影响本断言")
	}

	raw, err := json.Marshal(toAppView(a))
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if _, ok := m["AppSecretHash"]; ok {
		t.Fatal("AppSecretHash 不得出现在管理端响应里")
	}
	if _, ok := m["app_secret_hash"]; ok {
		t.Fatal("app_secret_hash 不得出现在管理端响应里")
	}
	if m["AppCode"] != "abc" || m["Name"] != "应用一" {
		t.Fatalf("白名单字段丢失（前端依赖大驼峰 key）: %v", m)
	}
}

// TestToAppViewNil 保证 nil 不 panic（仓储返回 nil, nil 的边界）。
func TestToAppViewNil(t *testing.T) {
	if toAppView(nil) != nil {
		t.Fatal("nil 输入应返回 nil")
	}
}
