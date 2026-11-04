package admin

import (
	"testing"
	"time"
)

// 这一组用例守的是"能配不生效"的反面：scope_app_id 存了就必须真的限制住，
// 但也不能把基础角色的全局视野误缩成单应用。

func scopedOperator(id int64) *User {
	app := id
	return &User{
		ID:     1,
		Role:   RoleViewer,
		Status: 1,
		Grants: []Grant{
			{SubjectID: "admin:1", Role: RoleOperator, ScopeAppID: &app},
		},
	}
}

func TestScopeForBaseRoleIsGlobal(t *testing.T) {
	// viewer 的 app:read 来自基础角色，必须全局——否则加了单应用授权
	// 反而让人看不见别的应用，是上线事故级别的退化。
	u := scopedOperator(7)
	if ids, restricted := u.ScopeFor("app:read"); restricted {
		t.Fatalf("基础角色权限不应受限，实际 %v", ids)
	}
}

func TestScopeForGrantOnlyIsRestricted(t *testing.T) {
	u := scopedOperator(7)
	ids, restricted := u.ScopeFor("binding:write")
	if !restricted {
		t.Fatal("仅由单应用授权提供的权限必须受限")
	}
	if len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("范围应为 [7]，实际 %v", ids)
	}
	if u.CanInApp("binding:write", 8) {
		t.Fatal("越界应用不应通过")
	}
	if !u.CanInApp("binding:write", 7) {
		t.Fatal("范围内应用应通过")
	}
}

func TestScopeForGlobalGrantWidens(t *testing.T) {
	// 任何一条全局来源都能让权限回到全局：收紧只能靠少授权，
	// 不能靠"他恰好还有一条单应用授权"来缩小既有能力。
	u := &User{
		ID: 1, Role: RoleViewer, Status: 1,
		Grants: []Grant{{Role: RoleOperator}}, // ScopeAppID = nil
	}
	if _, restricted := u.ScopeFor("binding:write"); restricted {
		t.Fatal("无 scope 的授权应视为全局")
	}
}

func TestScopeForExpiredGrantIgnored(t *testing.T) {
	app := int64(7)
	revoked := time.Now().UTC().Add(-time.Hour)
	u := &User{
		ID: 1, Role: RoleViewer, Status: 1,
		Grants: []Grant{{Role: RoleOperator, ScopeAppID: &app, RevokedAt: &revoked}},
	}
	// 撤销后该授权不再生效：Can 为 false，ScopeFor 返回"受限且空"。
	// 空集合是安全的默认值——它只会少给权限，不会多给。
	if u.Can("binding:write") {
		t.Fatal("已撤销的授权不应生效")
	}
	ids, restricted := u.ScopeFor("binding:write")
	if !restricted || len(ids) != 0 {
		t.Fatalf("应返回受限且空集合，实际 %v restricted=%v", ids, restricted)
	}
}

func TestRestrictAppAutofillsSingleScope(t *testing.T) {
	u := scopedOperator(7)
	id, ok := RestrictApp(u, "binding:write", 0)
	if !ok || id != 7 {
		t.Fatalf("唯一范围应自动补全为 7，实际 %d ok=%v", id, ok)
	}
}

func TestRestrictAppRejectsOutOfScope(t *testing.T) {
	u := scopedOperator(7)
	if _, ok := RestrictApp(u, "binding:write", 8); ok {
		t.Fatal("越界 app_id 必须拒绝")
	}
}

func TestRestrictAppGlobalPassthrough(t *testing.T) {
	u := scopedOperator(7)
	// app:read 是全局权限：请求值原样返回，包括 0（表示不限应用）。
	for _, want := range []int64{0, 8, 9} {
		got, ok := RestrictApp(u, "app:read", want)
		if !ok || got != want {
			t.Fatalf("全局权限应原样返回 %d，实际 %d ok=%v", want, got, ok)
		}
	}
}

func TestRestrictAppNilUserPasses(t *testing.T) {
	// nil 主体 = 内部调用（补偿任务、单测），不受管理员范围约束。
	if id, ok := RestrictApp(nil, "binding:write", 42); !ok || id != 42 {
		t.Fatalf("nil 用户应原样放行，实际 %d ok=%v", id, ok)
	}
}
