package admin

import (
	"testing"
	"time"
)

func futureGrant(role Role) Grant {
	exp := time.Now().UTC().Add(time.Hour)
	return Grant{SubjectID: "admin:1", Role: role, ExpiresAt: &exp}
}

// TestUserCanUnionsRoleAndGrants 是 K 组权限判定的核心：
// 基础角色与附加授权取并集。
//
// 如果只认 role，grants 等于没生效；如果只认 grants，现有管理员会在
// K 组上线瞬间全部失去权限——两种都是事故。
func TestUserCanUnionsRoleAndGrants(t *testing.T) {
	u := &User{ID: 1, Role: RoleViewer}
	if u.Can("app:write") {
		t.Fatal("viewer 不应有 app:write")
	}
	// 附加一条 operator 授权后，token:revoke 应生效。
	u.Grants = []Grant{futureGrant(RoleOperator)}
	if !u.Can("token:revoke") {
		t.Fatal("grants 里的 operator 应让 token:revoke 生效")
	}
	// 原有 role 的权限不受影响。
	if !u.Can("app:read") {
		t.Fatal("基础角色的读权限应保留")
	}
}

// TestGrantExpiryAndRevocation：过期与被撤销的授权不参与判定。
func TestGrantExpiryAndRevocation(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	revokedAt := time.Now().UTC().Add(-time.Minute)

	u := &User{ID: 1, Role: RoleViewer, Grants: []Grant{
		{SubjectID: "admin:1", Role: RoleOperator, ExpiresAt: &past},
		{SubjectID: "admin:1", Role: RoleConfigAdmin, RevokedAt: &revokedAt},
	}}
	if u.Can("token:revoke") {
		t.Fatal("已过期的授权不应生效")
	}
	if u.Can("app:write") {
		t.Fatal("已撤销的授权不应生效")
	}
}

// TestSuperAdminAlwaysTrue：super_admin 拥有全部权限（含 admin:grant）。
func TestSuperAdminAlwaysTrue(t *testing.T) {
	u := &User{ID: 1, Role: RoleSuperAdmin}
	for _, perm := range []string{"app:write", "admin:grant", "key:write", "不存在的权限"} {
		if !u.Can(perm) {
			t.Fatalf("super_admin 应拥有 %s", perm)
		}
	}
}

// TestViewerCannotGrant：viewer 拿不到 admin:grant。
//
// 这是 K 组最关键的边界：能改"谁能进管理端"的人必须是最小集合。
func TestViewerCannotGrant(t *testing.T) {
	u := &User{ID: 1, Role: RoleViewer}
	if u.Can("admin:grant") {
		t.Fatal("viewer 不应拥有 admin:grant")
	}
	// 即便是 config_admin / operator 也不行。
	for _, r := range []Role{RoleOperator, RoleConfigAdmin} {
		if (&User{ID: 1, Role: r}).Can("admin:grant") {
			t.Fatalf("%s 不应拥有 admin:grant", r)
		}
	}
}

// TestNilUserCanIsFalse：nil 安全（Require 中间件在异常路径会拿到 nil）。
func TestNilUserCanIsFalse(t *testing.T) {
	var u *User
	if u.Can("app:read") {
		t.Fatal("nil 用户不应拥有任何权限")
	}
}

// TestGrantEffective 覆盖 Effective 的三种状态。
func TestGrantEffective(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	revoked := now.Add(-time.Minute)

	cases := []struct {
		name  string
		grant Grant
		want  bool
	}{
		{"长期有效", Grant{Role: RoleViewer}, true},
		{"临时未过期", Grant{Role: RoleViewer, ExpiresAt: &future}, true},
		{"已过期", Grant{Role: RoleViewer, ExpiresAt: &past}, false},
		{"已撤销", Grant{Role: RoleViewer, RevokedAt: &revoked}, false},
		{"已撤销且未过期", Grant{Role: RoleViewer, ExpiresAt: &future, RevokedAt: &revoked}, false},
	}
	for _, c := range cases {
		if got := c.grant.Effective(now); got != c.want {
			t.Fatalf("%s: want %v got %v", c.name, c.want, got)
		}
	}
}

// TestSubjectOf：subject_id 命名必须与审计一致（admin:<id>）。
func TestSubjectOf(t *testing.T) {
	cases := map[int64]string{1: "admin:1", 0: "admin:0", 12345: "admin:12345"}
	for id, want := range cases {
		if got := SubjectOf(id); got != want {
			t.Fatalf("SubjectOf(%d)=%q, want %q", id, got, want)
		}
	}
}
