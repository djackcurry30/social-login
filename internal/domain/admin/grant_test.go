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

// TestPermissionsForSuperAdminIsWildcard：super_admin 返回通配符，
// 而不是把权限字符串逐一枚举——权限表会随接口增长，枚举必然漏。
func TestPermissionsForSuperAdminIsWildcard(t *testing.T) {
	u := &User{ID: 1, Role: RoleSuperAdmin}
	got := u.Permissions()
	if len(got) != 1 || got[0] != "*" {
		t.Fatalf("super_admin 应返回 [\"*\"]，实际 %v", got)
	}
}

// TestPermissionsIncludesEffectiveGrants：/auth/me 下发的权限集必须含 grants。
//
// 前端据此禁用无权限的按钮；如果这里漏了 grants，viewer 加了 operator 授权后
// 按钮仍然是灰的——"给了我权限却不让点"，比不给更难解释。
func TestPermissionsIncludesEffectiveGrants(t *testing.T) {
	u := &User{ID: 1, Role: RoleViewer, Grants: []Grant{futureGrant(RoleOperator)}}
	got := u.Permissions()
	has := func(p string) bool {
		for _, v := range got {
			if v == p {
				return true
			}
		}
		return false
	}
	if !has("token:revoke") {
		t.Fatalf("应包含 grants 带来的 token:revoke，实际 %v", got)
	}
	if !has("app:read") {
		t.Fatalf("应保留基础角色的 app:read，实际 %v", got)
	}
	if has("admin:grant") {
		t.Fatal("viewer + operator 不应包含 admin:grant")
	}
	// 稳定排序：前端会缓存它，顺序乱跳没有意义。
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("权限集应有序: %v", got)
		}
	}
}

// TestPermissionsExcludesExpiredGrante：过期授权不进权限集。
func TestPermissionsExcludesExpiredGrante(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	u := &User{ID: 1, Role: RoleViewer, Grants: []Grant{
		{SubjectID: "admin:1", Role: RoleOperator, ExpiresAt: &past},
	}}
	for _, p := range u.Permissions() {
		if p == "token:revoke" {
			t.Fatal("过期授权不应出现在权限集里")
		}
	}
}

func TestPermissionsNilUser(t *testing.T) {
	var u *User
	if got := u.Permissions(); got != nil {
		t.Fatalf("nil 用户应返回 nil，实际 %v", got)
	}
}
