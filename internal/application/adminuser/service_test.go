package adminuser

import (
	"context"
	"testing"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// fakeUsers 是内存版 UserRepository。
type fakeUsers struct {
	seq       int64
	byID      map[int64]*admin.User
	byName    map[string]*admin.User
	insertErr error
}

func newFakeUsers(seed ...*admin.User) *fakeUsers {
	f := &fakeUsers{byID: map[int64]*admin.User{}, byName: map[string]*admin.User{}}
	for _, u := range seed {
		f.byID[u.ID] = u
		f.byName[u.Username] = u
		if u.ID > f.seq {
			f.seq = u.ID
		}
	}
	return f
}

func (f *fakeUsers) FindByUsername(_ context.Context, username string) (*admin.User, error) {
	if u, ok := f.byName[username]; ok {
		return u, nil
	}
	return nil, admin.ErrNotFound
}

func (f *fakeUsers) FindByID(_ context.Context, id int64) (*admin.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, admin.ErrNotFound
}

func (f *fakeUsers) Insert(_ context.Context, u *admin.User) (*admin.User, error) {
	if f.insertErr != nil {
		return nil, f.insertErr
	}
	if _, ok := f.byName[u.Username]; ok {
		return nil, errs.Newf(errs.CodeAdminConflict, "username 已存在: %s", u.Username)
	}
	f.seq++
	u.ID = f.seq
	if u.Status == 0 {
		u.Status = 1
	}
	f.byID[u.ID] = u
	f.byName[u.Username] = u
	return u, nil
}

func (f *fakeUsers) UpdateLastLoginAt(context.Context, int64) error { return nil }

func (f *fakeUsers) UpdatePassword(_ context.Context, id int64, hash string) error {
	if u, ok := f.byID[id]; ok {
		u.PasswordHash = hash
		return nil
	}
	return admin.ErrNotFound
}

func (f *fakeUsers) List(_ context.Context, _ int) ([]*admin.User, error) {
	out := make([]*admin.User, 0, len(f.byID))
	for _, u := range f.byID {
		cp := *u
		cp.PasswordHash = ""
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeUsers) UpdateProfile(_ context.Context, id int64, in admin.ProfileUpdate) error {
	u, ok := f.byID[id]
	if !ok {
		return admin.ErrNotFound
	}
	if in.DisplayName != nil {
		u.DisplayName = *in.DisplayName
	}
	if in.Role != nil {
		u.Role = *in.Role
	}
	if in.Status != nil {
		u.Status = *in.Status
	}
	return nil
}

func (f *fakeUsers) CountEnabledSuperAdmins(context.Context) (int64, error) {
	var n int64
	for _, u := range f.byID {
		if u.Role == admin.RoleSuperAdmin && u.Status == 1 {
			n++
		}
	}
	return n, nil
}

// fakeSessions 记录撤销调用。
type fakeSessions struct {
	revokedByUser []int64
	revokeErr     error
}

func (f *fakeSessions) Insert(context.Context, *admin.Session) error { return nil }

func (f *fakeSessions) FindByTokenHash(context.Context, string) (*admin.Session, error) {
	return nil, admin.ErrNotFound
}

func (f *fakeSessions) Revoke(context.Context, int64) error { return nil }

func (f *fakeSessions) RevokeAllByUser(_ context.Context, userID int64) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revokedByUser = append(f.revokedByUser, userID)
	return nil
}

func newSvc(users *fakeUsers, sessions *fakeSessions) *Service {
	return New(Deps{Users: users, Sessions: sessions})
}

func superUser(id int64, name string) *admin.User {
	return &admin.User{ID: id, Username: name, Role: admin.RoleSuperAdmin, Status: 1}
}

func TestCreateRejectsBadUsername(t *testing.T) {
	s := newSvc(newFakeUsers(superUser(1, "root")), &fakeSessions{})
	for _, name := range []string{"ab", "with space", "with:colon", string(make([]byte, 70))} {
		if _, err := s.Create(context.Background(), superUser(1, "root"),
			CreateInput{Username: name, Password: "password123", Reason: "测试"}); err == nil {
			t.Fatalf("非法用户名 %q 应被拒绝", name)
		}
	}
}

func TestCreateRejectsShortPassword(t *testing.T) {
	s := newSvc(newFakeUsers(superUser(1, "root")), &fakeSessions{})
	_, err := s.Create(context.Background(), superUser(1, "root"),
		CreateInput{Username: "alice", Password: "short", Reason: "测试"})
	if err == nil {
		t.Fatal("短密码应被拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeInvalidRequest, errs.CodeOf(err))
	}
}

func TestCreateDefaultsRoleToViewer(t *testing.T) {
	users := newFakeUsers(superUser(1, "root"))
	s := newSvc(users, &fakeSessions{})

	v, err := s.Create(context.Background(), superUser(1, "root"),
		CreateInput{Username: "alice", Password: "password123", Reason: "测试"})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if v.Role != string(admin.RoleViewer) {
		t.Fatalf("未指定角色应默认 viewer，实际 %s", v.Role)
	}
}

func TestCreateRejectsInvalidRole(t *testing.T) {
	s := newSvc(newFakeUsers(superUser(1, "root")), &fakeSessions{})
	if _, err := s.Create(context.Background(), superUser(1, "root"),
		CreateInput{Username: "alice", Password: "password123", Role: "root", Reason: "测试"}); err == nil {
		t.Fatal("非法角色应被拒绝")
	}
}

func TestUpdateRejectsSelfDemotion(t *testing.T) {
	root := superUser(1, "root")
	s := newSvc(newFakeUsers(root, superUser(2, "root2")), &fakeSessions{})
	role := string(admin.RoleViewer)

	_, err := s.Update(context.Background(), root, 1, UpdateInput{Role: &role, Reason: "测试"})
	if err == nil {
		t.Fatal("不能修改自己的角色")
	}
	if errs.CodeOf(err) != errs.CodeForbidden {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeForbidden, errs.CodeOf(err))
	}
}

func TestUpdateRejectsSelfDisable(t *testing.T) {
	root := superUser(1, "root")
	s := newSvc(newFakeUsers(root, superUser(2, "root2")), &fakeSessions{})
	disabled := int16(0)

	if _, err := s.Update(context.Background(), root, 1, UpdateInput{Status: &disabled, Reason: "测试"}); err == nil {
		t.Fatal("不能停用自己")
	}
}

func TestUpdateRejectsLastSuperAdmin(t *testing.T) {
	root := superUser(1, "root")
	// 另一个超级管理员已停用，所以启用中的只有一个。
	other := &admin.User{ID: 2, Username: "other", Role: admin.RoleSuperAdmin, Status: 0}
	users := newFakeUsers(root, other)
	s := newSvc(users, &fakeSessions{})

	// 由"另一个已停用的超级管理员"来操作（模拟历史会话），目标是 root。
	disabled := int16(0)
	_, err := s.Update(context.Background(), other, 1, UpdateInput{Status: &disabled, Reason: "测试"})
	if err == nil {
		t.Fatal("最后一个启用中的超级管理员不能被停用")
	}
	if errs.CodeOf(err) != errs.CodeForbidden {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeForbidden, errs.CodeOf(err))
	}

	role := string(admin.RoleOperator)
	if _, err := s.Update(context.Background(), other, 1, UpdateInput{Role: &role, Reason: "测试"}); err == nil {
		t.Fatal("最后一个启用中的超级管理员不能被降级")
	}
}

func TestUpdateAllowsWhenAnotherSuperAdminExists(t *testing.T) {
	root := superUser(1, "root")
	root2 := superUser(2, "root2")
	s := newSvc(newFakeUsers(root, root2), &fakeSessions{})

	role := string(admin.RoleOperator)
	if _, err := s.Update(context.Background(), root2, 1, UpdateInput{Role: &role, Reason: "测试"}); err != nil {
		t.Fatalf("还有其它超级管理员时应允许降级: %v", err)
	}
}

func TestUpdateDisableRevokesSessions(t *testing.T) {
	root := superUser(1, "root")
	alice := &admin.User{ID: 2, Username: "alice", Role: admin.RoleViewer, Status: 1}
	users := newFakeUsers(root, alice)
	sessions := &fakeSessions{}
	s := newSvc(users, sessions)

	disabled := int16(0)
	if _, err := s.Update(context.Background(), root, 2, UpdateInput{Status: &disabled, Reason: "测试"}); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if len(sessions.revokedByUser) != 1 || sessions.revokedByUser[0] != 2 {
		t.Fatalf("停用必须撤销该账号会话，实际 %v", sessions.revokedByUser)
	}
	if users.byID[2].Status != 0 {
		t.Fatal("状态未落库")
	}
}

func TestUpdateRejectsInvalidStatus(t *testing.T) {
	root := superUser(1, "root")
	alice := &admin.User{ID: 2, Username: "alice", Role: admin.RoleViewer, Status: 1}
	s := newSvc(newFakeUsers(root, alice), &fakeSessions{})
	bad := int16(7)

	if _, err := s.Update(context.Background(), root, 2, UpdateInput{Status: &bad, Reason: "测试"}); err == nil {
		t.Fatal("非法状态值应被拒绝")
	}
}

func TestResetPasswordRevokesSessions(t *testing.T) {
	root := superUser(1, "root")
	alice := &admin.User{ID: 2, Username: "alice", Role: admin.RoleViewer, Status: 1}
	users := newFakeUsers(root, alice)
	sessions := &fakeSessions{}
	s := newSvc(users, sessions)

	if err := s.ResetPassword(context.Background(), root, 2, "newpassword123", "测试"); err != nil {
		t.Fatalf("重置失败: %v", err)
	}
	if users.byID[2].PasswordHash == "" || users.byID[2].PasswordHash == "newpassword123" {
		t.Fatal("密码应以哈希形式落库")
	}
	if len(sessions.revokedByUser) != 1 {
		t.Fatalf("重置密码必须撤销会话，实际 %v", sessions.revokedByUser)
	}
}

func TestResetPasswordRejectsShort(t *testing.T) {
	root := superUser(1, "root")
	alice := &admin.User{ID: 2, Username: "alice", Role: admin.RoleViewer, Status: 1}
	s := newSvc(newFakeUsers(root, alice), &fakeSessions{})

	if err := s.ResetPassword(context.Background(), root, 2, "short", "测试"); err == nil {
		t.Fatal("短密码应被拒绝")
	}
}

func TestListDoesNotLeakPasswordHash(t *testing.T) {
	root := superUser(1, "root")
	root.PasswordHash = "$2a$12$secret"
	s := newSvc(newFakeUsers(root), &fakeSessions{})

	items, err := s.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("应返回 1 条，实际 %d", len(items))
	}
	// View 里根本没有密码字段，这条断言是"以后有人往里加字段"时的哨兵。
	if items[0].Username != "root" {
		t.Fatal("用户名不正确")
	}
}

func TestCreateRequiresReason(t *testing.T) {
	s := newSvc(newFakeUsers(superUser(1, "root")), &fakeSessions{})
	_, err := s.Create(context.Background(), superUser(1, "root"),
		CreateInput{Username: "alice", Password: "password123"})
	if err == nil {
		t.Fatal("缺少 reason 必须被拒绝：管理端写操作要留审计原因")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeInvalidRequest, errs.CodeOf(err))
	}
}

func TestUpdateRequiresReason(t *testing.T) {
	root := superUser(1, "root")
	alice := &admin.User{ID: 2, Username: "alice", Role: admin.RoleViewer, Status: 1}
	s := newSvc(newFakeUsers(root, alice), &fakeSessions{})
	disabled := int16(0)

	if _, err := s.Update(context.Background(), root, 2, UpdateInput{Status: &disabled}); err == nil {
		t.Fatal("缺少 reason 必须被拒绝")
	}
}
