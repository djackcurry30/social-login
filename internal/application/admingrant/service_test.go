package admingrant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

type fakeGrants struct {
	rows      []admin.Grant
	inserted  *admin.Grant
	insertErr error
	revoked   int64
	lastFilt  admin.GrantFilter
}

func (f *fakeGrants) List(_ context.Context, flt admin.GrantFilter) ([]admin.Grant, int64, error) {
	f.lastFilt = flt
	return f.rows, int64(len(f.rows)), nil
}

func (f *fakeGrants) Insert(_ context.Context, g *admin.Grant) (*admin.Grant, error) {
	if f.insertErr != nil {
		return nil, f.insertErr
	}
	cp := *g
	cp.ID = 7
	f.inserted = &cp
	return &cp, nil
}

func (f *fakeGrants) Revoke(_ context.Context, id int64, at time.Time) (*admin.Grant, error) {
	if id == 404 {
		return nil, admin.ErrGrantNotFound
	}
	f.revoked = id
	now := at
	return &admin.Grant{ID: id, SubjectID: "admin:2", Role: admin.RoleOperator, RevokedAt: &now}, nil
}

func (f *fakeGrants) FindByID(context.Context, int64) (*admin.Grant, error) {
	return nil, admin.ErrGrantNotFound
}

func (f *fakeGrants) ListEffectiveBySubject(context.Context, string, time.Time) ([]admin.Grant, error) {
	return nil, nil
}

type fakeUsers struct {
	exists map[int64]bool
}

func (f *fakeUsers) FindByUsername(context.Context, string) (*admin.User, error) {
	return nil, admin.ErrNotFound
}
func (f *fakeUsers) FindByID(_ context.Context, id int64) (*admin.User, error) {
	if f.exists[id] {
		return &admin.User{ID: id, Username: "u", Role: admin.RoleViewer, Status: 1}, nil
	}
	return nil, admin.ErrNotFound
}
func (f *fakeUsers) Insert(context.Context, *admin.User) (*admin.User, error) { return nil, nil }
func (f *fakeUsers) UpdateLastLoginAt(context.Context, int64) error           { return nil }
func (f *fakeUsers) UpdatePassword(context.Context, int64, string) error      { return nil }

func newSvc() (*Service, *fakeGrants) {
	g := &fakeGrants{}
	return New(Deps{
		Grants: g,
		Users:  &fakeUsers{exists: map[int64]bool{1: true, 2: true}},
	}), g
}

func superAdmin() *admin.Principal {
	return &admin.Principal{User: &admin.User{ID: 1, Role: admin.RoleSuperAdmin}}
}

func TestGrantRequiresReason(t *testing.T) {
	svc, g := newSvc()
	_, err := svc.Grant(context.Background(), GrantInput{
		SubjectID: "admin:2", Role: "operator", Reason: "x", Principal: superAdmin(),
	})
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if g.inserted != nil {
		t.Fatal("校验失败不得落库")
	}
}

func TestGrantRejectsUnknownRole(t *testing.T) {
	svc, _ := newSvc()
	_, err := svc.Grant(context.Background(), GrantInput{
		SubjectID: "admin:2", Role: "root", Reason: "临时提权", Principal: superAdmin(),
	})
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("未知角色应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

// TestGrantRequiresLocalSubjectFormat：subject 必须形如 admin:<id>。
func TestGrantRequiresLocalSubjectFormat(t *testing.T) {
	svc, _ := newSvc()
	for _, bad := range []string{"user@example.com", "admin:", "admin:abc"} {
		_, err := svc.Grant(context.Background(), GrantInput{
			SubjectID: bad, Role: "operator", Reason: "临时提权", Principal: superAdmin(),
		})
		if err == nil {
			t.Fatalf("非法 subject %q 必须拒绝", bad)
		}
	}
}

// TestGrantRejectsMissingAccount：不能给不存在的账号授权。
//
// 建出"授予了不存在的人"的记录会在排查时被当成"授权没生效"。
func TestGrantRejectsMissingAccount(t *testing.T) {
	svc, _ := newSvc()
	_, err := svc.Grant(context.Background(), GrantInput{
		SubjectID: "admin:999", Role: "operator", Reason: "临时提权", Principal: superAdmin(),
	})
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("应为 404，实际 %v", errs.CodeOf(err))
	}
}

func TestGrantRejectsPastExpiry(t *testing.T) {
	svc, _ := newSvc()
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	_, err := svc.Grant(context.Background(), GrantInput{
		SubjectID: "admin:2", Role: "operator", Reason: "临时提权",
		ExpiresAt: past, Principal: superAdmin(),
	})
	// 过去的到期时间等于"授予即失效"，几乎必然是填错。
	if err == nil {
		t.Fatal("过去的 expires_at 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestGrantSetsGrantedBy(t *testing.T) {
	svc, g := newSvc()
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	item, err := svc.Grant(context.Background(), GrantInput{
		SubjectID: "admin:2", Role: "operator", Reason: "临时处理客诉",
		ExpiresAt: future, Principal: superAdmin(),
	})
	if err != nil {
		t.Fatalf("授予失败: %v", err)
	}
	if g.inserted.GrantedBy != "admin:1" {
		t.Fatalf("granted_by 应为操作人，实际 %s", g.inserted.GrantedBy)
	}
	if item == nil || item.ID != 7 || !item.Effective {
		t.Fatalf("出参不符: %+v", item)
	}
}

func TestRevokeRequiresReason(t *testing.T) {
	svc, g := newSvc()
	err := svc.Revoke(context.Background(), 7, "x", superAdmin())
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if g.revoked != 0 {
		t.Fatal("校验失败不得撤销")
	}
}

// TestRevokeMapsNotFound：裸领域错误会被折算成 500，必须归一化。
func TestRevokeMapsNotFound(t *testing.T) {
	svc, _ := newSvc()
	err := svc.Revoke(context.Background(), 404, "撤销不存在的授权", superAdmin())
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("应为 404，实际 %v", errs.CodeOf(err))
	}
}

func TestRevokeSuccess(t *testing.T) {
	svc, g := newSvc()
	if err := svc.Revoke(context.Background(), 7, "员工离职", superAdmin()); err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	if g.revoked != 7 {
		t.Fatalf("应撤销 7，实际 %d", g.revoked)
	}
}

func TestListFilters(t *testing.T) {
	svc, g := newSvc()
	now := time.Now().UTC()
	g.rows = []admin.Grant{{ID: 1, SubjectID: "admin:2", Role: admin.RoleOperator, GrantedAt: now}}
	out, err := svc.List(context.Background(), ListInput{SubjectID: "admin:2", IncludeRevoked: true})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if g.lastFilt.SubjectID != "admin:2" || !g.lastFilt.IncludeRevoked {
		t.Fatalf("过滤条件未透传: %+v", g.lastFilt)
	}
	if len(out.Items) != 1 || !out.Items[0].Effective {
		t.Fatalf("出参不符: %+v", out.Items)
	}
}

// TestInsertErrorPropagates：仓储错误要透出（不能静默当成成功）。
func TestInsertErrorPropagates(t *testing.T) {
	svc, g := newSvc()
	g.insertErr = errors.New("db down")
	if _, err := svc.Grant(context.Background(), GrantInput{
		SubjectID: "admin:2", Role: "operator", Reason: "临时提权", Principal: superAdmin(),
	}); err == nil {
		t.Fatal("仓储错误必须透出")
	}
}
