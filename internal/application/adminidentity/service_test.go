package adminidentity

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

type fakeIdentities struct {
	rows []identity.Identity
}

func (f *fakeIdentities) ListAdmin(context.Context, identity.AdminQuery) ([]identity.Identity, int64, error) {
	return f.rows, int64(len(f.rows)), nil
}

type fakeIdentityRepo struct {
	item *identity.Identity
	err  error
}

func (f *fakeIdentityRepo) Upsert(context.Context, identity.UpsertInput) (*identity.Identity, error) {
	return nil, nil
}
func (f *fakeIdentityRepo) FindByOpenID(context.Context, identity.FindQuery) (*identity.Identity, error) {
	return nil, identity.ErrNotFound
}
func (f *fakeIdentityRepo) FindByID(context.Context, int64, int64) (*identity.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.item, nil
}

type fakeClaims struct{ rows []identity.Claim }

func (f *fakeClaims) Insert(context.Context, identity.ClaimUpsertInput) (*identity.Claim, error) {
	return nil, nil
}
func (f *fakeClaims) FindVerified(context.Context, int64, string, string) (*identity.Claim, error) {
	return nil, identity.ErrNotFound
}
func (f *fakeClaims) ListByIdentity(context.Context, int64, int64) ([]identity.Claim, error) {
	return f.rows, nil
}
func (f *fakeClaims) Revoke(context.Context, int64, int64, string, string, time.Time) error {
	return nil
}

type fakeBindings struct{ rows []binding.Binding }

func (f *fakeBindings) ListAdmin(context.Context, binding.AdminFilter) ([]binding.Binding, int64, error) {
	return f.rows, int64(len(f.rows)), nil
}

type fakeWriter struct {
	unbound   int
	transfer  int
	lastEvent *binding.AdminEvent
	err       error
}

func (f *fakeWriter) ForceUnbind(_ context.Context, in binding.AdminUnbindInput) (*binding.Binding, error) {
	f.unbound++
	f.lastEvent = in.Event
	if f.err != nil {
		return nil, f.err
	}
	return &binding.Binding{ID: in.BindingID, AppID: 3, ExternalUserID: "u-1",
		Status: binding.StatusUnbound, IdentityID: 9}, nil
}

func (f *fakeWriter) Transfer(_ context.Context, in binding.AdminTransferInput) (*binding.Binding, error) {
	f.transfer++
	f.lastEvent = in.Event
	if f.err != nil {
		return nil, f.err
	}
	return &binding.Binding{ID: in.BindingID, AppID: 3, ExternalUserID: in.TargetUser,
		Status: binding.StatusActive, IdentityID: 9}, nil
}

func newSvc() (*Service, *fakeWriter) {
	w := &fakeWriter{}
	return New(Deps{
		Identities:  &fakeIdentities{},
		IdentityGet: &fakeIdentityRepo{item: &identity.Identity{ID: 9, AppID: 3}},
		Claims:      &fakeClaims{},
		Bindings:    &fakeBindings{},
		Writer:      w,
	}), w
}

func operator() *admin.Principal {
	return &admin.Principal{User: &admin.User{ID: 2, Role: admin.RoleOperator}}
}

// --- 查询 ---

func TestListBindingsRejectsUnknownStatus(t *testing.T) {
	svc, _ := newSvc()
	_, err := svc.ListBindings(context.Background(), BindingListInput{Status: "deleted"})
	if err == nil {
		t.Fatal("非法 status 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestGetIdentityRequiresAppID(t *testing.T) {
	svc, _ := newSvc()
	// 身份按应用隔离：没有 app_id 就无法确定查的是哪一份数据。
	_, err := svc.GetIdentity(context.Background(), 0, 9)
	if err == nil {
		t.Fatal("缺 app_id 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestGetIdentityMapsNotFound(t *testing.T) {
	w := &fakeWriter{}
	svc := New(Deps{
		Identities:  &fakeIdentities{},
		IdentityGet: &fakeIdentityRepo{err: identity.ErrNotFound},
		Claims:      &fakeClaims{},
		Bindings:    &fakeBindings{},
		Writer:      w,
	})
	_, err := svc.GetIdentity(context.Background(), 3, 9)
	// 裸领域错误会被折算成 500。
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("应为 404，实际 %v", errs.CodeOf(err))
	}
}

func TestGetIdentityHidesClaimValue(t *testing.T) {
	svc := New(Deps{
		Identities:  &fakeIdentities{},
		IdentityGet: &fakeIdentityRepo{item: &identity.Identity{ID: 9, AppID: 3}},
		Claims: &fakeClaims{rows: []identity.Claim{{
			ID: 1, Type: "phone", ValueHash: "abcdef0123456789", Verified: true,
			Source: identity.SourceSMSVerified, CreatedAt: time.Now(),
		}}},
		Bindings: &fakeBindings{},
		Writer:   &fakeWriter{},
	})
	d, err := svc.GetIdentity(context.Background(), 3, 9)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(d.Claims) != 1 {
		t.Fatalf("应返回 1 条 claim，实际 %d", len(d.Claims))
	}
	// 只给哈希前缀：完整哈希可用于离线比对，没必要完整暴露。
	if d.Claims[0].ValueHash != "abcdef01" {
		t.Fatalf("应只返回 8 位前缀，实际 %q", d.Claims[0].ValueHash)
	}
}

// --- 强制解绑 ---

func TestForceUnbindRequiresReason(t *testing.T) {
	svc, w := newSvc()
	_, err := svc.ForceUnbind(context.Background(), 5, UnbindInput{Reason: "x", Principal: operator()})
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if w.unbound != 0 {
		t.Fatal("校验失败不得执行解绑")
	}
}

func TestForceUnbindEmitsEvent(t *testing.T) {
	svc, w := newSvc()
	item, err := svc.ForceUnbind(context.Background(), 5, UnbindInput{
		Reason: "用户申诉：非本人绑定", Principal: operator(),
	})
	if err != nil {
		t.Fatalf("解绑失败: %v", err)
	}
	if item == nil || item.Status != binding.StatusUnbound {
		t.Fatalf("出参不符: %+v", item)
	}
	if w.unbound != 1 {
		t.Fatal("应调用一次解绑")
	}
	// 业务方靠 binding.removed 同步自己的数据，事件不能漏。
	if w.lastEvent == nil || w.lastEvent.Type != "binding.removed" {
		t.Fatalf("必须同时写入 binding.removed 事件: %+v", w.lastEvent)
	}
	if w.lastEvent.Payload["admin_reason"] != "用户申诉：非本人绑定" {
		t.Fatal("事件体应带上运营理由，便于对方排障")
	}
}

// --- transfer ---

func TestTransferRequiresTargetAndReason(t *testing.T) {
	svc, w := newSvc()
	if _, err := svc.Transfer(context.Background(), 5, TransferInput{
		Reason: "客服确认", Principal: operator(),
	}); err == nil {
		t.Fatal("缺 target_user_id 必须拒绝")
	}
	if err := func() error {
		_, e := svc.Transfer(context.Background(), 5, TransferInput{
			TargetUser: "u-2", Reason: "ok", Principal: operator(),
		})
		return e
	}(); errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("reason 过短应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if w.transfer != 0 {
		t.Fatal("校验失败不得执行转移")
	}
}

func TestTransferEmitsEvent(t *testing.T) {
	svc, w := newSvc()
	item, err := svc.Transfer(context.Background(), 5, TransferInput{
		TargetUser: "u-2", Reason: "客服核实微信归属", Principal: operator(),
	})
	if err != nil {
		t.Fatalf("转移失败: %v", err)
	}
	if item.ExternalUserID != "u-2" {
		t.Fatalf("转移后应挂到新账号: %+v", item)
	}
	if w.lastEvent == nil || w.lastEvent.Payload["reason"] != "admin_transfer" {
		t.Fatalf("transfer 事件应带 reason=admin_transfer: %+v", w.lastEvent)
	}
}
