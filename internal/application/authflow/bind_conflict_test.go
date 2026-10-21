package authflow

import (
	"context"
	"errors"
	"testing"
	"time"

	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// fakeTickets 只实现 bindConflict 路径上用到的两个方法，其余 panic——
// 如果实现变了导致别的方法被调用，测试会立刻炸出来，而不是静默返回零值。
type fakeTickets struct {
	savedAuthCodes []*ticket.AuthCode
	mergeTickets   []*ticket.MergeTicket
}

func (f *fakeTickets) SaveContext(context.Context, *ticket.Context, time.Duration) error {
	panic("unexpected SaveContext")
}
func (f *fakeTickets) ConsumeContext(context.Context, string) (*ticket.Context, error) {
	panic("unexpected ConsumeContext")
}
func (f *fakeTickets) SaveBindTicket(context.Context, *ticket.BindTicket, time.Duration) error {
	panic("unexpected SaveBindTicket")
}
func (f *fakeTickets) ConsumeBindTicket(context.Context, string) (*ticket.BindTicket, error) {
	panic("unexpected ConsumeBindTicket")
}
func (f *fakeTickets) SaveAuthCode(_ context.Context, c *ticket.AuthCode, _ time.Duration) error {
	f.savedAuthCodes = append(f.savedAuthCodes, c)
	return nil
}
func (f *fakeTickets) ConsumeAuthCode(context.Context, string) (*ticket.AuthCode, error) {
	panic("unexpected ConsumeAuthCode")
}
func (f *fakeTickets) SaveMergeTicket(_ context.Context, t *ticket.MergeTicket, _ time.Duration) error {
	f.mergeTickets = append(f.mergeTickets, t)
	return nil
}
func (f *fakeTickets) GetMergeTicket(context.Context, string) (*ticket.MergeTicket, error) {
	return nil, ticket.ErrMergeTicketInvalid
}
func (f *fakeTickets) DeleteMergeTicket(context.Context, string) error { return nil }
func (f *fakeTickets) MarkReplay(context.Context, string, time.Duration) error { return nil }
func (f *fakeTickets) SeenReplay(context.Context, string) (bool, error)        { return false, nil }

type fakeMerge struct {
	err    error
	calls  int
	last   appmerge.Request
	result *appmerge.Result
}

func (f *fakeMerge) Execute(_ context.Context, req appmerge.Request) (*appmerge.Result, error) {
	f.calls++
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &appmerge.Result{OperationID: 1}, nil
}

func conflictFixture(mode string) (*Service, *fakeTickets, *fakeMerge, *tenant.Application,
	*ticket.Context, *identity.Identity, *binding.Binding,
) {
	tk := &fakeTickets{}
	mk := &fakeMerge{}
	p := tenant.DefaultPolicy()
	p.Merge.Mode = mode
	app := &tenant.Application{ID: 5, AppCode: "app-a", Policy: p}
	tc := &ticket.Context{Mode: provider.ModeBind, BindExternalUserID: "user-C"}
	idn := &identity.Identity{ID: 9, AppID: 5, Platform: "wechat"}
	ex := &binding.Binding{AppID: 5, ExternalUserID: "user-B", IdentityID: 9, Status: "active"}

	return New(Config{}, Deps{Tickets: tk, Merge: mk}), tk, mk, app, tc, idn, ex
}

// TestBindConflictAutoMerges 覆盖需求 R1 的主路径：
// auto 模式下绑定冲突直接合并，并签发 target 账号的 auth_code。
func TestBindConflictAutoMerges(t *testing.T) {
	svc, tk, mk, app, tc, idn, ex := conflictFixture(tenant.MergeModeAuto)

	out, err := svc.bindConflict(context.Background(), app, tc, idn, ex, &CallbackOutput{},
		reqmetaZero(), time.Now())
	if err != nil {
		t.Fatalf("auto 模式应完成合并: %v", err)
	}
	if mk.calls != 1 {
		t.Fatalf("应调用合并 1 次，实际 %d", mk.calls)
	}
	if mk.last.TargetUserID != "user-C" || mk.last.SourceUserID != "user-B" {
		t.Fatalf("合并方向错误（必须是 source→target）: %+v", mk.last)
	}
	if mk.last.Trigger != appmerge.TriggerBind {
		t.Fatalf("触发场景应为 bind，实际 %s", mk.last.Trigger)
	}
	if out.ExternalUserID != "user-C" {
		t.Fatalf("合并后应签发目标账号的 auth_code，实际 %s", out.ExternalUserID)
	}
	if out.AuthCode == "" || len(tk.savedAuthCodes) != 1 {
		t.Fatal("应保存一条 auth_code")
	}
}

// TestBindConflictConfirmRequiresVerification：confirm 绝不能静默合并。
func TestBindConflictConfirmRequiresVerification(t *testing.T) {
	svc, tk, mk, app, tc, idn, ex := conflictFixture(tenant.MergeModeConfirm)

	_, err := svc.bindConflict(context.Background(), app, tc, idn, ex, &CallbackOutput{},
		reqmetaZero(), time.Now())
	if err == nil {
		t.Fatal("confirm 必须要求验证")
	}
	if errs.CodeOf(err) != errs.CodeBindMergeRequired {
		t.Fatalf("应为 BIND.MERGE_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if mk.calls != 0 {
		t.Fatal("需要验证时不得执行合并")
	}
	// confirm 必须签发一次性合并票据，否则前端拿到错误也没有下一步入口。
	if len(tk.mergeTickets) != 1 {
		t.Fatalf("应签发 1 张合并票据，实际 %d", len(tk.mergeTickets))
	}
	mt := tk.mergeTickets[0]
	if mt.TargetUserID != "user-C" || mt.SourceUserID != "user-B" {
		t.Fatalf("票据里的双方账号错误: %+v", mt)
	}
	if mt.Ticket == "" {
		t.Fatal("票据 ID 不能为空")
	}
}

// TestBindConflictManualRejects：manual 只提示不处理。
func TestBindConflictManualRejects(t *testing.T) {
	svc, _, mk, app, tc, idn, ex := conflictFixture(tenant.MergeModeManual)

	_, err := svc.bindConflict(context.Background(), app, tc, idn, ex, &CallbackOutput{},
		reqmetaZero(), time.Now())
	if err == nil {
		t.Fatal("manual 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeBindIdentityTaken {
		t.Fatalf("应为 BIND.IDENTITY_TAKEN，实际 %v", errs.CodeOf(err))
	}
	if mk.calls != 0 {
		t.Fatal("manual 不得执行合并")
	}
}

// TestBindConflictWithoutMergeDependencyRejects：少装配依赖时必须拒绝而不是放行。
func TestBindConflictWithoutMergeDependencyRejects(t *testing.T) {
	tk := &fakeTickets{}
	p := tenant.DefaultPolicy()
	p.Merge.Mode = tenant.MergeModeAuto
	app := &tenant.Application{ID: 5, Policy: p}
	svc := New(Config{}, Deps{Tickets: tk}) // Merge 未注入

	_, err := svc.bindConflict(context.Background(), app,
		&ticket.Context{Mode: provider.ModeBind, BindExternalUserID: "user-C"},
		&identity.Identity{ID: 9, Platform: "wechat"},
		&binding.Binding{ExternalUserID: "user-B"}, &CallbackOutput{}, reqmetaZero(), time.Now())
	if err == nil {
		t.Fatal("未装配合并能力时不得放行")
	}
	if errs.CodeOf(err) != errs.CodeBindIdentityTaken {
		t.Fatalf("应为 BIND.IDENTITY_TAKEN，实际 %v", errs.CodeOf(err))
	}
}

// TestBindConflictMergeFailureSurfacesError：合并失败必须如实报错，
// 不能"失败了也当绑定成功"——绑定实际没有发生。
func TestBindConflictMergeFailureSurfacesError(t *testing.T) {
	svc, tk, mk, app, tc, idn, ex := conflictFixture(tenant.MergeModeAuto)
	mk.err = errs.New(errs.CodeAccountUnavailable, "用户中心不可用")

	_, err := svc.bindConflict(context.Background(), app, tc, idn, ex, &CallbackOutput{},
		reqmetaZero(), time.Now())
	if err == nil {
		t.Fatal("合并失败必须报错")
	}
	if !errors.Is(err, mk.err) && errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应透出用户中心错误，实际 %v", err)
	}
	if len(tk.savedAuthCodes) != 0 {
		t.Fatal("合并失败不得签发 auth_code")
	}
}

// TestBindConflictMergeRejectedMapsToIdentityTaken：
// 内部拒绝（如跨平台未授权）要映射成接入方熟悉的口径。
func TestBindConflictMergeRejectedMapsToIdentityTaken(t *testing.T) {
	svc, _, mk, app, tc, idn, ex := conflictFixture(tenant.MergeModeAuto)
	mk.err = &appmerge.RejectError{Reason: "跨平台未授权", Code: errs.CodeBindIdentityTaken}

	_, err := svc.bindConflict(context.Background(), app, tc, idn, ex, &CallbackOutput{},
		reqmetaZero(), time.Now())
	if errs.CodeOf(err) != errs.CodeBindIdentityTaken {
		t.Fatalf("应为 BIND.IDENTITY_TAKEN，实际 %v", errs.CodeOf(err))
	}
}

// reqmetaZero 给一个空元信息，避免每个用例都写一遍。
func reqmetaZero() reqmeta.Meta { return reqmeta.Meta{} }
