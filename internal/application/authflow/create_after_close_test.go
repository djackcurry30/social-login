package authflow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// reLoginFixture 覆盖"注销之后再登录"这一轮，用最小的依赖把它跑到签发授权码。
//
// 为什么要单独建这套替身而不是复用 claimmerge_test 的：fakeAccounts.Create
// 是 panic 的（那条路径在归并用例里不该发生）。这里需要它按调用次数返回
// 不同状态，才能表达"第一次建号返回 closed、第二次返回 active"。
type reLoginFixture struct {
	svc *Service
	acc *closeCycleAccounts
	bd  *closeCycleBindings
}

type closeCycleAccounts struct {
	// replies 按调用顺序返回；用完后返回最后一个。
	replies []*account.Account
	calls   []account.CreateRequest
}

func (f *closeCycleAccounts) GetByClaim(context.Context, string, account.Claim) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (f *closeCycleAccounts) Get(context.Context, string, string) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (f *closeCycleAccounts) Create(_ context.Context, req account.CreateRequest) (*account.Account, error) {
	f.calls = append(f.calls, req)
	if len(f.replies) == 0 {
		return nil, errs.New(errs.CodeInternal, "测试未配置返回值")
	}
	var out *account.Account
	if len(f.replies) > 1 {
		out = f.replies[0]
		f.replies = f.replies[1:]
	} else {
		out = f.replies[0]
	}
	return out, nil
}
func (f *closeCycleAccounts) Merge(context.Context, account.MergeRequest) (*account.MergeResult, error) {
	return nil, errs.New(errs.CodeAccountNotSupported, "不支持")
}

type closeCycleBindings struct{ activated []binding.ActivateInput }

func (f *closeCycleBindings) FindActiveByIdentity(context.Context, int64, int64) (*binding.Binding, error) {
	return nil, binding.ErrNotFound
}
func (f *closeCycleBindings) ListActiveByExternalUser(context.Context, int64, string) ([]binding.Binding, error) {
	return nil, nil
}
func (f *closeCycleBindings) Activate(_ context.Context, in binding.ActivateInput) (*binding.Binding, bool, error) {
	f.activated = append(f.activated, in)
	return &binding.Binding{
		ID: 1, AppID: in.AppID, ExternalUserID: in.ExternalUserID,
		IdentityID: in.IdentityID, Status: binding.StatusActive,
	}, false, nil
}
func (f *closeCycleBindings) Unbind(context.Context, int64, int64, time.Time) error { return nil }
func (f *closeCycleBindings) CountActive(context.Context, int64, string) (int, error) {
	return 1, nil
}

func newReLoginFixture(replies ...*account.Account) *reLoginFixture {
	f := &reLoginFixture{
		acc: &closeCycleAccounts{replies: replies},
		bd:  &closeCycleBindings{},
	}
	f.svc = New(Config{}, Deps{
		Accounts: f.acc,
		Bindings: f.bd,
		Tickets:  &fakeTickets{},
	})
	return f
}

func (f *reLoginFixture) run(t *testing.T) (*CallbackOutput, error) {
	t.Helper()
	app := &tenant.Application{ID: 5, AppCode: "app_a"}
	tc := &ticket.Context{
		Platform: "wechat", Scene: "mini_program", Mode: "login",
		RedirectURI: "https://biz.example.com/cb", BusinessState: "s1",
	}
	idn := &identity.Identity{ID: 9, AppID: 5, Platform: "wechat", OpenID: "openid-1"}
	out := &CallbackOutput{Platform: "wechat", Scene: "mini_program"}
	return f.svc.autoCreateAndBind(context.Background(), app, tc, idn, out,
		[]account.Claim{{Type: identity.ClaimTypeEmail, Value: "a@example.com", Source: identity.SourceWeChatPhone}},
		reqmeta.Meta{TraceID: "tr-1"}, time.Now())
}

// 主路径：正常建号并绑定。
func TestAutoCreateBindsActiveAccount(t *testing.T) {
	f := newReLoginFixture(&account.Account{UserID: "user-1", Status: account.StatusActive})
	out, err := f.run(t)
	if err != nil {
		t.Fatalf("应成功: %v", err)
	}
	if out.ExternalUserID != "user-1" || out.AuthCode == "" {
		t.Fatalf("应签发 user-1 的授权码，实际 %+v", out)
	}
	if len(f.acc.calls) != 1 {
		t.Fatalf("只应建号一次，实际 %d 次", len(f.acc.calls))
	}
}

// 注销之后再用同一个身份登录：必须重建账号，而不是把用户绑回那个 closed 账号。
//
// 这条路径此前是错的：Create 的幂等键按 (app, identity) 固定，所以重放
// 永远返回同一个 closed 账号，用户"登录成功"却绑在一个已注销的账号上——
// 所有需要用户中心参与的操作都会失败，而且每次登录都重复这个状态。
func TestAutoCreateRecreatesAfterClosed(t *testing.T) {
	f := newReLoginFixture(
		&account.Account{UserID: "user-old", Status: account.StatusClosed},
		&account.Account{UserID: "user-new", Status: account.StatusActive},
	)
	out, err := f.run(t)
	if err != nil {
		t.Fatalf("注销后重登应成功: %v", err)
	}
	if out.ExternalUserID != "user-new" {
		t.Fatalf("应绑到新账号 user-new，实际 %s", out.ExternalUserID)
	}
	if len(f.acc.calls) != 2 {
		t.Fatalf("closed 之后应再建一次号，实际建号 %d 次", len(f.acc.calls))
	}
	k1, k2 := f.acc.calls[0].IdempotencyKey, f.acc.calls[1].IdempotencyKey
	if k1 == k2 {
		t.Fatalf("第二次建号必须换幂等键，否则会永远重放 closed 账号（都是 %s）", k1)
	}
	if !strings.Contains(k2, "user-old") {
		t.Fatalf("幂等键应带上被注销账号的 id（同轮重试仍幂等），实际 %s", k2)
	}
}

// 冻结账号不能被"再登录一次"绕过：那不是重建账号，是自助解封。
func TestAutoCreateRejectsFrozen(t *testing.T) {
	f := newReLoginFixture(&account.Account{UserID: "user-frozen", Status: account.StatusFrozen})

	_, err := f.run(t)
	if err == nil {
		t.Fatal("冻结账号必须拒绝登录")
	}
	if errs.CodeOf(err) != errs.CodeForbidden {
		t.Fatalf("错误码应为 AUTH.FORBIDDEN，实际 %s", errs.CodeOf(err))
	}
	if len(f.acc.calls) != 1 {
		t.Fatalf("冻结时不应再次建号，实际建号 %d 次", len(f.acc.calls))
	}
	if len(f.bd.activated) != 0 {
		t.Fatal("冻结时不应建立绑定")
	}
}

// 幂等键的推导规则本身也要锁住：并发同一次登录必须算出同一个键。
func TestFirstLoginKeyIsStablePerIdentity(t *testing.T) {
	if a, b := firstLoginKey("app_a", 9, ""), firstLoginKey("app_a", 9, ""); a != b {
		t.Fatalf("同一身份同一轮必须稳定，实际 %s vs %s", a, b)
	}
	if firstLoginKey("app_a", 9, "") == firstLoginKey("app_b", 9, "") {
		t.Fatal("不同应用的同一 identity id 不能共用幂等键")
	}
	if firstLoginKey("app_a", 9, "") == firstLoginKey("app_a", 9, "user-old") {
		t.Fatal("注销后重建必须换键")
	}
}
