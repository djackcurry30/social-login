package authflow

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// --- fakes：只实现 claimmerge 用得到的方法，其余 panic ---
//
// panic 而不是返回零值：如果实现改动导致别的方法被调用，测试会立刻炸出来，
// 而不是静默地"看起来通过"。

type fakeClaims struct {
	verified map[string]*identity.Claim
}

func claimKey(claimType, hash string) string { return claimType + "|" + hash }

func (f *fakeClaims) FindVerified(_ context.Context, _ int64, claimType, hash string) (*identity.Claim, error) {
	if c, ok := f.verified[claimKey(claimType, hash)]; ok {
		return c, nil
	}
	return nil, identity.ErrNotFound
}
func (f *fakeClaims) Insert(context.Context, identity.ClaimUpsertInput) (*identity.Claim, error) {
	panic("unexpected Insert")
}
func (f *fakeClaims) ListByIdentity(context.Context, int64, int64) ([]identity.Claim, error) {
	panic("unexpected ListByIdentity")
}
func (f *fakeClaims) Revoke(context.Context, int64, int64, string, string, time.Time) error {
	panic("unexpected Revoke")
}

type fakeIdentities struct {
	byID map[int64]*identity.Identity
}

func (f *fakeIdentities) FindByID(_ context.Context, _ int64, id int64) (*identity.Identity, error) {
	if v, ok := f.byID[id]; ok {
		return v, nil
	}
	return nil, identity.ErrNotFound
}
func (f *fakeIdentities) Upsert(context.Context, identity.UpsertInput) (*identity.Identity, error) {
	panic("unexpected Upsert")
}
func (f *fakeIdentities) FindByOpenID(context.Context, identity.FindQuery) (*identity.Identity, error) {
	panic("unexpected FindByOpenID")
}

type fakeBindings struct {
	byIdentity map[int64]*binding.Binding
	activated  []binding.ActivateInput
}

func (f *fakeBindings) FindActiveByIdentity(_ context.Context, _ int64, identityID int64) (*binding.Binding, error) {
	if b, ok := f.byIdentity[identityID]; ok {
		return b, nil
	}
	return nil, binding.ErrNotFound
}

func (f *fakeBindings) Activate(_ context.Context, in binding.ActivateInput) (*binding.Binding, bool, error) {
	f.activated = append(f.activated, in)
	b := &binding.Binding{
		AppID: in.AppID, ExternalUserID: in.ExternalUserID,
		IdentityID: in.IdentityID, Status: binding.StatusActive,
		BindSource: in.BindSource,
	}
	f.byIdentity[in.IdentityID] = b
	return b, false, nil
}
func (f *fakeBindings) ListActiveByExternalUser(context.Context, int64, string) ([]binding.Binding, error) {
	panic("unexpected ListActiveByExternalUser")
}
func (f *fakeBindings) Unbind(context.Context, int64, int64, time.Time) error {
	panic("unexpected Unbind")
}
func (f *fakeBindings) CountActive(context.Context, int64, string) (int, error) {
	panic("unexpected CountActive")
}

type fakeAccounts struct {
	byClaim map[string]*account.Account
	err     error
}

func accKey(c account.Claim) string { return c.Type + ":" + c.Value }

func (f *fakeAccounts) GetByClaim(_ context.Context, c account.Claim) (*account.Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.byClaim[accKey(c)]; ok {
		return a, nil
	}
	return nil, account.ErrNotFound
}
func (f *fakeAccounts) Get(context.Context, string) (*account.Account, error) {
	panic("unexpected Get")
}
func (f *fakeAccounts) Create(context.Context, account.CreateRequest) (*account.Account, error) {
	panic("unexpected Create")
}
func (f *fakeAccounts) Merge(context.Context, account.MergeRequest) (*account.MergeResult, error) {
	panic("unexpected Merge")
}

// fakeHasher 用确定性的简单映射：测试只关心"能否用同一算法反查"，
// 不关心哈希强度（真实实现在 crypto 包，已有自己的测试）。
type fakeHasher struct{}

func (fakeHasher) Hash(_ int64, claimType, value string) string {
	return "h:" + claimType + ":" + value
}

// --- fixture ---

const testPhone = "13800000000"

// testRelayEmail 是 Apple 私密中继地址（不是真实邮箱）。
const testRelayEmail = "abc123@privaterelay.appleid.com"

type claimFix struct {
	svc  *Service
	cl   *fakeClaims
	ids  *fakeIdentities
	bd   *fakeBindings
	acc  *fakeAccounts
	tk   *fakeTickets
	app  *tenant.Application
	tc   *ticket.Context
	cur  *identity.Identity
	out  *CallbackOutput
	meta reqmeta.Meta
}

// newClaimFix 构造基线场景：
//
//	identity 8（微信，已绑定账号 user-A）验证过手机号 13800000000
//	identity 9（微信，本次登录）没有任何绑定
//	用户中心认可 user-A 当前持有该手机号
func newClaimFix(opts ...func(*tenant.Policy, *claimFix)) *claimFix {
	p := tenant.DefaultPolicy()
	p.Merge.Mode = tenant.MergeModeAuto
	p.Merge.OnLogin = tenant.OnLoginClaimVerified
	p.Merge.Verification = tenant.VerificationSMS

	f := &claimFix{
		app: &tenant.Application{ID: 5, AppCode: "app-a", Policy: p},
		tc: &ticket.Context{
			Platform: "wechat", Scene: "mini_program", Mode: provider.ModeLogin,
			RedirectURI: "https://biz.example.com/cb", BusinessState: "biz-state-1",
		},
		cur:  &identity.Identity{ID: 9, AppID: 5, Platform: "wechat", OpenID: "openid-new"},
		out:  &CallbackOutput{Platform: "wechat", Scene: "mini_program"},
		meta: reqmeta.Meta{TraceID: "trace-1", ClientIP: "1.2.3.4"},
		cl: &fakeClaims{verified: map[string]*identity.Claim{
			claimKey(identity.ClaimTypePhone, "h:"+identity.ClaimTypePhone+":"+testPhone): {
				AppID: 5, IdentityID: 8, Type: identity.ClaimTypePhone,
				Verified: true, Source: identity.SourceWeChatPhone,
			},
		}},
		ids: &fakeIdentities{byID: map[int64]*identity.Identity{
			8: {ID: 8, AppID: 5, Platform: "wechat", OpenID: "openid-old"},
			9: {ID: 9, AppID: 5, Platform: "wechat", OpenID: "openid-new"},
		}},
		bd: &fakeBindings{byIdentity: map[int64]*binding.Binding{
			8: {ID: 100, AppID: 5, ExternalUserID: "user-A", IdentityID: 8, Status: binding.StatusActive},
		}},
		acc: &fakeAccounts{byClaim: map[string]*account.Account{
			identity.ClaimTypePhone + ":" + testPhone: {UserID: "user-A", Status: account.StatusActive},
		}},
		tk: &fakeTickets{},
	}
	for _, o := range opts {
		o(&f.app.Policy, f)
	}
	f.svc = New(Config{}, Deps{
		Tickets:    f.tk,
		Claims:     f.cl,
		Identities: f.ids,
		Bindings:   f.bd,
		Accounts:   f.acc,
		Hasher:     fakeHasher{},
	})
	return f
}

// run 以"手机号"这一条凭证执行一次归并尝试。
func (f *claimFix) run() (*CallbackOutput, bool, error) {
	res, err := f.svc.tryClaimMerge(context.Background(), f.app, f.tc, f.cur,
		[]account.Claim{{Type: identity.ClaimTypePhone, Value: testPhone, Source: identity.SourceWeChatPhone}},
		f.out, f.meta, time.Now())
	return res, res != nil, err
}

// targetUser 返回本次实际绑定的账号（没有绑定则空串）。
func (f *claimFix) targetUser() string {
	if len(f.bd.activated) == 0 {
		return ""
	}
	return f.bd.activated[0].ExternalUserID
}

// TestClaimMergeBindsNewIdentityToExistingAccount 是这条能力的主路径：
// 新渠道的同一个手机号 → 挂到既有账号上，并签发 auth_code。
func TestClaimMergeBindsNewIdentityToExistingAccount(t *testing.T) {
	f := newClaimFix()
	res, handled, err := f.run()
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if !handled {
		t.Fatal("应完成归并")
	}
	if f.targetUser() != "user-A" {
		t.Fatalf("应归并到 user-A，实际 %q", f.targetUser())
	}
	if res.AuthCode == "" {
		t.Fatal("归并后必须签发 auth_code")
	}
	if len(f.bd.activated) != 1 {
		t.Fatalf("应建立 1 条绑定，实际 %d", len(f.bd.activated))
	}
	in := f.bd.activated[0]
	if in.IdentityID != 9 || in.ExternalUserID != "user-A" {
		t.Fatalf("绑定方向错误: %+v", in)
	}
	// bind_source 必须是 merge 而不是 login：排障时要能区分"登录时自动归并"
	// 与"用户主动绑定"，两者的用户预期完全不同。
	if in.BindSource != binding.SourceMerge {
		t.Fatalf("bind_source 应为 merge，实际 %q", in.BindSource)
	}
}

// TestClaimMergeRequiresAccountBackCheck 守住 P0-6：
// 本地 claim 表说"手机号属于 user-A"，但用户中心说它现在属于 user-B。
// 说明本地表过期了，此时归并会把用户登进错误的账号。
func TestClaimMergeRequiresAccountBackCheck(t *testing.T) {
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		f.acc.byClaim[identity.ClaimTypePhone+":"+testPhone] = &account.Account{
			UserID: "user-B", Status: account.StatusActive,
		}
	})
	_, handled, err := f.run()
	if err != nil {
		t.Fatalf("不应报错（不一致是数据状态，不是故障）: %v", err)
	}
	if handled {
		t.Fatal("用户中心账号与本地绑定不一致时禁止归并")
	}
	if len(f.bd.activated) != 0 {
		t.Fatal("被拒绝时不得建立绑定")
	}
}

// TestClaimMergeSkipsWhenAccountMissing 覆盖"claim 还在、账号已注销"。
func TestClaimMergeSkipsWhenAccountMissing(t *testing.T) {
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		f.acc.err = account.ErrNotFound
	})
	_, handled, err := f.run()
	if err != nil || handled {
		t.Fatalf("用户中心查不到账号时应跳过，err=%v handled=%v", err, handled)
	}
}

// TestClaimMergeMultipleAccountsIsRejected：命中多个账号不能择一（§7.4 护栏）。
func TestClaimMergeMultipleAccountsIsRejected(t *testing.T) {
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		f.acc.err = account.ErrMultipleAccounts
	})
	_, _, err := f.run()
	if err == nil {
		t.Fatal("命中多个账号必须报错")
	}
	if code := errs.CodeOf(err); code != errs.CodeAccountMultiple {
		t.Fatalf("应为 ACCOUNT.MULTIPLE_MATCH，实际 %v", code)
	}
}

// TestClaimMergeCrossPlatformOffByDefault 守住 R4 红线 3：
// 微信手机号去归并支付宝账号，默认必须拒绝。
func TestClaimMergeCrossPlatformOffByDefault(t *testing.T) {
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		f.cur.Platform = "alipay"
	})
	_, handled, err := f.run()
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if handled {
		t.Fatal("跨平台自动归并默认关闭，不得归并")
	}
}

// TestClaimMergeCrossPlatformWhenEnabled：应用显式打开开关后才允许。
func TestClaimMergeCrossPlatformWhenEnabled(t *testing.T) {
	f := newClaimFix(func(p *tenant.Policy, f *claimFix) {
		p.Merge.AllowCrossPlatformAuto = true
		f.cur.Platform = "alipay"
	})
	_, handled, err := f.run()
	if err != nil || !handled {
		t.Fatalf("开关打开后应归并，err=%v handled=%v", err, handled)
	}
	if f.targetUser() != "user-A" {
		t.Fatalf("应归并到 user-A，实际 %q", f.targetUser())
	}
}

// TestClaimMergeRejectsAppleRelayCrossPlatform：Apple 私密中继邮箱不是真实邮箱，
// 即使打开了跨平台开关也不能用于跨平台匹配（§7.5.3 红线 1 的特殊说明）。
func TestClaimMergeRejectsAppleRelayCrossPlatform(t *testing.T) {
	f := newClaimFix(func(p *tenant.Policy, f *claimFix) {
		p.Merge.AllowCrossPlatformAuto = true
		f.cur.Platform = "wechat"
		f.ids.byID[8].Platform = "apple"
		f.cl.verified = map[string]*identity.Claim{
			claimKey(identity.ClaimTypeEmail, "h:"+identity.ClaimTypeEmail+":"+testRelayEmail): {
				AppID: 5, IdentityID: 8, Type: identity.ClaimTypeEmail,
				Verified: true, Source: identity.SourceAppleEmail,
			},
		}
		f.acc.byClaim = map[string]*account.Account{
			identity.ClaimTypeEmail + ":" + testRelayEmail: {UserID: "user-A", Status: account.StatusActive},
		}
	})
	res, err := f.svc.tryClaimMerge(context.Background(), f.app, f.tc, f.cur,
		[]account.Claim{{Type: identity.ClaimTypeEmail, Value: testRelayEmail, Source: identity.SourceAppleEmail}},
		f.out, f.meta, time.Now())
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if res != nil {
		t.Fatal("Apple 私密中继邮箱不得用于跨平台归并")
	}
}

// TestClaimMergeSkipsInactiveAccount：冻结/注销的账号不能作为归并目标。
func TestClaimMergeSkipsInactiveAccount(t *testing.T) {
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		f.acc.byClaim[identity.ClaimTypePhone+":"+testPhone] = &account.Account{
			UserID: "user-A", Status: account.StatusFrozen,
		}
	})
	_, handled, err := f.run()
	if err != nil || handled {
		t.Fatalf("非 active 账号应跳过，err=%v handled=%v", err, handled)
	}
}

// TestClaimMergeSkipsSameIdentity：凭证本来就属于当前身份（第二次登录），
// 不需要也不应该产生"归并"动作。
func TestClaimMergeSkipsSameIdentity(t *testing.T) {
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		f.cl.verified[claimKey(identity.ClaimTypePhone, "h:"+identity.ClaimTypePhone+":"+testPhone)].IdentityID = 9
	})
	_, handled, err := f.run()
	if err != nil || handled {
		t.Fatalf("指向自身时应跳过，err=%v handled=%v", err, handled)
	}
	if len(f.bd.activated) != 0 {
		t.Fatal("指向自身时不得写绑定")
	}
}

// TestTryClaimMergeRejectsConflictingClaims：一次授权带两个凭证、分别指向
// 不同账号时，没有正确答案 —— 必须拒绝，而不是"先遍历到哪条就归并哪条"。
func TestTryClaimMergeRejectsConflictingClaims(t *testing.T) {
	const email = "a@example.com"
	f := newClaimFix(func(_ *tenant.Policy, f *claimFix) {
		// identity 7 → 账号 user-C，由邮箱凭证指向
		f.ids.byID[7] = &identity.Identity{ID: 7, AppID: 5, Platform: "wechat", OpenID: "openid-3"}
		f.bd.byIdentity[7] = &binding.Binding{
			ID: 101, AppID: 5, ExternalUserID: "user-C", IdentityID: 7, Status: binding.StatusActive,
		}
		f.cl.verified[claimKey(identity.ClaimTypeEmail, "h:"+identity.ClaimTypeEmail+":"+email)] = &identity.Claim{
			AppID: 5, IdentityID: 7, Type: identity.ClaimTypeEmail,
			Verified: true, Source: identity.SourceSMSVerified,
		}
		f.acc.byClaim[identity.ClaimTypeEmail+":"+email] = &account.Account{
			UserID: "user-C", Status: account.StatusActive,
		}
	})

	_, err := f.svc.tryClaimMerge(context.Background(), f.app, f.tc, f.cur, []account.Claim{
		{Type: identity.ClaimTypePhone, Value: testPhone, Source: identity.SourceWeChatPhone},
		{Type: identity.ClaimTypeEmail, Value: email, Source: identity.SourceSMSVerified},
	}, f.out, f.meta, time.Now())
	if err == nil {
		t.Fatal("两个凭证指向不同账号时必须拒绝，不能替用户选")
	}
	if code := errs.CodeOf(err); code != errs.CodeAccountMultiple {
		t.Fatalf("应为 ACCOUNT.MULTIPLE_MATCH，实际 %v", code)
	}
	if len(f.bd.activated) != 0 {
		t.Fatal("被拒绝时不得建立任何绑定")
	}
}
