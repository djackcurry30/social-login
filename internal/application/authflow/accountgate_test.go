package authflow

import (
	"context"
	"errors"
	"testing"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// gateAccounts 同时实现 account.Provider 与 account.ClaimReplacer。
//
// 用同一个假实现而不是两个，是因为生产里也是同一个对象（HTTPAccountProvider
// 既提供 Get 又提供 ReplaceClaim）；分开会让"类型断言拿不到换绑能力"这条
// 分支永远测不到。
type gateAccounts struct {
	acc *account.Account
	err error

	replaced   []account.ReplaceClaimRequest
	replaceErr error

	getCalls int
}

func (f *gateAccounts) Get(_ context.Context, _, _ string) (*account.Account, error) {
	f.getCalls++
	if f.err != nil {
		return nil, f.err
	}
	return f.acc, nil
}

func (f *gateAccounts) GetByClaim(_ context.Context, _ string, _ account.Claim) (*account.Account, error) {
	return nil, errors.New("not used")
}

func (f *gateAccounts) Create(_ context.Context, _ account.CreateRequest) (*account.Account, error) {
	return nil, errors.New("not used")
}

func (f *gateAccounts) Merge(_ context.Context, _ account.MergeRequest) (*account.MergeResult, error) {
	return nil, errors.New("not used")
}

func (f *gateAccounts) ReplaceClaim(_ context.Context, req account.ReplaceClaimRequest) (*account.Account, error) {
	f.replaced = append(f.replaced, req)
	if f.replaceErr != nil {
		return nil, f.replaceErr
	}
	return f.acc, nil
}

func newGateService(acc account.Provider, cfg AccountCheckConfig) *Service {
	return New(Config{AccountCheck: cfg}, Deps{Accounts: acc})
}

func testApp() *tenant.Application {
	return &tenant.Application{AppCode: "app_gate", Name: "gate"}
}

func testBinding(userID string) *binding.Binding {
	return &binding.Binding{ExternalUserID: userID, IdentityID: 9}
}

func TestGateDisabledDoesNotTouchProvider(t *testing.T) {
	f := &gateAccounts{acc: &account.Account{UserID: "u1", Status: account.StatusFrozen}}
	s := newGateService(f, AccountCheckConfig{Enabled: false})

	if err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"), nil); err != nil {
		t.Fatalf("未启用时不应拦截: %v", err)
	}
	if f.getCalls != 0 {
		t.Fatal("未启用时不该产生远端调用")
	}
}

func TestGateRejectsNonActiveAccount(t *testing.T) {
	for _, status := range []account.Status{account.StatusFrozen, account.StatusClosed} {
		f := &gateAccounts{acc: &account.Account{UserID: "u1", Status: status}}
		s := newGateService(f, AccountCheckConfig{Enabled: true})

		err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"), nil)
		if err == nil {
			t.Fatalf("状态 %s 必须拒绝登录", status)
		}
		if got := errs.CodeOf(err); got != errs.CodeForbidden {
			t.Fatalf("状态 %s 的错误码应为 %s，实际 %s", status, errs.CodeForbidden, got)
		}
	}
}

func TestGateRejectsWhenAccountMissing(t *testing.T) {
	f := &gateAccounts{err: account.ErrNotFound}
	s := newGateService(f, AccountCheckConfig{Enabled: true, AllowOnUnavailable: true})

	err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"), nil)
	if err == nil {
		t.Fatal("本地有绑定但对端没有账号时必须拒绝")
	}
	// 注意：AllowOnUnavailable 只管"查不了"，不管"查到了没有"。
	// 账号明确不存在是确定答案，不能因为配置了放行就签发令牌。
	if got := errs.CodeOf(err); got != errs.CodeAccountNotFound {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeAccountNotFound, got)
	}
}

func TestGateUnavailableRejectsByDefault(t *testing.T) {
	f := &gateAccounts{err: errs.New(errs.CodeAccountUnavailable, "超时")}
	s := newGateService(f, AccountCheckConfig{Enabled: true})

	err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"), nil)
	if err == nil {
		t.Fatal("默认（架构 §6.2）应拒绝")
	}
	if got := errs.CodeOf(err); got != errs.CodeAccountUnavailable {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeAccountUnavailable, got)
	}
	if !errs.Retryable(err) {
		t.Fatal("对端不可用必须是可重试的，否则业务方会当成账号问题")
	}
}

func TestGateUnavailableAllowsWhenConfigured(t *testing.T) {
	f := &gateAccounts{err: errs.New(errs.CodeAccountUnavailable, "超时")}
	s := newGateService(f, AccountCheckConfig{Enabled: true, AllowOnUnavailable: true})

	if err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"), nil); err != nil {
		t.Fatalf("配置放行时不应拦截: %v", err)
	}
}

func TestGateReplacesChangedPhone(t *testing.T) {
	f := &gateAccounts{acc: &account.Account{
		UserID: "u1",
		Status: account.StatusActive,
		Claims: []account.Claim{{Type: "phone", Value: "13800138000", Source: "wechat_phone"}},
	}}
	s := newGateService(f, AccountCheckConfig{Enabled: true})

	// 平台这次返回的是带国际区号的新号。
	err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"),
		[]account.Claim{{Type: "phone", Value: "+8613900139000", Source: "wechat_phone"}})
	if err != nil {
		t.Fatalf("换绑失败不应阻断登录: %v", err)
	}
	if len(f.replaced) != 1 {
		t.Fatalf("应调用一次换绑，实际 %d", len(f.replaced))
	}
	if f.replaced[0].Claim.Value != "+8613900139000" {
		t.Fatalf("换绑用的是本次平台返回的值，实际 %q", f.replaced[0].Claim.Value)
	}
	if f.replaced[0].UserID != "u1" || f.replaced[0].AppKey != "app_gate" {
		t.Fatalf("换绑的账号/租户不对: %+v", f.replaced[0])
	}
}

func TestGateDoesNotReplaceWhenOnlyFormattingDiffers(t *testing.T) {
	f := &gateAccounts{acc: &account.Account{
		UserID: "u1",
		Status: account.StatusActive,
		Claims: []account.Claim{{Type: "phone", Value: "13800138000"}},
	}}
	s := newGateService(f, AccountCheckConfig{Enabled: true})

	// 同一个号码的不同写法：不归一化就会每次登录都发一次"换了但没换"的请求。
	for _, v := range []string{"+8613800138000", "138 0013 8000", "8613800138000"} {
		if err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"),
			[]account.Claim{{Type: "phone", Value: v}}); err != nil {
			t.Fatalf("不应报错: %v", err)
		}
	}
	if len(f.replaced) != 0 {
		t.Fatalf("仅格式不同不该触发换绑，实际调用 %d 次", len(f.replaced))
	}
}

func TestGateSkipsClaimTypesAccountDoesNotHave(t *testing.T) {
	f := &gateAccounts{acc: &account.Account{
		UserID: "u1",
		Status: account.StatusActive,
		Claims: []account.Claim{{Type: "phone", Value: "13800138000"}},
	}}
	s := newGateService(f, AccountCheckConfig{Enabled: true})

	// 账号没有 email 这类凭证：补一条需要"新增凭证"能力，契约里没有，
	// 因此只能跳过，不能拿 Replace 去造语义。
	if err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"),
		[]account.Claim{{Type: "email", Value: "new@example.com"}}); err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if len(f.replaced) != 0 {
		t.Fatal("账号没有该类凭证时不该调用换绑")
	}
}

func TestGateContinuesLoginWhenReplaceConflicts(t *testing.T) {
	f := &gateAccounts{
		acc: &account.Account{
			UserID: "u1",
			Status: account.StatusActive,
			Claims: []account.Claim{{Type: "phone", Value: "13800138000"}},
		},
		replaceErr: errs.New(errs.CodeBindIdentityTaken, "该凭证已被其他账号占用"),
	}
	s := newGateService(f, AccountCheckConfig{Enabled: true})

	// 新号码在别人名下：换绑失败，但登录必须继续——否则用户既进不去，
	// 也不知道号码在谁那里。这里的选择是"让能登的人登进来，数据交给人工修"。
	if err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"),
		[]account.Claim{{Type: "phone", Value: "13900139000"}}); err != nil {
		t.Fatalf("换绑冲突不应阻断登录: %v", err)
	}
}

func TestGateSkipsReplaceWhenProviderLacksCapability(t *testing.T) {
	// 只用 Provider 的最小实现（不带 ReplaceClaim），模拟桩/假对端。
	s := newGateService(providerOnly{acc: &account.Account{
		UserID: "u1",
		Status: account.StatusActive,
		Claims: []account.Claim{{Type: "phone", Value: "13800138000"}},
	}}, AccountCheckConfig{Enabled: true})

	if err := s.gateBoundAccount(context.Background(), testApp(), testBinding("u1"),
		[]account.Claim{{Type: "phone", Value: "13900139000"}}); err != nil {
		t.Fatalf("缺少换绑能力时应跳过而不是报错: %v", err)
	}
}

// providerOnly 只实现 account.Provider，不实现 ClaimReplacer。
type providerOnly struct{ acc *account.Account }

func (p providerOnly) Get(_ context.Context, _, _ string) (*account.Account, error) {
	return p.acc, nil
}

func (p providerOnly) GetByClaim(_ context.Context, _ string, _ account.Claim) (*account.Account, error) {
	return nil, errors.New("not used")
}

func (p providerOnly) Create(_ context.Context, _ account.CreateRequest) (*account.Account, error) {
	return nil, errors.New("not used")
}

func (p providerOnly) Merge(_ context.Context, _ account.MergeRequest) (*account.MergeResult, error) {
	return nil, errors.New("not used")
}
