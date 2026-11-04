package accountclose

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- 替身 ---

type fakeApps struct{}

func (fakeApps) Application(context.Context, string) (*tenant.Application, error) {
	return &tenant.Application{ID: 7, AppCode: "app_a"}, nil
}

// fakeAccounts 记录调用顺序，用于断言"先关对端、再清本地"。
type fakeAccounts struct {
	calls   *[]string
	closeFn func() error
	// supportClose=false 时模拟"对端没有注销能力"。
	supportClose bool
}

func (f *fakeAccounts) Get(context.Context, string, string) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (f *fakeAccounts) GetByClaim(context.Context, string, account.Claim) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (f *fakeAccounts) Create(context.Context, account.CreateRequest) (*account.Account, error) {
	return nil, errs.New(errs.CodeAccountNotSupported, "不支持")
}
func (f *fakeAccounts) Merge(context.Context, account.MergeRequest) (*account.MergeResult, error) {
	return nil, errs.New(errs.CodeAccountNotSupported, "不支持")
}

func (f *fakeAccounts) Close(context.Context, string, string) error {
	*f.calls = append(*f.calls, "remote_close")
	if f.closeFn != nil {
		return f.closeFn()
	}
	return nil
}

type fakeBindings struct {
	rows    []binding.Binding
	unbound []int64
	failOn  int64
}

func (f *fakeBindings) FindActiveByIdentity(context.Context, int64, int64) (*binding.Binding, error) {
	return nil, binding.ErrNotFound
}
func (f *fakeBindings) ListActiveByExternalUser(context.Context, int64, string) ([]binding.Binding, error) {
	return f.rows, nil
}
func (f *fakeBindings) Activate(context.Context, binding.ActivateInput) (*binding.Binding, bool, error) {
	return nil, false, errors.New("unexpected")
}
func (f *fakeBindings) Unbind(_ context.Context, _ int64, identityID int64, _ time.Time) error {
	if f.failOn != 0 && f.failOn == identityID {
		return errors.New("boom")
	}
	f.unbound = append(f.unbound, identityID)
	return nil
}
func (f *fakeBindings) CountActive(context.Context, int64, string) (int, error) {
	return len(f.rows), nil
}

type fakeIdentities struct{ byID map[int64]*identity.Identity }

func (f *fakeIdentities) Upsert(context.Context, identity.UpsertInput) (*identity.Identity, error) {
	return nil, errors.New("unexpected")
}
func (f *fakeIdentities) FindByOpenID(context.Context, identity.FindQuery) (*identity.Identity, error) {
	return nil, identity.ErrNotFound
}
func (f *fakeIdentities) FindByID(_ context.Context, _ int64, id int64) (*identity.Identity, error) {
	if i, ok := f.byID[id]; ok {
		return i, nil
	}
	return nil, identity.ErrNotFound
}

type fakeSessions struct {
	calls   *[]string
	revoked int64
	err     error
}

func (f *fakeSessions) Create(context.Context, session.CreateInput) (*session.RefreshToken, error) {
	return nil, errors.New("unexpected")
}
func (f *fakeSessions) FindByHash(context.Context, int64, string) (*session.RefreshToken, error) {
	return nil, session.ErrNotFound
}
func (f *fakeSessions) Revoke(context.Context, int64, int64, string) error { return nil }
func (f *fakeSessions) RevokeChainFrom(context.Context, int64, int64, string) (int, error) {
	return 0, nil
}
func (f *fakeSessions) RevokeAllByUser(context.Context, int64, string, string) (int64, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, "revoke_tokens")
	}
	return f.revoked, f.err
}

type fakeRevocation struct {
	calls *[]string
	water time.Time
	err   error
}

func (f *fakeRevocation) RevokeJTI(context.Context, string, time.Duration) error { return nil }
func (f *fakeRevocation) IsJTIRevoked(context.Context, string) (bool, error)     { return false, nil }
func (f *fakeRevocation) RevokeUser(_ context.Context, _ int64, _ string, at time.Time, _ time.Duration) error {
	if f.calls != nil {
		*f.calls = append(*f.calls, "revoke_watermark")
	}
	f.water = at
	return f.err
}
func (f *fakeRevocation) RevokedAt(context.Context, int64, string) (time.Time, error) {
	return time.Time{}, nil
}

type fakeClaims struct {
	calls *[]string
	ids   []int64
	n     int64
	err   error
}

func (f *fakeClaims) Insert(context.Context, identity.ClaimUpsertInput) (*identity.Claim, error) {
	return nil, errors.New("unexpected")
}
func (f *fakeClaims) FindVerified(context.Context, int64, string, string) (*identity.Claim, error) {
	return nil, identity.ErrNotFound
}
func (f *fakeClaims) FindByID(context.Context, int64, int64) (*identity.Claim, error) {
	return nil, identity.ErrNotFound
}
func (f *fakeClaims) ListByIdentity(context.Context, int64, int64) ([]identity.Claim, error) {
	return nil, nil
}
func (f *fakeClaims) Revoke(context.Context, int64, int64, string, string, time.Time) error {
	return nil
}
func (f *fakeClaims) PurgeByIdentities(_ context.Context, _ int64, ids []int64) (int64, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, "purge_claims")
	}
	f.ids = ids
	return f.n, f.err
}

type fakeAudit struct{ events []*audit.Event }

func (f *fakeAudit) Write(_ context.Context, e *audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

// --- 用例 ---

func newSvc(t *testing.T, mod func(*Deps)) (*Service, *fakeAccounts, *fakeBindings, *fakeSessions, *fakeRevocation, *fakeClaims, *fakeAudit, *[]string) {
	t.Helper()
	calls := &[]string{}
	acc := &fakeAccounts{calls: calls, supportClose: true}
	bindings := &fakeBindings{rows: []binding.Binding{
		{IdentityID: 11, Status: "active"},
		{IdentityID: 12, Status: "active"},
	}}
	sessions := &fakeSessions{calls: calls, revoked: 3}
	revocation := &fakeRevocation{calls: calls}
	claims := &fakeClaims{calls: calls, n: 2}
	au := &fakeAudit{}

	deps := Deps{
		Tenant:   fakeApps{},
		Accounts: acc,
		Bindings: bindings,
		Identities: &fakeIdentities{byID: map[int64]*identity.Identity{
			11: {ID: 11, Platform: "wechat"},
			12: {ID: 12, Platform: "apple"},
		}},
		Sessions:   sessions,
		Revocation: revocation,
		Claims:     claims,
		Audit:      au,
		Logger:     zap.NewNop(),
	}
	if mod != nil {
		mod(&deps)
	}
	return New(deps), acc, bindings, sessions, revocation, claims, au, calls
}

func TestCloseCascadesEverything(t *testing.T) {
	svc, _, bindings, _, revocation, claims, au, _ := newSvc(t, nil)

	res, err := svc.Close(context.Background(), "app_a", "user_1", "不想用了")
	if err != nil {
		t.Fatalf("注销应成功: %v", err)
	}
	if res.ClosedBindings != 2 {
		t.Fatalf("应解除 2 条绑定，实际 %d", res.ClosedBindings)
	}
	if res.RevokedTokens != 3 || res.PurgedClaims != 2 {
		t.Fatalf("令牌/凭证清理数不对: %+v", res)
	}
	if len(bindings.unbound) != 2 {
		t.Fatalf("两条绑定都应被解除，实际 %v", bindings.unbound)
	}
	if len(claims.ids) != 2 {
		t.Fatalf("应清理两条身份下的凭证，实际 %v", claims.ids)
	}
	if revocation.water.IsZero() {
		t.Fatal("必须写账号撤销水位，否则已签发的 access_token 会继续有效到自然过期")
	}
	if len(res.Warnings) != 2 {
		t.Fatalf("两个渠道都应产出人工撤销提示，实际 %+v", res.Warnings)
	}
	if len(au.events) != 1 || au.events[0].Action != "account.close" {
		t.Fatalf("应写一条 account.close 审计，实际 %+v", au.events)
	}
	if au.events[0].Detail["reason"] != "不想用了" {
		t.Fatalf("用户给出的原因应进审计，实际 %v", au.events[0].Detail)
	}
}

// 这条用例盯的是整个流程最关键的一条约束：先关对端。
//
// 顺序反了的话，中途失败会让"对端 active + 本地已解绑"，用户下次登录会
// 自动创建新账号——注销变成"看起来删了，其实多了一个空账号"。
func TestCloseCallsRemoteBeforeLocalCleanup(t *testing.T) {
	svc, _, _, _, _, _, _, calls := newSvc(t, nil)

	if _, err := svc.Close(context.Background(), "app_a", "user_1", ""); err != nil {
		t.Fatalf("注销应成功: %v", err)
	}
	if len(*calls) < 4 {
		t.Fatalf("调用次数不足: %v", *calls)
	}
	if (*calls)[0] != "remote_close" {
		t.Fatalf("必须先关对端，实际顺序 %v", *calls)
	}
}

// 对端关闭失败时，本地一个字节都不能动。
func TestCloseAbortsWhenRemoteFails(t *testing.T) {
	svc, _, bindings, _, revocation, claims, au, _ := newSvc(t, func(d *Deps) {
		(d.Accounts.(*fakeAccounts)).closeFn = func() error {
			return errs.New(errs.CodeAccountUnavailable, "用户中心不可用")
		}
	})

	if _, err := svc.Close(context.Background(), "app_a", "user_1", ""); err == nil {
		t.Fatal("对端关闭失败必须整体失败")
	}
	if len(bindings.unbound) != 0 || len(claims.ids) != 0 || !revocation.water.IsZero() {
		t.Fatal("对端失败后不应清本地：那会造成数据分叉")
	}
	if len(au.events) != 1 || au.events[0].Result != audit.ResultFailure {
		t.Fatalf("失败也要留审计，实际 %+v", au.events)
	}
	if au.events[0].ErrorCode == "" {
		t.Fatal("失败审计应带错误码")
	}
}

// provider 不支持注销时拒绝，而不是"只清本地"。
func TestCloseRejectsWhenProviderCannotClose(t *testing.T) {
	svc, _, bindings, _, _, claims, _, _ := newSvc(t, func(d *Deps) {
		// 换成一个只实现 Provider、不实现 AccountCloser 的实现。
		d.Accounts = providerOnly{}
	})

	_, err := svc.Close(context.Background(), "app_a", "user_1", "")
	if err == nil {
		t.Fatal("对端不支持注销时必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAccountNotSupported {
		t.Fatalf("错误码应为 %s，实际 %s", errs.CodeAccountNotSupported, errs.CodeOf(err))
	}
	if len(bindings.unbound) != 0 || len(claims.ids) != 0 {
		t.Fatal("拒绝时不能动本地数据")
	}
}

// 单条解绑失败不阻断其余清理：否则一条脏数据能让用户永远注销不掉。
func TestCloseContinuesWhenOneUnbindFails(t *testing.T) {
	svc, _, bindings, _, _, claims, _, _ := newSvc(t, nil)
	bindings.failOn = 11

	res, err := svc.Close(context.Background(), "app_a", "user_1", "")
	if err != nil {
		t.Fatalf("单条解绑失败不应让整个注销失败: %v", err)
	}
	if res.ClosedBindings != 1 {
		t.Fatalf("应只计成功的那 1 条，实际 %d", res.ClosedBindings)
	}
	if len(claims.ids) != 2 {
		t.Fatal("凭证清理应包含全部身份，包括解绑失败的那条")
	}
}

// 撤销水位写失败不阻断注销：PII 清除比令牌过期更重要。
func TestCloseSurvivesWatermarkFailure(t *testing.T) {
	svc, _, _, _, _, claims, _, _ := newSvc(t, func(d *Deps) {
		d.Revocation = &fakeRevocation{err: errors.New("redis down")}
	})

	res, err := svc.Close(context.Background(), "app_a", "user_1", "")
	if err != nil {
		t.Fatalf("水位失败不应让注销失败: %v", err)
	}
	if res.PurgedClaims != 2 || len(claims.ids) != 2 {
		t.Fatal("水位失败后仍应继续清理凭证")
	}
}

// 令牌撤销失败要整体失败：这一步没做成，用户手里的 refresh_token 还能换新令牌。
func TestCloseFailsWhenTokenRevokeFails(t *testing.T) {
	svc, _, _, _, _, claims, _, _ := newSvc(t, func(d *Deps) {
		d.Sessions = &fakeSessions{err: errors.New("db down")}
	})

	if _, err := svc.Close(context.Background(), "app_a", "user_1", ""); err == nil {
		t.Fatal("令牌撤销失败必须整体失败")
	}
	if len(claims.ids) != 0 {
		t.Fatal("失败时不应继续清理凭证")
	}
}

func TestCloseRequiresUserID(t *testing.T) {
	svc, _, _, _, _, _, _, _ := newSvc(t, nil)
	if _, err := svc.Close(context.Background(), "app_a", "", ""); err == nil {
		t.Fatal("缺少 user_id 必须拒绝")
	}
}

// providerOnly 只实现 account.Provider，用于验证"能力缺失"分支。
type providerOnly struct{}

func (providerOnly) Get(context.Context, string, string) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (providerOnly) GetByClaim(context.Context, string, account.Claim) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (providerOnly) Create(context.Context, account.CreateRequest) (*account.Account, error) {
	return nil, errs.New(errs.CodeAccountNotSupported, "不支持")
}
func (providerOnly) Merge(context.Context, account.MergeRequest) (*account.MergeResult, error) {
	return nil, errs.New(errs.CodeAccountNotSupported, "不支持")
}
