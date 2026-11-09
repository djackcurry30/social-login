package claimsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// 这组用例守的是"通知处理既要生效又不能变成阻塞源"：
// 未知应用、未知类型要能被投递方识别为永久失败；
// 没有绑定 / 重复投递要返回成功（否则对端会无限重投）。

type fakeApps struct {
	app *tenant.Application
	err error
}

func (f *fakeApps) FindByAppCode(context.Context, string) (*tenant.Application, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.app, nil
}
func (f *fakeApps) FindByID(context.Context, int64) (*tenant.Application, error) { return f.app, nil }
func (f *fakeApps) Upsert(_ context.Context, a *tenant.Application) (*tenant.Application, error) {
	return a, nil
}

type fakeBindings struct {
	list []binding.Binding
	err  error
}

func (f *fakeBindings) FindActiveByIdentity(context.Context, int64, int64) (*binding.Binding, error) {
	return nil, binding.ErrNotFound
}
func (f *fakeBindings) ListActiveByExternalUser(context.Context, int64, string) ([]binding.Binding, error) {
	return f.list, f.err
}
func (f *fakeBindings) Activate(context.Context, binding.ActivateInput) (*binding.Binding, bool, error) {
	return nil, false, nil
}
func (f *fakeBindings) Unbind(context.Context, int64, int64, time.Time) error { return nil }
func (f *fakeBindings) CountActive(context.Context, int64, string) (int, error) {
	return len(f.list), nil
}

// fakeClaims 记录每次按类型撤销的调用。
type fakeClaims struct {
	calls   []revokeCall
	revoked int64
	err     error
}

type revokeCall struct {
	identityID int64
	claimType  string
}

func (f *fakeClaims) RevokeByType(_ context.Context, _ int64, identityID int64, claimType string, _ time.Time) (int64, error) {
	f.calls = append(f.calls, revokeCall{identityID: identityID, claimType: claimType})
	return f.revoked, f.err
}

// 以下方法本包不使用。
func (f *fakeClaims) Insert(context.Context, identity.ClaimUpsertInput) (*identity.Claim, error) {
	return nil, errors.New("unexpected Insert")
}
func (f *fakeClaims) FindVerified(context.Context, int64, string, string) (*identity.Claim, error) {
	return nil, errors.New("unexpected FindVerified")
}
func (f *fakeClaims) FindByID(context.Context, int64, int64) (*identity.Claim, error) {
	return nil, errors.New("unexpected FindByID")
}
func (f *fakeClaims) ListByIdentity(context.Context, int64, int64) ([]identity.Claim, error) {
	return nil, nil
}
func (f *fakeClaims) Revoke(context.Context, int64, int64, string, string, time.Time) error {
	return nil
}
func (f *fakeClaims) PurgeByIdentities(context.Context, int64, []int64) (int64, error) {
	return 0, nil
}

type fakeMetrics struct{ results []string }

func (m *fakeMetrics) RecordClaimInvalidated(result string, _ int) {
	m.results = append(m.results, result)
}

func newSvc(bindings []binding.Binding, revoked int64) (*Service, *fakeClaims, *fakeMetrics) {
	cl := &fakeClaims{revoked: revoked}
	mt := &fakeMetrics{}
	svc := New(Deps{
		Apps:     &fakeApps{app: &tenant.Application{ID: 5, AppCode: "app_x"}},
		Bindings: &fakeBindings{list: bindings},
		Claims:   cl,
		Metrics:  mt,
		Now:      func() time.Time { return time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC) },
	})
	return svc, cl, mt
}

func twoBindings() []binding.Binding {
	return []binding.Binding{{IdentityID: 101}, {IdentityID: 102}}
}

func TestInvalidateRevokesAllBoundIdentities(t *testing.T) {
	svc, cl, mt := newSvc(twoBindings(), 1)

	res, err := svc.Invalidate(context.Background(), Input{
		AppKey: "app_x", UserID: "u1", ClaimType: "phone", Reason: "replaced",
	})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if res.Identities != 2 || res.Revoked != 2 {
		t.Fatalf("结果不符: %+v", res)
	}
	if len(cl.calls) != 2 {
		t.Fatalf("应对两个身份各撤销一次，实际 %+v", cl.calls)
	}
	if cl.calls[0].claimType != "phone" {
		t.Fatalf("应只撤销 phone，实际 %q", cl.calls[0].claimType)
	}
	if len(mt.results) != 1 || mt.results[0] != "ok" {
		t.Fatalf("指标应为 ok，实际 %v", mt.results)
	}
}

// TestInvalidateAllTypesOnClose 注销/合并时 claim_type 为空 → 撤销全部类型。
func TestInvalidateAllTypesOnClose(t *testing.T) {
	svc, cl, _ := newSvc(twoBindings(), 3)
	if _, err := svc.Invalidate(context.Background(), Input{
		AppKey: "app_x", UserID: "u1", Reason: "closed",
	}); err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	for _, c := range cl.calls {
		if c.claimType != "" {
			t.Fatalf("应撤销全部类型（空串），实际 %q", c.claimType)
		}
	}
}

// TestInvalidateNoBindingsIsSuccess 该账号在本服务没有绑定是正常情况，
// 必须返回成功，否则对端会把一条"本来就没事"的通知重投到死信。
func TestInvalidateNoBindingsIsSuccess(t *testing.T) {
	svc, cl, mt := newSvc(nil, 0)
	res, err := svc.Invalidate(context.Background(), Input{AppKey: "app_x", UserID: "u1", ClaimType: "phone"})
	if err != nil {
		t.Fatalf("无绑定不应报错: %v", err)
	}
	if res.Identities != 0 || len(cl.calls) != 0 {
		t.Fatalf("不应有任何撤销调用: %+v", res)
	}
	if mt.results[0] != "ignored" {
		t.Fatalf("应记为 ignored，实际 %v", mt.results)
	}
}

// TestInvalidateRepeatIsIdempotent 重复投递：撤销 0 行但成功。
// 这是"至少一次投递 + 接收方幂等"能成立的前提。
func TestInvalidateRepeatIsIdempotent(t *testing.T) {
	svc, _, mt := newSvc(twoBindings(), 0)
	res, err := svc.Invalidate(context.Background(), Input{AppKey: "app_x", UserID: "u1", ClaimType: "phone"})
	if err != nil {
		t.Fatalf("重复投递不应报错: %v", err)
	}
	if res.Revoked != 0 {
		t.Fatalf("重复投递应撤销 0 行，实际 %d", res.Revoked)
	}
	if mt.results[0] != "ignored" {
		t.Fatalf("应记为 ignored（区分重投比例），实际 %v", mt.results)
	}
}

// TestInvalidateUnknownAppIsNotFound 未知应用必须 404：
// 投递方据此判永久失败并进死信，而不是无限重试一个不存在的租户。
func TestInvalidateUnknownAppIsNotFound(t *testing.T) {
	svc := New(Deps{
		Apps:     &fakeApps{err: tenant.ErrNotFound},
		Bindings: &fakeBindings{},
		Claims:   &fakeClaims{},
	})
	_, err := svc.Invalidate(context.Background(), Input{AppKey: "nope", UserID: "u1"})
	if e := errs.From(err); e == nil || e.Code != errs.CodeNotFound {
		t.Fatalf("应为 NOT_FOUND，实际 %v", err)
	}
}

// TestInvalidateRejectsUnknownClaimType 未知类型必须 400：
// 静默忽略会让"本地永远有一条不该存在的 claim"，而没人知道。
func TestInvalidateRejectsUnknownClaimType(t *testing.T) {
	svc, cl, _ := newSvc(twoBindings(), 1)
	_, err := svc.Invalidate(context.Background(), Input{
		AppKey: "app_x", UserID: "u1", ClaimType: "passport",
	})
	if e := errs.From(err); e == nil || e.Code != errs.CodeInvalidRequest {
		t.Fatalf("应为 INVALID_REQUEST，实际 %v", err)
	}
	if len(cl.calls) != 0 {
		t.Fatal("参数不合法时不得动数据")
	}
}

func TestInvalidateRequiresIdentity(t *testing.T) {
	svc, _, _ := newSvc(twoBindings(), 1)
	if _, err := svc.Invalidate(context.Background(), Input{UserID: "u1"}); err == nil {
		t.Fatal("缺 app_key 必须拒绝")
	}
}

// TestInvalidateWritesAudit 审计要能回答"这条 claim 是被谁失效的"。
func TestInvalidateWritesAudit(t *testing.T) {
	w := &auditSpy{}
	svc := New(Deps{
		Apps:     &fakeApps{app: &tenant.Application{ID: 5, AppCode: "app_x"}},
		Bindings: &fakeBindings{list: twoBindings()},
		Claims:   &fakeClaims{revoked: 1},
		Audit:    w,
	})
	if _, err := svc.Invalidate(context.Background(), Input{
		AppKey: "app_x", UserID: "u1", ClaimType: "phone", Reason: "replaced", EventID: "42",
	}); err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if len(w.events) != 1 {
		t.Fatalf("应写一条审计，实际 %d", len(w.events))
	}
	ev := w.events[0]
	if ev.Action != AuditAction || ev.ExternalUserID != "u1" || ev.AppID != 5 {
		t.Fatalf("审计字段不符: %+v", ev)
	}
	if ev.Detail["event_id"] != "42" || ev.Detail["claim_type"] != "phone" {
		t.Fatalf("审计 detail 不符: %+v", ev.Detail)
	}
}

type auditSpy struct{ events []*audit.Event }

func (a *auditSpy) Write(_ context.Context, e *audit.Event) error {
	a.events = append(a.events, e)
	return nil
}
