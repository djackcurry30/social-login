package merge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
)

// --- fakes ---

type fakeStore struct {
	existing *mergex.Operation // Create 的返回（模拟已有记录）
	created  bool
	created_ *mergex.Operation

	markDone   int
	markFailed int
	markDead   int
	lastErr    string
	lastRemote map[string]any
}

func (f *fakeStore) Create(_ context.Context, op *mergex.Operation) (*mergex.Operation, bool, error) {
	f.created_ = op
	if f.existing != nil {
		return f.existing, f.created, nil
	}
	cp := *op
	cp.ID = 42
	cp.Status = mergex.StatusPending
	return &cp, true, nil
}

func (f *fakeStore) Get(context.Context, int64) (*mergex.Operation, error) {
	return f.existing, nil
}

func (f *fakeStore) List(context.Context, mergex.Filter) ([]*mergex.Operation, int64, error) {
	return nil, 0, nil
}

func (f *fakeStore) MarkDone(context.Context, int64, map[string]any) error {
	f.markDone++
	return nil
}

func (f *fakeStore) MarkFailed(_ context.Context, _ int64, remote map[string]any, errMsg string) error {
	f.markFailed++
	f.lastRemote = remote
	f.lastErr = errMsg
	return nil
}

func (f *fakeStore) MarkDead(_ context.Context, _ int64, errMsg string) error {
	f.markDead++
	f.lastErr = errMsg
	return nil
}

func (f *fakeStore) MarkRejected(context.Context, int64, string) error { return nil }

func (f *fakeStore) ListDue(context.Context, int) ([]*mergex.Operation, error) { return nil, nil }

type fakeAccounts struct {
	err    error
	result *account.MergeResult
	calls  int
	last   account.MergeRequest
}

func (f *fakeAccounts) Get(context.Context, string) (*account.Account, error) {
	return nil, account.ErrNotFound
}

func (f *fakeAccounts) GetByClaim(context.Context, account.Claim) (*account.Account, error) {
	return nil, account.ErrNotFound
}

func (f *fakeAccounts) Create(context.Context, account.CreateRequest) (*account.Account, error) {
	return nil, errors.New("not supported")
}

func (f *fakeAccounts) Merge(_ context.Context, req account.MergeRequest) (*account.MergeResult, error) {
	f.calls++
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
	return &account.MergeResult{Merged: true, RemoteRef: map[string]any{"id": "r1"}}, nil
}

type fakeConverger struct {
	err  error
	last *mergex.ConvergeInput
}

func (f *fakeConverger) Converge(_ context.Context, in mergex.ConvergeInput) error {
	f.last = &in
	return f.err
}

type fakeLocker struct{ locked bool }

func (f *fakeLocker) Lock(context.Context, string, time.Duration) (func(), error) {
	if f.locked {
		return nil, mergex.ErrLocked
	}
	return func() {}, nil
}

func appWithMode(mode string) *tenant.Application {
	p := tenant.DefaultPolicy()
	p.Merge.Mode = mode
	return &tenant.Application{ID: 3, AppCode: "app-x", Policy: p}
}

func newSvc(opts ...func(*Deps)) (*Service, *fakeStore, *fakeAccounts, *fakeConverger) {
	st := &fakeStore{}
	ac := &fakeAccounts{}
	cv := &fakeConverger{}
	d := Deps{
		Ops:              st,
		Converger:        cv,
		Accounts:         ac,
		Locker:           &fakeLocker{},
		RemoteIdempotent: true,
	}
	for _, o := range opts {
		o(&d)
	}
	return New(d), st, ac, cv
}

func reqAuto() Request {
	return Request{
		App:          appWithMode(tenant.MergeModeAuto),
		TargetUserID: "user-C",
		SourceUserID: "user-B",
		Identity:     &identity.Identity{ID: 9, Platform: "wechat"},
		Trigger:      TriggerBind,
		Reason:       "test",
	}
}

// --- 前置校验 ---

func TestExecuteRejectsSelfMerge(t *testing.T) {
	svc, _, ac, _ := newSvc()
	r := reqAuto()
	r.SourceUserID = r.TargetUserID
	if _, err := svc.Execute(context.Background(), r); err == nil {
		t.Fatal("目标与源相同时必须拒绝")
	}
	if ac.calls != 0 {
		t.Fatal("校验失败不得调用用户中心")
	}
}

// TestManualModeRejected 是 manual 的语义边界：
// 不允许合并，但也不能"什么都不返回让调用方以为成功"。
func TestManualModeRejected(t *testing.T) {
	svc, st, ac, _ := newSvc()
	r := reqAuto()
	r.App = appWithMode(tenant.MergeModeManual)

	_, err := svc.Execute(context.Background(), r)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("manual 应返回 ErrRejected，实际=%v", err)
	}
	if st.created_ != nil || ac.calls != 0 {
		t.Fatal("被拒绝时不得落库、不得调用远端")
	}
}

// TestConfirmNeedsVerification 守住最关键的一条：confirm 不能被静默降级为 auto。
func TestConfirmNeedsVerification(t *testing.T) {
	svc, st, ac, _ := newSvc()
	r := reqAuto()
	r.App = appWithMode(tenant.MergeModeConfirm)

	_, err := svc.Execute(context.Background(), r)
	if !errors.Is(err, ErrNeedVerification) {
		t.Fatalf("confirm 应要求验证，实际=%v", err)
	}
	if st.created_ != nil || ac.calls != 0 {
		t.Fatal("需要验证时不得产生任何数据变更")
	}
}

// --- 成功路径 ---

func TestAutoMergeConvergesWithEvent(t *testing.T) {
	svc, st, ac, cv := newSvc()
	r := reqAuto()
	r.Identity = &identity.Identity{ID: 9, Platform: "wechat"}

	res, err := svc.Execute(context.Background(), r)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if res == nil || res.OperationID != 42 || res.AlreadyMerged {
		t.Fatalf("结果不符: %+v", res)
	}
	if ac.calls != 1 {
		t.Fatalf("应调用用户中心 1 次，实际 %d", ac.calls)
	}
	// 幂等键必须是确定性的且传给远端：用户中心靠它去重。
	if ac.last.IdempotencyKey == "" || ac.last.IdempotencyKey != st.created_.IdempotencyKey {
		t.Fatalf("传给远端的幂等键应与落库一致: %q vs %q",
			ac.last.IdempotencyKey, st.created_.IdempotencyKey)
	}
	if cv.last == nil {
		t.Fatal("必须执行本地收敛")
	}
	if cv.last.Event == nil || cv.last.Event.Type != "account.merged" {
		t.Fatal("事件必须与收敛同事务写入")
	}
	if cv.last.Event.Payload["target_user_id"] != "user-C" {
		t.Fatalf("事件体缺少目标账号: %+v", cv.last.Event.Payload)
	}
	// R4 红线 2：通知标记必须是 true，不允许被配置关掉。
	if cv.last.Event.Payload["notify_source_account"] != true {
		t.Fatal("事件体必须声明通知 source 账号")
	}
	if cv.last.Audit == nil || cv.last.Audit.Action != "merge" {
		t.Fatal("审计必须与收敛同事务写入")
	}
}

// TestIdempotentWhenAlreadyDone：重复请求返回 AlreadyMerged，不再调远端。
func TestIdempotentWhenAlreadyDone(t *testing.T) {
	svc, _, ac, cv := newSvc(func(d *Deps) {})
	svc.deps.Ops = &fakeStore{existing: &mergex.Operation{
		ID: 7, Status: mergex.StatusDone, IdempotencyKey: "k",
	}}

	res, err := svc.Execute(context.Background(), reqAuto())
	if err != nil {
		t.Fatalf("幂等命中不应报错: %v", err)
	}
	if !res.AlreadyMerged {
		t.Fatal("应返回 AlreadyMerged")
	}
	if ac.calls != 0 {
		t.Fatal("已完成的合并不应再次调用用户中心")
	}
	if cv.last != nil {
		t.Fatal("已完成的合并不应再次收敛")
	}
}

// TestLockedReturnsConflict：并发合并不是失败，应提示稍后重试。
func TestLockedReturnsConflict(t *testing.T) {
	svc, _, ac, _ := newSvc(func(d *Deps) { d.Locker = &fakeLocker{locked: true} })
	if _, err := svc.Execute(context.Background(), reqAuto()); err == nil {
		t.Fatal("拿不到锁必须报错")
	}
	if ac.calls != 0 {
		t.Fatal("拿不到锁不得调用远端")
	}
}

// --- 失败路径 ---

func TestRemoteFailureMarksFailedWhenIdempotent(t *testing.T) {
	svc, st, _, cv := newSvc()
	svc.deps.Accounts = &fakeAccounts{err: errors.New("timeout")}

	if _, err := svc.Execute(context.Background(), reqAuto()); err == nil {
		t.Fatal("远端失败必须报错")
	}
	if st.markFailed != 1 || st.markDead != 0 {
		t.Fatalf("幂等远端失败应标 failed，实际 failed=%d dead=%d", st.markFailed, st.markDead)
	}
	if cv.last != nil {
		t.Fatal("远端失败时本地不得收敛")
	}
}

// TestRemoteFailureMarksDeadWhenNotIdempotent 是 §7.3 的硬性要求：
// 非幂等的 Merge 绝不能进自动重试链路。
func TestRemoteFailureMarksDeadWhenNotIdempotent(t *testing.T) {
	svc, st, _, _ := newSvc(func(d *Deps) { d.RemoteIdempotent = false })
	svc.deps.Accounts = &fakeAccounts{err: errors.New("timeout")}

	if _, err := svc.Execute(context.Background(), reqAuto()); err == nil {
		t.Fatal("远端失败必须报错")
	}
	if st.markDead != 1 || st.markFailed != 0 {
		t.Fatalf("非幂等远端应直接 dead，实际 failed=%d dead=%d", st.markFailed, st.markDead)
	}
}

// TestConvergeFailureMarksFailed：远端成功但本地失败，这是最需要补偿的状态。
func TestConvergeFailureMarksFailed(t *testing.T) {
	svc, st, _, _ := newSvc(func(d *Deps) {
		d.Converger = &fakeConverger{err: errors.New("db down")}
	})

	_, err := svc.Execute(context.Background(), reqAuto())
	if err == nil {
		t.Fatal("收敛失败必须报错")
	}
	if st.markFailed != 1 {
		t.Fatalf("应标 failed 等待补偿，实际 %d", st.markFailed)
	}
	// remote_result 必须落下来，否则补偿时无法判断"远端到底成功没有"。
	if st.lastRemote == nil {
		t.Fatal("应保存远端结果")
	}
}

// --- 补偿 ---

func TestResumeSkipsWhenRemoteNotIdempotent(t *testing.T) {
	svc, st, ac, _ := newSvc(func(d *Deps) { d.RemoteIdempotent = false })
	op := &mergex.Operation{ID: 1, Status: mergex.StatusFailed, Attempts: 1}

	if err := svc.Resume(context.Background(), op); err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if ac.calls != 0 || st.markFailed != 0 {
		t.Fatal("非幂等远端不得自动重放")
	}
}

func TestResumeConvergesWithoutPrecheck(t *testing.T) {
	svc, _, ac, cv := newSvc()
	svc.SetAppLookup(func(context.Context, int64) (*tenant.Application, error) {
		return appWithMode(tenant.MergeModeAuto), nil
	})
	// 即使应用后来被改成 manual，补偿也必须把已决定的事做完——
	// 否则远端已合并、本地永远停在半路。
	op := &mergex.Operation{
		ID: 11, AppID: 3, Status: mergex.StatusFailed, Attempts: 1,
		IdempotencyKey: "k", TargetUserID: "user-C", SourceUserID: "user-B",
	}
	if err := svc.Resume(context.Background(), op); err != nil {
		t.Fatalf("补偿失败: %v", err)
	}
	if ac.calls != 1 || cv.last == nil {
		t.Fatal("补偿应重放远端并收敛")
	}
}

// --- 幂等键 ---

func TestIdempotencyKeyIsDeterministic(t *testing.T) {
	r := reqAuto()
	a := idempotencyKey(r)
	b := idempotencyKey(r)
	if a != b {
		t.Fatalf("同参数必须生成相同幂等键: %q vs %q", a, b)
	}
	r2 := reqAuto()
	r2.SourceUserID = "user-D"
	if idempotencyKey(r2) == a {
		t.Fatal("不同源账号必须生成不同幂等键")
	}
}
