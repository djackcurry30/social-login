package accountsync

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
)

// --- 测试替身 ---

type fakeApps struct {
	mu   sync.Mutex
	apps map[string]*tenant.Application
	// listErr 注入"读应用列表失败"（库不可用）。
	listErr error
}

func newFakeApps(apps ...*tenant.Application) *fakeApps {
	m := make(map[string]*tenant.Application, len(apps))
	for _, a := range apps {
		m[a.AppCode] = a
	}
	return &fakeApps{apps: m}
}

func (f *fakeApps) ListForSync(_ context.Context, limit int) ([]tenant.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]tenant.Application, 0, len(f.apps))
	for _, a := range f.apps {
		out = append(out, *a)
	}
	// 固定顺序：并发对账的结果计数与顺序无关，但测试失败时的输出要好读。
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeApps) FindByAppCode(_ context.Context, appCode string) (*tenant.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.apps[appCode]
	if !ok {
		return nil, tenant.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (f *fakeApps) put(a *tenant.Application) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.apps[a.AppCode] = a
}

type fakeRegistrar struct {
	mu sync.Mutex
	// got 记录每次注册请求，按到达顺序。
	got []account.AppRegistration
	// failFor 指定哪些 app_key 注册失败。
	failFor map[string]error
	// block 非 nil 时每次调用都阻塞到它被关闭（用于验证非阻塞入队）。
	block chan struct{}
	// delay 模拟慢对端（用于验证单次调用超时）。
	delay time.Duration
	// events 在每次成功/失败调用后投递 app_key + 状态，供 Run 的用例等待。
	events chan string
}

func (f *fakeRegistrar) RegisterApp(ctx context.Context, reg account.AppRegistration) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	f.mu.Lock()
	f.got = append(f.got, reg)
	err := f.failFor[reg.AppKey]
	f.mu.Unlock()

	if f.events != nil {
		select {
		case f.events <- reg.AppKey + ":" + string(reg.Status):
		default:
		}
	}
	return err
}

func (f *fakeRegistrar) registrations() []account.AppRegistration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]account.AppRegistration(nil), f.got...)
}

type fakeRecorder struct {
	mu     sync.Mutex
	synced map[int64]time.Time
	failed map[int64]string
	// writeErr 注入"写状态失败"（库抖动）。
	writeErr error
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{synced: map[int64]time.Time{}, failed: map[int64]string{}}
}

func (f *fakeRecorder) MarkUCSynced(_ context.Context, appID int64, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.synced[appID] = at
	// 成功后清空错误，与方法契约一致。
	delete(f.failed, appID)
	return nil
}

func (f *fakeRecorder) MarkUCSyncFailed(_ context.Context, appID int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.failed[appID] = reason
	return nil
}

// --- 用例 ---

func app(id int64, code string, status int16) *tenant.Application {
	return &tenant.Application{
		ID: id, AppCode: code, Name: "应用" + code, Status: status,
		UpdatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

// TestReconcileSyncsAllApps 验证全量对账的基本行为。
//
// 其中"停用应用也要同步"是一条容易被"优化掉"的规则：看起来停用的应用
// 不需要注册，但对端需要知道它停了——否则对端会继续认为该应用可用，
// 排查时"本地明明停了"与"对端还能用"会同时成立。
func TestReconcileSyncsAllApps(t *testing.T) {
	apps := newFakeApps(
		app(1, "app_a", 1),
		app(2, "app_b", 0),
	)
	reg := &fakeRegistrar{}
	rec := newFakeRecorder()

	svc := New(Deps{Apps: apps, Registrar: reg, Recorder: rec, Workers: 2})
	rep, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("对账不应失败: %v", err)
	}
	if rep.Total != 2 || rep.Succeeded != 2 || rep.Failed != 0 {
		t.Fatalf("统计不符：%+v", rep)
	}

	got := reg.registrations()
	if len(got) != 2 {
		t.Fatalf("应注册两个应用，实际 %d", len(got))
	}
	byKey := map[string]account.AppRegistration{}
	for _, r := range got {
		byKey[r.AppKey] = r
	}
	if byKey["app_a"].Status != account.AppStatusActive {
		t.Fatalf("启用应用应注册为 active，实际 %q", byKey["app_a"].Status)
	}
	if byKey["app_b"].Status != account.AppStatusDisabled {
		t.Fatalf("停用应用应注册为 disabled，实际 %q", byKey["app_b"].Status)
	}
	// 名称要带过去：它是对端唯一能用肉眼识别租户的信息。
	if byKey["app_a"].Name != "应用app_a" {
		t.Fatalf("名称未透传：%q", byKey["app_a"].Name)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.synced) != 2 {
		t.Fatalf("两个应用都应记录成功，实际 %v", rec.synced)
	}
}

// TestReconcileIsolatesFailure 验证"一个应用失败不影响其余"。
//
// 这条很重要：对端可能因为某个 app_key 的历史脏数据而单独拒绝它，
// 若整轮对账因此中断，其余几十个应用会跟着不可用。
func TestReconcileIsolatesFailure(t *testing.T) {
	apps := newFakeApps(app(1, "app_ok", 1), app(2, "app_bad", 1))
	reg := &fakeRegistrar{failFor: map[string]error{
		"app_bad": errors.New("对端拒绝：app_key 已存在但与本地不一致"),
	}}
	rec := newFakeRecorder()

	svc := New(Deps{Apps: apps, Registrar: reg, Recorder: rec, Workers: 1})
	rep, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("单个应用失败不应让整轮对账报错: %v", err)
	}
	if rep.Total != 2 || rep.Succeeded != 1 || rep.Failed != 1 {
		t.Fatalf("统计不符：%+v", rep)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if _, ok := rec.synced[1]; !ok {
		t.Fatal("成功的应用应记录成功")
	}
	if reason, ok := rec.failed[2]; !ok || reason == "" {
		t.Fatalf("失败的应用应记录原因，实际 %v", rec.failed)
	}
}

// TestSyncTimeoutIsRecorded 验证单次调用超时被当作失败落库。
//
// 后台任务没有入站 deadline 可继承，"对端接住了但不回"是真实会发生的
// （网关挂起、对端死锁）。没有单次超时的话，这个 worker 会被永久占住。
func TestSyncTimeoutIsRecorded(t *testing.T) {
	apps := newFakeApps(app(1, "app_slow", 1))
	reg := &fakeRegistrar{delay: 200 * time.Millisecond}
	rec := newFakeRecorder()

	svc := New(Deps{
		Apps: apps, Registrar: reg, Recorder: rec,
		Workers: 1, Timeout: 20 * time.Millisecond,
	})
	rep, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("对账本身不应报错: %v", err)
	}
	if rep.Failed != 1 {
		t.Fatalf("超时应计为失败，实际 %+v", rep)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if _, ok := rec.failed[1]; !ok {
		t.Fatalf("超时应记录失败原因，实际 %v", rec)
	}
	if _, ok := rec.synced[1]; ok {
		t.Fatal("超时不应记录成功")
	}
}

// TestNotifyAppChangedNeverBlocks 验证入队是非阻塞的。
//
// 这是整组设计里最容易被"优化"掉的一条：把队列改成阻塞发送，代码看起来
// 更严谨（不丢任务），但后果是"用户中心故障 → 建不了应用"，而建应用恰恰
// 是恢复期最需要的操作。丢任务的代价只是等下一轮对账（≤5 分钟）。
func TestNotifyAppChangedNeverBlocks(t *testing.T) {
	// registrar 永不放行，worker 会卡住；此处连 Run 都不启动，队列必然填满。
	reg := &fakeRegistrar{block: make(chan struct{})}
	svc := New(Deps{Apps: newFakeApps(), Registrar: reg, Recorder: newFakeRecorder()})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 远超队列容量：前 queueSize 个进队列，其余走 default 分支被丢弃。
		for i := 0; i < queueSize*3; i++ {
			svc.NotifyAppChanged("app_x")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("入队发生阻塞：建应用会被用户中心故障拖死")
	}
}

// TestRunSyncsQueuedAppWithLatestState 验证即时同步会回查最新状态。
//
// "回查"而不是"带快照"是有原因的：建完应用可能立刻被改（改名/停用），
// 队列里那份就是过期的。这里用"入队后把应用改成停用"来验证同步拿到的是
// 新状态，而不是入队那一刻的旧状态。
func TestRunSyncsQueuedAppWithLatestState(t *testing.T) {
	apps := newFakeApps(app(1, "app_q", 1))
	reg := &fakeRegistrar{events: make(chan string, 16)}
	rec := newFakeRecorder()
	svc := New(Deps{
		Apps: apps, Registrar: reg, Recorder: rec,
		Interval: time.Hour, // 关掉定时对账，只验即时路径
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.Run(ctx)

	// 先吃掉启动对账那一次（app_q:active）。
	if got := waitEvent(t, reg.events); got != "app_q:active" {
		t.Fatalf("启动对账事件不符：%q", got)
	}

	// 改动后入队：同步应拿到新状态。
	apps.put(app(1, "app_q", 0))
	svc.NotifyAppChanged("app_q")

	if got := waitEvent(t, reg.events); got != "app_q:disabled" {
		t.Fatalf("即时同步应使用最新状态，实际 %q", got)
	}
}

// TestNotifyUnknownAppIsIgnored 验证应用被删后入队不会报错。
func TestNotifyUnknownAppIsIgnored(t *testing.T) {
	reg := &fakeRegistrar{events: make(chan string, 4)}
	svc := New(Deps{
		Apps: newFakeApps(), Registrar: reg, Recorder: newFakeRecorder(),
		Interval: time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.Run(ctx)

	svc.NotifyAppChanged("app_gone")

	select {
	case ev := <-reg.events:
		t.Fatalf("已删除的应用不应产生注册调用，实际 %q", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestNilRegistrarIsNoop 验证"没有用户中心"是合法状态。
//
// stub 模式下根本没有注册端口。此时整个同步能力关闭，且不报错——
// 报错会让演示环境无法启动，而演示环境恰恰是最常跑 stub 的地方。
func TestNilRegistrarIsNoop(t *testing.T) {
	svc := New(Deps{Apps: newFakeApps(app(1, "app_a", 1)), Recorder: newFakeRecorder()})

	rep, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("没有注册端口时不该报错: %v", err)
	}
	if rep.Total != 0 || rep.Succeeded != 0 || rep.Failed != 0 {
		t.Fatalf("没有注册端口时不应做任何事，实际 %+v", rep)
	}

	// Run 应立即返回，否则会挂住调用方的 WaitGroup。
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("没有注册端口时 Run 应立即返回")
	}
}

// TestReconcileListFailure 验证读不到应用列表时报错（而不是当成"没有应用"）。
//
// 静默吞掉会让"库不可用"表现成"同步一切正常，只是没有应用要同步"，
// 而实际上这一轮什么都没做。
func TestReconcileListFailure(t *testing.T) {
	apps := newFakeApps()
	apps.listErr = errors.New("db down")
	svc := New(Deps{Apps: apps, Registrar: &fakeRegistrar{}, Recorder: newFakeRecorder()})

	if _, err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("读列表失败必须报错")
	}
}

// TestRunStopsOnCancel 验证后台循环可被 ctx 停止（避免 goroutine 泄漏）。
func TestRunStopsOnCancel(t *testing.T) {
	svc := New(Deps{
		Apps: newFakeApps(), Registrar: &fakeRegistrar{}, Recorder: newFakeRecorder(),
		Interval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(ctx)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ctx 取消后 Run 应退出")
	}
}

// TestStatusMapping 验证状态映射对脏值保守处理。
//
// 未知状态映射成 disabled 是刻意的偏向：宁可让对端认为应用停用（业务会
// 立刻不可用、但马上被发现），也不要让一个状态不明的应用在对端保持启用。
func TestStatusMapping(t *testing.T) {
	cases := []struct {
		in   int16
		want account.AppStatus
	}{
		{1, account.AppStatusActive},
		{0, account.AppStatusDisabled},
		{9, account.AppStatusDisabled},
		{-1, account.AppStatusDisabled},
	}
	for _, c := range cases {
		if got := statusOf(c.in); got != c.want {
			t.Fatalf("status=%d 应映射为 %q，实际 %q", c.in, c.want, got)
		}
	}
}

// TestRecordWriteFailureDoesNotLoseSync 验证"写状态失败"不影响同步结果判定。
//
// 状态写失败是次要故障：同步真的成功了，只是管理端看不到。把主结果改成
// 失败会让对账统计失真，进而掩盖真正的失败。
func TestRecordWriteFailureDoesNotLoseSync(t *testing.T) {
	apps := newFakeApps(app(1, "app_a", 1))
	rec := newFakeRecorder()
	rec.writeErr = errors.New("db timeout")

	svc := New(Deps{Apps: apps, Registrar: &fakeRegistrar{}, Recorder: rec})
	rep, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("对账不应报错: %v", err)
	}
	if rep.Succeeded != 1 {
		t.Fatalf("注册成功就应计为成功（状态写失败是次要故障），实际 %+v", rep)
	}
}

// waitEvent 等待一个注册事件，超时即失败。
func waitEvent(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("等待注册调用超时")
		return ""
	}
}
