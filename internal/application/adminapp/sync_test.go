package adminapp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- 测试替身 ---

// fakeAppRepo 是内存版应用仓储。
type fakeAppRepo struct {
	mu   sync.Mutex
	rows map[string]*tenant.Application
	seq  int64
	// failUpsert 注入写失败。
	failUpsert error
}

func newFakeAppRepo() *fakeAppRepo {
	return &fakeAppRepo{rows: map[string]*tenant.Application{}}
}

func (f *fakeAppRepo) FindByAppCode(_ context.Context, appCode string) (*tenant.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.rows[appCode]
	if !ok {
		return nil, tenant.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (f *fakeAppRepo) FindByID(_ context.Context, id int64) (*tenant.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.rows {
		if a.ID == id {
			cp := *a
			return &cp, nil
		}
	}
	return nil, tenant.ErrNotFound
}

func (f *fakeAppRepo) Upsert(_ context.Context, app *tenant.Application) (*tenant.Application, error) {
	if f.failUpsert != nil {
		return nil, f.failUpsert
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if app.AppCode == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "app_code 为空")
	}
	if prev, ok := f.rows[app.AppCode]; ok {
		// 保留创建时间与同步状态，模拟真实仓储"只更新写集合里的列"。
		app.ID = prev.ID
		app.CreatedAt = prev.CreatedAt
		app.AccountSync = prev.AccountSync
	} else {
		f.seq++
		app.ID = f.seq
		app.CreatedAt = time.Unix(1_700_000_000, 0).UTC()
	}
	cp := *app
	f.rows[app.AppCode] = &cp
	return app, nil
}

// fakeNotifier 记录被通知的 app_code。
type fakeNotifier struct {
	mu    sync.Mutex
	codes []string
}

func (f *fakeNotifier) NotifyAppChanged(appCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes = append(f.codes, appCode)
}

func (f *fakeNotifier) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.codes...)
}

// testHasher 是确定性的假哈希。
//
// 真实实现（crypto.AppSecretHasher）有自己的测试；这里只关心"建应用这个
// 动作有没有触发同步"，用假哈希可以让用例不依赖盐与 HMAC 的实现细节。
func testHasher(plain string) (string, error) { return "h:" + plain, nil }

// --- 用例 ---

// TestCreateAppNotifiesSync 验证建应用后会触发用户中心同步。
//
// 这条链路不做的话，用户中心上线后新建的应用"看起来建成了"，但该应用的
// 所有登录都会 400 APP.UNKNOWN —— 而且要等到有人来报障才会发现。
func TestCreateAppNotifiesSync(t *testing.T) {
	repo := newFakeAppRepo()
	notes := &fakeNotifier{}
	svc := New(Deps{TenantApps: repo, AppSync: notes, HashSecret: testHasher})

	out, err := svc.CreateApp(context.Background(), CreateAppInput{
		Name: "应用一", Reason: "验收：建应用应触发同步",
	})
	if err != nil {
		t.Fatalf("建应用失败: %v", err)
	}

	codes := notes.got()
	if len(codes) != 1 {
		t.Fatalf("应通知一次同步，实际 %d 次（%v）", len(codes), codes)
	}
	if codes[0] != out.App.AppCode {
		t.Fatalf("通知的 app_code 应为新建应用的 %q，实际 %q", out.App.AppCode, codes[0])
	}
}

// TestCreateAppWithoutNotifier 验证没有用户中心时建应用照常成功。
//
// stub 模式、或运维显式关闭同步时 AppSync 为 nil。这条路径必须安静地通过：
// 报错会让演示环境无法启动，而演示环境恰恰最常跑 stub。
func TestCreateAppWithoutNotifier(t *testing.T) {
	svc := New(Deps{TenantApps: newFakeAppRepo(), HashSecret: testHasher})

	if _, err := svc.CreateApp(context.Background(), CreateAppInput{
		Name: "应用二", Reason: "验收：无用户中心时建应用",
	}); err != nil {
		t.Fatalf("没有同步能力时建应用不应失败: %v", err)
	}
}

// TestUpdateAppNotifiesSync 验证启停/改名同样会触发同步。
//
// 只改本地而不告知对端时，对端会继续认为该应用可用——"本地明明停了"
// 与"对端还能用"会同时成立，排查时很难相信任何一侧。
func TestUpdateAppNotifiesSync(t *testing.T) {
	repo := newFakeAppRepo()
	notes := &fakeNotifier{}
	svc := New(Deps{TenantApps: repo, AppSync: notes, HashSecret: testHasher})

	created, err := svc.CreateApp(context.Background(), CreateAppInput{
		Name: "应用三", Reason: "验收：先建一个应用",
	})
	if err != nil {
		t.Fatalf("建应用失败: %v", err)
	}

	disabled := int16(0)
	if _, err := svc.UpdateApp(context.Background(), created.App.ID, UpdateAppInput{
		Status: &disabled, Reason: "验收：停用应触发同步",
	}); err != nil {
		t.Fatalf("停用失败: %v", err)
	}

	codes := notes.got()
	if len(codes) != 2 {
		t.Fatalf("建 + 停用应各通知一次，实际 %v", codes)
	}
	if codes[1] != created.App.AppCode {
		t.Fatalf("停用通知的 app_code 不符：%q", codes[1])
	}
}

// TestFailedCreateDoesNotNotify 验证失败时不会去同步一个不存在的应用。
//
// 否则对端会收到一个本地并不存在的租户，而它的登录请求永远不会来；
// 更糟的是这类"幽灵租户"会被当成真实应用去做容量与限流规划。
func TestFailedCreateDoesNotNotify(t *testing.T) {
	repo := newFakeAppRepo()
	repo.failUpsert = errs.New(errs.CodeInternal, "库不可用")
	notes := &fakeNotifier{}
	svc := New(Deps{TenantApps: repo, AppSync: notes, HashSecret: testHasher})

	if _, err := svc.CreateApp(context.Background(), CreateAppInput{
		Name: "应用四", Reason: "验收：建应用失败不应同步",
	}); err == nil {
		t.Fatal("写库失败时应返回错误")
	}
	if codes := notes.got(); len(codes) != 0 {
		t.Fatalf("失败时不应通知同步，实际 %v", codes)
	}
}

// TestAppViewCarriesSyncState 验证同步状态会出现在管理端视图里。
//
// 不展示的话，运维要等"这个应用的登录全部失败"才知道它没注册上——
// 而那时已经把故障暴露给业务方了。
func TestAppViewCarriesSyncState(t *testing.T) {
	at := time.Unix(1_700_000_500, 0).UTC()
	view := toAppView(&tenant.Application{
		ID: 7, AppCode: "app_x", Name: "应用X", Status: 1,
		AccountSync: tenant.AccountSyncState{SyncedAt: &at, LastError: ""},
	})
	if view.AccountSync.SyncedAt == nil || !view.AccountSync.SyncedAt.Equal(at) {
		t.Fatalf("同步时间未透出：%+v", view.AccountSync)
	}
}
