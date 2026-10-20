package adminaudit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- fakes ---

type fakeQuery struct {
	lastFilter audit.Filter
	rows       []audit.Record
	adminRows  []audit.AdminRecord
	streamed   [][]audit.Record
	streamErr  error
	listErr    error
}

func (f *fakeQuery) List(_ context.Context, flt audit.Filter) ([]audit.Record, int64, error) {
	f.lastFilter = flt
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.rows, int64(len(f.rows)), nil
}

func (f *fakeQuery) ListAdmin(_ context.Context, _ audit.AdminFilter) ([]audit.AdminRecord, int64, error) {
	return f.adminRows, int64(len(f.adminRows)), nil
}

func (f *fakeQuery) Stream(_ context.Context, _ audit.Filter, _ int, fn func([]audit.Record) error) error {
	for _, b := range f.streamed {
		if err := fn(b); err != nil {
			return err
		}
	}
	return f.streamErr
}

type fakeExports struct {
	created *audit.ExportTask
	item    *audit.ExportTask
	bySubj  []*audit.ExportTask
	getErr  error
}

func (f *fakeExports) Create(_ context.Context, t *audit.ExportTask) error {
	f.created = t
	return nil
}

func (f *fakeExports) Get(_ context.Context, _ string) (*audit.ExportTask, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.item, nil
}

func (f *fakeExports) ListBySubject(context.Context, string, int) ([]*audit.ExportTask, error) {
	return f.bySubj, nil
}

func (f *fakeExports) ClaimPending(context.Context) (*audit.ExportTask, error) { return nil, nil }

func (f *fakeExports) MarkSucceeded(context.Context, string, int64, int64, string, time.Time) error {
	return nil
}

func (f *fakeExports) MarkFailed(context.Context, string, string, string) error { return nil }

func (f *fakeExports) PurgeExpired(context.Context, time.Time, int) ([]*audit.ExportTask, error) {
	return nil, nil
}

func newSvc() (*Service, *fakeQuery, *fakeExports) {
	q := &fakeQuery{}
	e := &fakeExports{}
	return New(Deps{Query: q, Exports: e, ExportDir: "/tmp/exports"}), q, e
}

func viewer() *admin.Principal {
	return &admin.Principal{User: &admin.User{ID: 7, Role: admin.RoleViewer}}
}

// --- 业务审计查询 ---

func TestListRejectsInvalidResult(t *testing.T) {
	svc, _, _ := newSvc()
	// result 是枚举：让它随便传会让"按结果筛选"返回空集却查不出原因。
	_, err := svc.List(context.Background(), ListInput{Result: "SUCCESS"})
	if err == nil {
		t.Fatal("非法 result 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际=%v", errs.CodeOf(err))
	}
}

func TestListRejectsBadTime(t *testing.T) {
	svc, _, _ := newSvc()
	if _, err := svc.List(context.Background(), ListInput{From: "2026-10-20"}); err == nil {
		t.Fatal("非 RFC3339 时间必须拒绝")
	}
}

func TestListRejectsInvertedRange(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.List(context.Background(), ListInput{
		From: "2026-10-21T00:00:00Z",
		To:   "2026-10-20T00:00:00Z",
	})
	if err == nil {
		t.Fatal("to 早于 from 必须拒绝")
	}
}

func TestListPassesFiltersThrough(t *testing.T) {
	svc, q, _ := newSvc()
	q.rows = []audit.Record{{ID: 1, AppID: 3, Action: "login", Result: "success"}}
	out, err := svc.List(context.Background(), ListInput{
		AppID: 3, Action: "login", TraceID: "t-1", Page: 2, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if q.lastFilter.AppID != 3 || q.lastFilter.Action != "login" || q.lastFilter.TraceID != "t-1" {
		t.Fatalf("过滤条件未透传: %+v", q.lastFilter)
	}
	if out.Total != 1 || len(out.Items) != 1 || out.Page != 2 {
		t.Fatalf("出参不符: %+v", out)
	}
}

// --- 导出提交 ---

func TestSubmitExportCreatesPendingTask(t *testing.T) {
	svc, _, e := newSvc()
	out, err := svc.SubmitExport(context.Background(), ExportInput{
		AppID: 1, Action: "login", Principal: viewer(),
	})
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	if e.created == nil {
		t.Fatal("必须落库一条任务")
	}
	if e.created.Status != audit.ExportPending {
		t.Fatalf("初始状态应为 pending，实际=%s", e.created.Status)
	}
	if e.created.SubjectID != "admin:7" {
		t.Fatalf("subject 应绑定提交人，实际=%s", e.created.SubjectID)
	}
	// task_id 必须足够长且随机：短 ID 可枚举会让"猜别人的导出任务"成立。
	if len(out.TaskID) != 32 {
		t.Fatalf("task_id 应为 16 字节 hex（32 字符），实际长度=%d", len(out.TaskID))
	}
	if out.Status != audit.ExportPending || out.DownloadPath != "" {
		t.Fatalf("未完成的任务不应给出下载地址: %+v", out)
	}
}

func TestSubmitExportRejectsBadResult(t *testing.T) {
	svc, _, e := newSvc()
	if _, err := svc.SubmitExport(context.Background(), ExportInput{Result: "ok"}); err == nil {
		t.Fatal("非法 result 必须拒绝")
	}
	if e.created != nil {
		t.Fatal("校验失败不得落库")
	}
}

// --- 导出查询与归属 ---

func TestGetExportHidesOtherSubjectsTask(t *testing.T) {
	svc, _, e := newSvc()
	e.item = &audit.ExportTask{ID: "x", SubjectID: "admin:99", Status: audit.ExportPending}

	p := viewer() // admin:7
	_, err := svc.GetExport(context.Background(), "x", p)
	if err == nil {
		t.Fatal("他人任务必须拒绝访问")
	}
	// 关键：不能返回 403（那等于确认"这个 task_id 存在"）。
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("应伪装成 404，实际=%v", errs.CodeOf(err))
	}
}

func TestGetExportAllowsOwner(t *testing.T) {
	svc, _, e := newSvc()
	e.item = &audit.ExportTask{ID: "x", SubjectID: "admin:7", Status: audit.ExportSucceeded,
		RowCount: 12, FileSize: 345}
	out, err := svc.GetExport(context.Background(), "x", viewer())
	if err != nil {
		t.Fatalf("本人任务应可读: %v", err)
	}
	if out.RowCount != 12 || out.DownloadPath == "" {
		t.Fatalf("成功任务应带下载地址: %+v", out)
	}
}

func TestGetExportSuperAdminSeesAll(t *testing.T) {
	svc, _, e := newSvc()
	e.item = &audit.ExportTask{ID: "x", SubjectID: "admin:99", Status: audit.ExportSucceeded}
	p := &admin.Principal{User: &admin.User{ID: 1, Role: admin.RoleSuperAdmin}}
	if _, err := svc.GetExport(context.Background(), "x", p); err != nil {
		t.Fatalf("super_admin 应可查看任意任务: %v", err)
	}
}

func TestGetExportMapsNotFound(t *testing.T) {
	svc, _, e := newSvc()
	e.getErr = audit.ErrExportNotFound
	_, err := svc.GetExport(context.Background(), "nope", viewer())
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("领域错误应归一化为 404，实际=%v", errs.CodeOf(err))
	}
}

// --- 下载 ---

func TestDownloadRejectsUnfinished(t *testing.T) {
	svc, _, e := newSvc()
	e.item = &audit.ExportTask{ID: "x", SubjectID: "admin:7", Status: audit.ExportPending}
	_, err := svc.PrepareDownload(context.Background(), "x", viewer())
	if err == nil {
		t.Fatal("未完成的导出不得下载")
	}
	// 用 409 而不是 500：这是"还没好"，不是"服务坏了"。
	if errs.CodeOf(err) != errs.CodeAdminConflict {
		t.Fatalf("应为 ADMIN.CONFLICT，实际=%v", errs.CodeOf(err))
	}
}

func TestDownloadRejectsExpired(t *testing.T) {
	svc, _, e := newSvc()
	past := time.Now().Add(-time.Hour)
	e.item = &audit.ExportTask{ID: "x", SubjectID: "admin:7", Status: audit.ExportSucceeded,
		FilePath: "audit-x.csv", ExpiresAt: &past}
	if _, err := svc.PrepareDownload(context.Background(), "x", viewer()); err == nil {
		t.Fatal("过期文件不得下载")
	}
}

func TestDownloadUsesExportDirAndStripsTraversal(t *testing.T) {
	svc, _, e := newSvc()
	e.item = &audit.ExportTask{ID: "x", SubjectID: "admin:7", Status: audit.ExportSucceeded,
		FilePath: "../../etc/passwd"}
	target, err := svc.PrepareDownload(context.Background(), "x", viewer())
	if err != nil {
		t.Fatalf("下载准备失败: %v", err)
	}
	// 即便历史数据里出现穿越路径，也只能落在导出目录下。
	if want := filepath.Join("/tmp/exports", "passwd"); target.Path != want {
		t.Fatalf("路径穿越未被收敛: %s（期望 %s）", target.Path, want)
	}
}

// --- 列表 ---

func TestListExportsOnlyReturnsOwn(t *testing.T) {
	svc, _, e := newSvc()
	e.bySubj = []*audit.ExportTask{
		{ID: "a", SubjectID: "admin:7", Status: audit.ExportSucceeded},
	}
	out, err := svc.ListExports(context.Background(), viewer(), 10)
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(out) != 1 || out[0].TaskID != "a" {
		t.Fatalf("出参不符: %+v", out)
	}
}
