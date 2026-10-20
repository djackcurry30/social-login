package auditexport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/audit"
)

type fakeQuery struct {
	batches [][]audit.Record
	err     error
}

func (f *fakeQuery) List(context.Context, audit.Filter) ([]audit.Record, int64, error) {
	return nil, 0, nil
}

func (f *fakeQuery) ListAdmin(context.Context, audit.AdminFilter) ([]audit.AdminRecord, int64, error) {
	return nil, 0, nil
}

func (f *fakeQuery) Stream(_ context.Context, _ audit.Filter, _ int, fn func([]audit.Record) error) error {
	for _, b := range f.batches {
		if err := fn(b); err != nil {
			return err
		}
	}
	return f.err
}

type fakeStore struct {
	claimed   []*audit.ExportTask
	succeeded struct {
		id    string
		rows  int64
		size  int64
		path  string
		ttl   time.Time
		calls int
	}
	failed struct {
		id    string
		code  string
		msg   string
		calls int
	}
	purged []*audit.ExportTask
}

func (f *fakeStore) Create(context.Context, *audit.ExportTask) error { return nil }

func (f *fakeStore) Get(context.Context, string) (*audit.ExportTask, error) {
	return nil, audit.ErrExportNotFound
}

func (f *fakeStore) ListBySubject(context.Context, string, int) ([]*audit.ExportTask, error) {
	return nil, nil
}

func (f *fakeStore) ClaimPending(context.Context) (*audit.ExportTask, error) {
	if len(f.claimed) == 0 {
		return nil, nil
	}
	t := f.claimed[0]
	f.claimed = f.claimed[1:]
	return t, nil
}

func (f *fakeStore) MarkSucceeded(_ context.Context, id string, rows, size int64, path string, ttl time.Time) error {
	f.succeeded.id = id
	f.succeeded.rows = rows
	f.succeeded.size = size
	f.succeeded.path = path
	f.succeeded.ttl = ttl
	f.succeeded.calls++
	return nil
}

func (f *fakeStore) MarkFailed(_ context.Context, id, code, msg string) error {
	f.failed.id = id
	f.failed.code = code
	f.failed.msg = msg
	f.failed.calls++
	return nil
}

func (f *fakeStore) PurgeExpired(context.Context, time.Time, int) ([]*audit.ExportTask, error) {
	return f.purged, nil
}

func newWorker(t *testing.T, q *fakeQuery, s *fakeStore) *Service {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig(dir)
	cfg.MaxPerRound = 5
	return New(q, s, cfg, nil)
}

func sampleRecord(id int64, action string) audit.Record {
	return audit.Record{
		ID:             id,
		AppID:          3,
		ExternalUserID: "u-1",
		Platform:       "wechat",
		Action:         action,
		Result:         audit.ResultSuccess,
		TraceID:        "trace-1",
		Detail:         map[string]any{"k": "v"},
		CreatedAt:      time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC),
	}
}

func TestExportOneWritesBOMHeaderAndRows(t *testing.T) {
	q := &fakeQuery{batches: [][]audit.Record{
		{sampleRecord(1, "login"), sampleRecord(2, "bind")},
	}}
	s := &fakeStore{}
	w := newWorker(t, q, s)

	task := &audit.ExportTask{ID: "t1", SubjectID: "admin:1", Status: audit.ExportRunning}
	if err := w.ExportOne(context.Background(), task); err != nil {
		t.Fatalf("导出失败: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(w.cfg.Dir, "audit-t1.csv"))
	if err != nil {
		t.Fatalf("导出文件不存在: %v", err)
	}
	// BOM 必须存在：没有它 Excel 打开中文就是乱码，这是导出给运营看的场景里
	// 最常见的坑，所以写成硬断言。
	if len(raw) < 3 || raw[0] != 0xEF || raw[1] != 0xBB || raw[2] != 0xBF {
		t.Fatal("缺少 UTF-8 BOM")
	}
	text := string(raw[3:])
	if !strings.HasPrefix(text, "id,created_at,app_id,action") {
		t.Fatalf("表头不符: %q", strings.SplitN(text, "\n", 2)[0])
	}
	if n := strings.Count(text, "\n"); n != 3 { // 表头 + 2 行
		t.Fatalf("行数不符，期望 3 行，实际 %d: %q", n, text)
	}
	if !strings.Contains(text, "wechat") || !strings.Contains(text, `"{""k"":""v""}"`) &&
		!strings.Contains(text, `{"k":"v"}`) {
		t.Fatalf("detail / platform 未正确写出: %q", text)
	}

	if s.succeeded.calls != 1 || s.succeeded.rows != 2 {
		t.Fatalf("应回写成功且 rows=2，实际 %+v", s.succeeded)
	}
	if s.succeeded.path != "audit-t1.csv" {
		t.Fatalf("只应存文件名（下载时再拼目录），实际=%s", s.succeeded.path)
	}
	if s.succeeded.ttl.IsZero() {
		t.Fatal("必须写入过期时间，否则文件永不清理")
	}
}

func TestExportOneMarksFailedAndRemovesFile(t *testing.T) {
	q := &fakeQuery{err: errors.New("db down")}
	s := &fakeStore{}
	w := newWorker(t, q, s)

	task := &audit.ExportTask{ID: "t2", Status: audit.ExportRunning}
	if err := w.ExportOne(context.Background(), task); err == nil {
		t.Fatal("数据库失败应返回错误")
	}
	if s.failed.calls != 1 || s.failed.id != "t2" {
		t.Fatalf("必须回写失败状态，实际 %+v", s.failed)
	}
	// 半成品文件必须删掉：留着会让失败的导出在目录里看起来像成功的。
	if _, err := os.Stat(filepath.Join(w.cfg.Dir, "audit-t2.csv")); !os.IsNotExist(err) {
		t.Fatal("失败后不应留下文件")
	}
}

func TestExportOneRefusesToOverwrite(t *testing.T) {
	w := newWorker(t, &fakeQuery{}, &fakeStore{})
	// 预置同名文件：task_id 随机且唯一，同名只可能是逻辑异常或人为放文件，
	// 此时静默覆盖等于毁掉别人已经导出的数据。
	path := filepath.Join(w.cfg.Dir, "audit-dup.csv")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("预置文件失败: %v", err)
	}
	task := &audit.ExportTask{ID: "dup", Status: audit.ExportRunning}
	if err := w.ExportOne(context.Background(), task); err == nil {
		t.Fatal("同名文件存在时必须失败")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "existing" {
		t.Fatal("不得覆盖已有文件")
	}
}

func TestRunOnceProcessesQueueUntilEmpty(t *testing.T) {
	q := &fakeQuery{batches: [][]audit.Record{{sampleRecord(1, "login")}}}
	s := &fakeStore{claimed: []*audit.ExportTask{
		{ID: "a", Status: audit.ExportRunning},
		{ID: "b", Status: audit.ExportRunning},
	}}
	w := newWorker(t, q, s)
	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if n != 2 || s.succeeded.calls != 2 {
		t.Fatalf("应处理 2 个任务，实际 done=%d calls=%d", n, s.succeeded.calls)
	}
}

// TestRunWithoutDirReturnsImmediately：未配置目录时 worker 必须立刻退出，
// 而不是空转。空转会让"提交了却永远 pending"变成查不出原因的谜案。
func TestRunWithoutDirReturnsImmediately(t *testing.T) {
	w := New(&fakeQuery{}, &fakeStore{}, Config{Dir: ""}, nil)
	done := make(chan struct{})
	go func() {
		w.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("缺少目录时 Run 应立即返回")
	}
}

func TestPurgeOnceRemovesFiles(t *testing.T) {
	dir := t.TempDir()
	q := &fakeQuery{}
	s := &fakeStore{}
	w := New(q, s, DefaultConfig(dir), nil)

	name := "audit-old.csv"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatalf("预置失败: %v", err)
	}
	s.purged = []*audit.ExportTask{{ID: "old", FilePath: name}}
	w.purgeOnce(context.Background())

	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatal("过期文件应被删除")
	}
}
