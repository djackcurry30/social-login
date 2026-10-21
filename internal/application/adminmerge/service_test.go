package adminmerge

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

type fakeStore struct {
	op       *mergex.Operation
	rows     []*mergex.Operation
	getErr   error
	marked   int
	deadID   int64
	deadMsg  string
	lastList mergex.Filter
}

func (f *fakeStore) Create(context.Context, *mergex.Operation) (*mergex.Operation, bool, error) {
	return nil, false, nil
}

func (f *fakeStore) Get(context.Context, int64) (*mergex.Operation, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.op, nil
}

func (f *fakeStore) List(_ context.Context, flt mergex.Filter) ([]*mergex.Operation, int64, error) {
	f.lastList = flt
	return f.rows, int64(len(f.rows)), nil
}

func (f *fakeStore) MarkDone(context.Context, int64, map[string]any) error { return nil }

func (f *fakeStore) MarkFailed(context.Context, int64, map[string]any, string) error {
	f.marked++
	return nil
}

func (f *fakeStore) MarkDead(_ context.Context, id int64, msg string) error {
	f.marked++
	f.deadID = id
	f.deadMsg = msg
	return nil
}

func (f *fakeStore) MarkRejected(context.Context, int64, string) error { return nil }

func (f *fakeStore) ListDue(context.Context, int) ([]*mergex.Operation, error) { return nil, nil }

func newSvc(op *mergex.Operation) (*Service, *fakeStore) {
	st := &fakeStore{op: op}
	return New(Deps{Ops: st}), st
}

func adminPrincipal() *admin.Principal {
	return &admin.Principal{User: &admin.User{ID: 1, Role: admin.RoleOperator}}
}

func TestListRejectsUnknownStatus(t *testing.T) {
	svc, _ := newSvc(nil)
	// status 是枚举：随便传会让"按状态筛选"静默返回空集。
	_, err := svc.List(context.Background(), ListInput{Status: "MERGED"})
	if err == nil {
		t.Fatal("非法 status 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestListPassesFilters(t *testing.T) {
	svc, st := newSvc(nil)
	st.rows = []*mergex.Operation{{ID: 3, AppID: 1, Status: mergex.StatusFailed,
		CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	out, err := svc.List(context.Background(), ListInput{
		AppID: 1, Status: mergex.StatusFailed, UserID: "u-1", Page: 2, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if st.lastList.AppID != 1 || st.lastList.UserID != "u-1" || st.lastList.Page != 2 {
		t.Fatalf("过滤条件未透传: %+v", st.lastList)
	}
	if out.Total != 1 || len(out.Items) != 1 || out.Page != 2 {
		t.Fatalf("出参不符: %+v", out)
	}
}

func TestGetMapsNotFound(t *testing.T) {
	svc, st := newSvc(nil)
	st.getErr = mergex.ErrNotFound
	_, err := svc.Get(context.Background(), 9)
	// 裸领域错误会被 HTTP 层折算成 500，必须归一化。
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("应为 404，实际 %v", errs.CodeOf(err))
	}
}

func TestRetryRequiresReason(t *testing.T) {
	svc, st := newSvc(&mergex.Operation{ID: 1, Status: mergex.StatusFailed})
	err := svc.Retry(context.Background(), 1, RetryInput{Reason: "x", Principal: adminPrincipal()})
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if st.marked != 0 {
		t.Fatal("校验失败不得改变状态")
	}
}

func TestRetryRejectsDone(t *testing.T) {
	svc, st := newSvc(&mergex.Operation{ID: 1, Status: mergex.StatusDone})
	err := svc.Retry(context.Background(), 1, RetryInput{Reason: "重试一次", Principal: adminPrincipal()})
	if err == nil {
		t.Fatal("已完成的合并不能重试")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
	if st.marked != 0 {
		t.Fatal("被拒绝时不得改变状态")
	}
}

// TestRetryRequeuesRejected：rejected 允许重试（运维可能刚把策略从 manual 改成 auto）。
func TestRetryRequeuesRejected(t *testing.T) {
	svc, st := newSvc(&mergex.Operation{ID: 7, Status: mergex.StatusRejected})
	// Merger 为 nil 时会在重新入队后报"未装配"，这里只验证前置的重新入队动作。
	_ = svc.Retry(context.Background(), 7, RetryInput{Reason: "策略已调整", Principal: adminPrincipal()})
	if st.marked != 1 {
		t.Fatalf("rejected 应先退回 pending，实际 marked=%d", st.marked)
	}
}

func TestResolveMarksDeadNotDone(t *testing.T) {
	svc, st := newSvc(&mergex.Operation{ID: 5, Status: mergex.StatusFailed})
	err := svc.Resolve(context.Background(), 5, ResolveInput{Reason: "已人工核对", Principal: adminPrincipal()})
	if err != nil {
		t.Fatalf("收尾失败: %v", err)
	}
	// 必须置 dead 而不是 done：done 会被下游当成"合并成功"，那是谎报。
	if st.deadID != 5 || st.marked != 1 {
		t.Fatalf("应标记 dead，实际 id=%d marked=%d", st.deadID, st.marked)
	}
	if st.deadMsg == "" {
		t.Fatal("应记录人工处理理由")
	}
}

func TestResolveRejectsDone(t *testing.T) {
	svc, st := newSvc(&mergex.Operation{ID: 5, Status: mergex.StatusDone})
	if err := svc.Resolve(context.Background(), 5, ResolveInput{
		Reason: "已人工核对", Principal: adminPrincipal(),
	}); err == nil {
		t.Fatal("已完成的合并无需收尾")
	}
	if st.marked != 0 {
		t.Fatal("不得改变状态")
	}
}

func TestResolveRequiresReason(t *testing.T) {
	svc, _ := newSvc(&mergex.Operation{ID: 5, Status: mergex.StatusFailed})
	err := svc.Resolve(context.Background(), 5, ResolveInput{Reason: "ok", Principal: adminPrincipal()})
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
}
