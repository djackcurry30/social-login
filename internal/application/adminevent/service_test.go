package adminevent

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

type fakeStore struct {
	item      *event.Event
	restored  int64
	discarded int64
}

func (f *fakeStore) Append(context.Context, *event.Event) error { return nil }
func (f *fakeStore) ClaimDue(context.Context, int, time.Duration) ([]*event.Event, error) {
	return nil, nil
}
func (f *fakeStore) MarkSent(context.Context, int64) error { return nil }
func (f *fakeStore) MarkRetry(context.Context, int64, int, time.Time, string) error {
	return nil
}
func (f *fakeStore) MarkDead(context.Context, int64, int, string) error { return nil }
func (f *fakeStore) MarkSkipped(context.Context, int64, string) error   { return nil }
func (f *fakeStore) Get(context.Context, int64) (*event.Event, error)   { return f.item, nil }
func (f *fakeStore) List(context.Context, event.Filter) ([]*event.Event, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) Restore(_ context.Context, id int64) error {
	f.restored = id
	return nil
}
func (f *fakeStore) Discard(_ context.Context, id int64, _ string) error {
	f.discarded = id
	return nil
}

func svcWith(status event.Status) (*Service, *fakeStore) {
	st := &fakeStore{item: &event.Event{ID: 9, EventID: "e9", Status: status, Attempts: 3}}
	return New(Deps{Events: st}), st
}

// TestRetryRejectsSent 是一条安全边界：已投递成功的事件不能重投。
// 重投会让业务方按 event_id 去重后仍然收到重复处理之外的效果——
// 更重要的是它违反"同一 event_id 不重复投递成功"的承诺。
func TestRetryRejectsSent(t *testing.T) {
	svc, st := svcWith(event.StatusSent)
	err := svc.Retry(context.Background(), 9, nil, "")
	if err == nil {
		t.Fatal("sent 状态必须拒绝重投")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际=%v", errs.CodeOf(err))
	}
	if st.restored != 0 {
		t.Fatal("被拒绝时不得产生状态变更")
	}
}

// TestRetryRejectsPending：pending 本来就会被投递，重投只会造成重复。
func TestRetryRejectsPending(t *testing.T) {
	svc, _ := svcWith(event.StatusPending)
	if err := svc.Retry(context.Background(), 9, nil, ""); err == nil {
		t.Fatal("pending 状态必须拒绝重投")
	}
}

func TestRetryAllowsDead(t *testing.T) {
	svc, st := svcWith(event.StatusDead)
	if err := svc.Retry(context.Background(), 9, nil, "重投死信"); err != nil {
		t.Fatalf("死信应允许重投: %v", err)
	}
	if st.restored != 9 {
		t.Fatalf("应调用 Restore(9)，实际=%v", st.restored)
	}
}

func TestRetryAllowsSkipped(t *testing.T) {
	svc, st := svcWith(event.StatusSkipped)
	if err := svc.Retry(context.Background(), 9, nil, ""); err != nil {
		t.Fatalf("skipped 应允许重投: %v", err)
	}
	if st.restored != 9 {
		t.Fatal("应调用 Restore")
	}
}

// TestDiscardRequiresReason：丢弃是销毁外发事实，必须有可追溯的理由。
func TestDiscardRequiresReason(t *testing.T) {
	svc, st := svcWith(event.StatusDead)
	err := svc.Discard(context.Background(), 9, DiscardInput{Reason: "x"})
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际=%v", errs.CodeOf(err))
	}
	if st.discarded != 0 {
		t.Fatal("被拒绝时不得丢弃")
	}
}

func TestDiscardRejectsSent(t *testing.T) {
	svc, _ := svcWith(event.StatusSent)
	if err := svc.Discard(context.Background(), 9, DiscardInput{Reason: "人工确认无需投递"}); err == nil {
		t.Fatal("已投递成功的事件不能丢弃")
	}
}

func TestListRejectsInvalidStatus(t *testing.T) {
	svc, _ := svcWith(event.StatusDead)
	_, err := svc.List(context.Background(), ListInput{Status: "whatever"})
	if err == nil {
		t.Fatal("非法 status 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际=%v", errs.CodeOf(err))
	}
}

func TestListRejectsBadTimeRange(t *testing.T) {
	svc, _ := svcWith(event.StatusDead)
	if _, err := svc.List(context.Background(), ListInput{From: "2026-01-01"}); err == nil {
		t.Fatal("非 RFC3339 时间必须拒绝")
	}
}
