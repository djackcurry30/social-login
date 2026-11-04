package adminapproval

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/approval"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// 这组用例守的是双人复核的全部安全属性：
// 自批、重复使用、过期、张冠李戴（用 A 的单子做 B）、以及"批准前的单子不能执行"。

type fakeStore struct {
	item *approval.Approval
}

func (f *fakeStore) Create(_ context.Context, a *approval.Approval) error {
	if f.item == nil {
		cp := *a
		cp.ID = 7
		a.ID = 7 // 与真实仓储一致：插入后回填自增 id
		f.item = &cp
	}
	return nil
}

func (f *fakeStore) Get(context.Context, int64) (*approval.Approval, error) {
	if f.item == nil {
		return nil, approval.ErrNotFound
	}
	return f.item, nil
}

func (f *fakeStore) List(context.Context, approval.Filter) ([]*approval.Approval, error) {
	if f.item == nil {
		return nil, nil
	}
	return []*approval.Approval{f.item}, nil
}

func (f *fakeStore) Approve(_ context.Context, id, approverID int64, at time.Time) error {
	return f.decide(id, approverID, at, approval.StatusApproved)
}

func (f *fakeStore) Reject(_ context.Context, id, approverID int64, at time.Time) error {
	return f.decide(id, approverID, at, approval.StatusRejected)
}

func (f *fakeStore) decide(id, approverID int64, at time.Time, to approval.Status) error {
	if f.item == nil || f.item.ID != id {
		return approval.ErrNotFound
	}
	if f.item.RequestedBy == approverID {
		return approval.ErrSelfApprove
	}
	if !at.Before(f.item.ExpiresAt) {
		return approval.ErrExpired
	}
	if f.item.Status != approval.StatusPending {
		return approval.ErrNotPending
	}
	f.item.Status = to
	f.item.ApprovedBy = &approverID
	f.item.ApprovedAt = &at
	return nil
}

func (f *fakeStore) Consume(_ context.Context, id int64, action string, appID *int64, at time.Time) error {
	if f.item == nil || f.item.ID != id {
		return approval.ErrNotFound
	}
	if f.item.Status != approval.StatusApproved || f.item.ConsumedAt != nil {
		return approval.ErrNotApproved
	}
	if !at.Before(f.item.ExpiresAt) {
		return approval.ErrExpired
	}
	if f.item.Action != action {
		return approval.ErrMismatch
	}
	if (appID == nil) != (f.item.AppID == nil) ||
		(appID != nil && *appID != *f.item.AppID) {
		return approval.ErrMismatch
	}
	f.item.Status = approval.StatusConsumed
	f.item.ConsumedAt = &at
	return nil
}

func newSvc(now time.Time) (*Service, *fakeStore) {
	st := &fakeStore{}
	return New(Deps{
		Store: st,
		Now:   func() time.Time { return now },
		TTL:   30 * time.Minute,
	}), st
}

func TestCreateRequiresReason(t *testing.T) {
	svc, _ := newSvc(time.Now())
	_, err := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionKeyRotate, Reason: "x", RequesterID: 1,
	})
	if err == nil {
		t.Fatal("理由过短必须拒绝")
	}
	if e := errs.From(err); e == nil || e.Code != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 REASON_REQUIRED，实际 %v", err)
	}
}

func TestSelfApproveRejected(t *testing.T) {
	now := time.Now()
	svc, _ := newSvc(now)
	a, err := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionKeyRotate, Reason: "轮换签名密钥", RequesterID: 1,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if _, err := svc.Approve(context.Background(), a.ID, 1); err == nil {
		t.Fatal("不能批准自己的申请")
	}
}

func TestApproveThenConsumeOnce(t *testing.T) {
	now := time.Now()
	svc, _ := newSvc(now)
	a, _ := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionKeyRotate, Reason: "轮换签名密钥", RequesterID: 1,
	})
	if _, err := svc.Approve(context.Background(), a.ID, 2); err != nil {
		t.Fatalf("他人批准应成功: %v", err)
	}
	if err := svc.Consume(context.Background(), a.ID, approval.ActionKeyRotate, nil); err != nil {
		t.Fatalf("首次消费应成功: %v", err)
	}
	// 第二次：一次性。
	if err := svc.Consume(context.Background(), a.ID, approval.ActionKeyRotate, nil); err == nil {
		t.Fatal("审批单不能重复使用")
	}
}

func TestConsumeBeforeApproveRejected(t *testing.T) {
	now := time.Now()
	svc, _ := newSvc(now)
	a, _ := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionKeyRotate, Reason: "轮换签名密钥", RequesterID: 1,
	})
	err := svc.Consume(context.Background(), a.ID, approval.ActionKeyRotate, nil)
	if err == nil {
		t.Fatal("未批准的单子不能执行")
	}
	if e := errs.From(err); e == nil || e.Code != errs.CodeAdminApprovalRequired {
		t.Fatalf("应为 APPROVAL_REQUIRED，实际 %v", err)
	}
}

func TestConsumeRejectsActionMismatch(t *testing.T) {
	now := time.Now()
	svc, _ := newSvc(now)
	appID := int64(3)
	a, _ := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionAppRotateSecret, AppID: &appID,
		Reason: "应用密钥疑似泄漏", RequesterID: 1,
	})
	if _, err := svc.Approve(context.Background(), a.ID, 2); err != nil {
		t.Fatalf("批准失败: %v", err)
	}
	// 用"应用密钥轮换"的单子去执行"签名密钥轮换"：必须拒绝。
	if err := svc.Consume(context.Background(), a.ID, approval.ActionKeyRotate, nil); err == nil {
		t.Fatal("动作不匹配必须拒绝")
	}
}

func TestConsumeRejectsAppMismatch(t *testing.T) {
	now := time.Now()
	svc, _ := newSvc(now)
	appID := int64(3)
	a, _ := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionAppRotateSecret, AppID: &appID,
		Reason: "应用密钥疑似泄漏", RequesterID: 1,
	})
	if _, err := svc.Approve(context.Background(), a.ID, 2); err != nil {
		t.Fatalf("批准失败: %v", err)
	}
	other := int64(4)
	if err := svc.Consume(context.Background(), a.ID, approval.ActionAppRotateSecret, &other); err == nil {
		t.Fatal("应用不匹配必须拒绝（批了 A 不能拿去操作 B）")
	}
}

func TestExpiredApprovalCannotBeConsumed(t *testing.T) {
	now := time.Now()
	st := &fakeStore{}
	svc := New(Deps{Store: st, Now: func() time.Time { return now }, TTL: time.Minute})
	a, _ := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionKeyRotate, Reason: "轮换签名密钥", RequesterID: 1,
	})
	if _, err := svc.Approve(context.Background(), a.ID, 2); err != nil {
		t.Fatalf("批准失败: %v", err)
	}
	// 时间推进到过期之后。
	later := now.Add(2 * time.Minute)
	svc2 := New(Deps{Store: st, Now: func() time.Time { return later }, TTL: time.Minute})
	if err := svc2.Consume(context.Background(), a.ID, approval.ActionKeyRotate, nil); err == nil {
		t.Fatal("过期单不能执行")
	}
}

func TestRejectPreventsConsume(t *testing.T) {
	now := time.Now()
	svc, _ := newSvc(now)
	a, _ := svc.Create(context.Background(), CreateInput{
		Action: approval.ActionKeyRotate, Reason: "轮换签名密钥", RequesterID: 1,
	})
	if _, err := svc.Reject(context.Background(), a.ID, 2); err != nil {
		t.Fatalf("驳回失败: %v", err)
	}
	if err := svc.Consume(context.Background(), a.ID, approval.ActionKeyRotate, nil); err == nil {
		t.Fatal("被驳回的单子不能执行")
	}
}

func TestHashOrEmptyRejectsRawSecrets(t *testing.T) {
	// 调用方误把原始参数（可能含凭证）传进来时，落库的必须是摘要，
	// 否则审批单自己变成新的泄漏点。
	got := hashOrEmpty("client_secret=abc123")
	if len(got) != 64 {
		t.Fatalf("应转成 sha256 摘要，实际 %q", got)
	}
	// 已经是合法摘要的保持原样。
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if hashOrEmpty(valid) != valid {
		t.Fatal("合法摘要不应被二次哈希")
	}
}

func TestIsSuperAdmin(t *testing.T) {
	if IsSuperAdmin(nil) {
		t.Fatal("nil 不是超管")
	}
	if !IsSuperAdmin(&adminUserSuper) {
		t.Fatal("super_admin 应判定为超管")
	}
	if IsSuperAdmin(&adminUserViewer) {
		t.Fatal("viewer 不是超管")
	}
}

var (
	adminUserSuper  = admin.User{ID: 1, Role: admin.RoleSuperAdmin}
	adminUserViewer = admin.User{ID: 2, Role: admin.RoleViewer}
)
