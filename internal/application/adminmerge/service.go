// Package adminmerge 是管理端"账号合并运维（D 组）"用例。
//
// 为什么必须与合并功能同批交付（架构 §13 第三期）：合并是高风险不可逆操作。
// 没有管理端兜底，一次"远端成功、本地失败"就只能靠连库改状态——
// 而那正是最容易改错的场景。
//
// 权限分层：读（merge:read）给 viewer，推进与收尾（merge:retry）给 operator。
// 后者会改变账号归属事实，必须与只读分开。
package adminmerge

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	"github.com/djackcurry30/social-login/internal/domain/admin"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Deps 是用例依赖。
type Deps struct {
	Ops        mergex.Store
	Merger     *appmerge.Service
	Impactor   mergex.Impactor
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
}

// Service 是 D 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service { return &Service{deps: d} }

// Item 是合并操作的对外视图。
type Item struct {
	ID             int64          `json:"id"`
	AppID          int64          `json:"app_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	TargetUserID   string         `json:"target_user_id"`
	SourceUserID   string         `json:"source_user_id"`
	IdentityID     int64          `json:"identity_id,omitempty"`
	Status         string         `json:"status"`
	Reason         string         `json:"reason,omitempty"`
	Attempts       int            `json:"attempts"`
	LastError      string         `json:"last_error,omitempty"`
	RemoteResult   map[string]any `json:"remote_result,omitempty"`
	CreatedAt      interface{}    `json:"created_at"`
	UpdatedAt      interface{}    `json:"updated_at"`
}

// ListInput 是 GET /admin/v1/merge-operations 的入参。
type ListInput struct {
	AppID    int64
	Status   string
	UserID   string
	From     string
	To       string
	Page     int
	PageSize int
}

// ListOutput 是列表出参。
type ListOutput struct {
	Items    []Item `json:"items"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// List 查询合并操作。
func (s *Service) List(ctx context.Context, in ListInput) (*ListOutput, error) {
	f := mergex.Filter{
		AppID:    in.AppID,
		Status:   in.Status,
		UserID:   in.UserID,
		Page:     in.Page,
		PageSize: in.PageSize,
	}
	if in.Status != "" && !validStatus(in.Status) {
		return nil, errs.Newf(errs.CodeInvalidRequest, "status 不合法: %s", in.Status)
	}
	if in.From != "" {
		t, err := parseTime(in.From)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "from 时间格式非法，应为 RFC3339")
		}
		f.From = &t
	}
	if in.To != "" {
		t, err := parseTime(in.To)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "to 时间格式非法，应为 RFC3339")
		}
		f.To = &t
	}

	rows, total, err := s.deps.Ops.List(ctx, f)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(rows))
	for _, op := range rows {
		items = append(items, toItem(op))
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &ListOutput{Items: items, Total: total, Page: page, PageSize: in.PageSize}, nil
}

// Get 查详情。
func (s *Service) Get(ctx context.Context, id int64) (*Item, error) {
	op, err := s.deps.Ops.Get(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	it := toItem(op)
	return &it, nil
}

// RetryInput 是人工重试的入参。
type RetryInput struct {
	Reason    string `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// Retry 人工重试。
//
// ⚠️ 复用原 IdempotencyKey（§15.4 D 组备注）：换新键等于让用户中心当成
// 一次新合并，可能重复迁移订单/资产。这里直接调 merge.Service.Resume，
// 它用的是操作记录里那一份键。
func (s *Service) Retry(ctx context.Context, id int64, in RetryInput) error {
	if len([]rune(in.Reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired, "人工重试合并必须填写 reason（≥4 字符）")
	}
	op, err := s.deps.Ops.Get(ctx, id)
	if err != nil {
		return mapErr(err)
	}
	switch op.Status {
	case mergex.StatusFailed, mergex.StatusPending, mergex.StatusRejected:
		// 允许 rejected 重试：运维可能刚把应用策略从 manual 改成 auto，
		// 此时"当时被拒绝"的合并值得再试一次。
	case mergex.StatusDone:
		return errs.New(errs.CodeInvalidRequest, "已完成的合并不能重试").
			WithDetail("status", op.Status)
	default:
		return errs.Newf(errs.CodeInvalidRequest, "状态为 %s 的合并不能重试", op.Status)
	}

	// rejected 的记录先退回 pending，Resume 才会处理它。
	if op.Status == mergex.StatusRejected {
		if err := s.deps.Ops.MarkFailed(ctx, id, nil, "人工重试：由管理端重新推进"); err != nil {
			return err
		}
	}

	if s.deps.Merger == nil {
		return errs.New(errs.CodeInternal, "合并服务未装配")
	}
	if err := s.deps.Merger.Resume(ctx, op); err != nil {
		s.writeAudit(ctx, in.Principal, "merge.retry", id, in.Reason, "error", err)
		return err
	}
	s.writeAudit(ctx, in.Principal, "merge.retry", id, in.Reason, "success", nil)

	// 补偿是同步执行的，重新读一次给出真实结果，避免"接口成功但状态没变"。
	latest, err := s.deps.Ops.Get(ctx, id)
	if err == nil && latest.Status != mergex.StatusDone {
		return errs.New(errs.CodeAdminConflict, "重试已执行，但合并仍未完成").
			WithDetail("status", latest.Status).
			WithDetail("last_error", latest.LastError)
	}
	return nil
}

// ResolveInput 是"人工核对已处理"的入参。
type ResolveInput struct {
	Reason    string `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// Resolve 标记人工已核对处理，停止补偿重试。
//
// 语义是"这条不再自动推进，且我们已经知道它处于什么状态"——因此置 dead
// 而不是 done。置 done 会被下游当成"合并成功"，那是谎报。
func (s *Service) Resolve(ctx context.Context, id int64, in ResolveInput) error {
	if len([]rune(in.Reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired, "标记人工处理必须填写 reason（≥4 字符）")
	}
	op, err := s.deps.Ops.Get(ctx, id)
	if err != nil {
		return mapErr(err)
	}
	if op.Status == mergex.StatusDone {
		return errs.New(errs.CodeInvalidRequest, "已完成的合并无需人工收尾")
	}
	if err := s.deps.Ops.MarkDead(ctx, id, "人工核对已处理："+in.Reason); err != nil {
		s.writeAudit(ctx, in.Principal, "merge.resolve", id, in.Reason, "error", err)
		return err
	}
	s.writeAudit(ctx, in.Principal, "merge.resolve", id, in.Reason, "success", nil)
	return nil
}

// Impact 返回影响面预估。
func (s *Service) Impact(ctx context.Context, id int64) (*mergex.Impact, error) {
	op, err := s.deps.Ops.Get(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if s.deps.Impactor == nil {
		return nil, errs.New(errs.CodeInternal, "影响面计算器未装配")
	}
	return s.deps.Impactor.Estimate(ctx, op.AppID, op.SourceUserID)
}

// --- helpers ---

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func toItem(op *mergex.Operation) Item {
	return Item{
		ID:             op.ID,
		AppID:          op.AppID,
		IdempotencyKey: op.IdempotencyKey,
		TargetUserID:   op.TargetUserID,
		SourceUserID:   op.SourceUserID,
		IdentityID:     op.IdentityID,
		Status:         op.Status,
		Reason:         op.Reason,
		Attempts:       op.Attempts,
		LastError:      op.LastError,
		RemoteResult:   op.RemoteResult,
		CreatedAt:      op.CreatedAt,
		UpdatedAt:      op.UpdatedAt,
	}
}

func validStatus(s string) bool {
	switch s {
	case mergex.StatusPending, mergex.StatusDone, mergex.StatusFailed,
		mergex.StatusDead, mergex.StatusRejected:
		return true
	}
	return false
}

// mapErr 把领域错误归一化成对外错误（裸 error 会被折算成 500）。
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if err == mergex.ErrNotFound {
		return errs.New(errs.CodeNotFound, "合并操作不存在")
	}
	return err
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action string, id int64,
	reason, result string, cause error,
) {
	if s.deps.AdminAudit == nil {
		return
	}
	e := &admin.AuditEvent{
		Action:     action,
		TargetType: "merge_operation",
		TargetID:   fmt.Sprintf("%d", id),
		Reason:     reason,
		Result:     result,
	}
	e.SubjectID = "admin:anonymous"
	if p != nil && p.User != nil {
		e.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	}
	if cause != nil {
		if ee, ok := errs.As(cause); ok {
			e.ErrorCode = string(ee.Code)
		} else {
			e.ErrorCode = string(errs.CodeInternal)
		}
	}
	_ = s.deps.AdminAudit.Write(ctx, e)
}
