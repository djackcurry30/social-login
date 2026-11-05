// Package adminapproval 是高危操作双人复核的用例层（§15.5）。
//
// 流程只有三步，刻意不做"批准后自动执行"：
//
//	① Create  申请人说明要做什么（动作 + 目标应用 + 原因）
//	② Approve 另一名超管批准（申请人不能自批）
//	③ Consume 执行接口带着审批单号，消费即作废
//
// 为什么不让审批通过后由系统异步执行原操作：
// 那需要把原始请求完整存下来（可能含凭证）、还要处理"执行时权限已变"
// 的情况。而现在这个模型里，"批准"只表示"同意这件事"，真正的执行仍然
// 走原来的接口、原来的校验、原来的审计——审批只多一个前置条件。
package adminapproval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/approval"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// Deps 是用例依赖。
type Deps struct {
	Store approval.Store
	// Audit 写 admin_audit_logs。可为 nil（单测），生产必须装配：
	// 审批的意义是"可追责"，只写普通日志的话，审计查询页里看不到
	// "谁批的、谁用掉了这张单"。
	Audit admin.AuditWriter
	Log   *zap.Logger
	Now   func() time.Time
	// TTL 是审批单有效期。0 取 approval.DefaultTTL。
	TTL time.Duration
}

// Service 是审批用例。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.TTL <= 0 {
		d.TTL = approval.DefaultTTL
	}
	return &Service{deps: d}
}

// CreateInput 是提交申请的参数。
type CreateInput struct {
	Action string
	AppID  *int64
	// Reason 必须写清楚"为什么要做这件事"，它是批准人的唯一判断依据。
	Reason string
	// PayloadHash 可选：调用方对本次请求的关键参数做摘要。
	// 服务端不强求（不同接口的参数结构不同），但存下来能证明
	// "批准的是同一件事"，而不是同一类事。
	PayloadHash string
	RequesterID int64
}

// Create 创建审批单。
func (s *Service) Create(ctx context.Context, in CreateInput) (*approval.Approval, error) {
	if in.Action == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "action 不能为空")
	}
	if len([]rune(in.Reason)) < 4 {
		// 与其它高危操作同口径：理由太短等于没写，批准人无从判断。
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"提交审批必须填写 reason（≥4 字符），它是批准人的唯一判断依据")
	}
	if in.RequesterID <= 0 {
		return nil, errs.New(errs.CodeUnauthorized, "缺少申请人")
	}

	now := s.deps.Now()
	a := &approval.Approval{
		Action:      in.Action,
		AppID:       in.AppID,
		PayloadHash: hashOrEmpty(in.PayloadHash),
		RequestedBy: in.RequesterID,
		RequestedAt: now,
		Reason:      in.Reason,
		Status:      approval.StatusPending,
		ExpiresAt:   now.Add(s.deps.TTL),
	}
	if err := s.deps.Store.Create(ctx, a); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "创建审批单失败", err)
	}
	s.writeAudit(ctx, in.RequesterID, "approval.create", fmt.Sprintf("%d", a.ID), in.Reason, nil,
		map[string]any{"action": a.Action, "app_id": a.AppID, "expires_at": a.ExpiresAt}, "success", nil)
	if s.deps.Log != nil {
		s.deps.Log.Info("审批单已创建",
			zap.Int64("approval_id", a.ID),
			zap.String("action", a.Action),
			zap.Int64("requested_by", a.RequestedBy))
	}
	return a, nil
}

// List 列出审批单。
//
// viewer 只能看自己提交的；只有超管能看全部——审批单里含"谁想动什么"，
// 普通管理员没有必要互相看。
func (s *Service) List(ctx context.Context, in ListInput) ([]*approval.Approval, error) {
	f := approval.Filter{Status: in.Status, Limit: in.Limit}
	if !in.All {
		f.RequestedBy = in.CallerID
	}
	return s.deps.Store.List(ctx, f)
}

// ListInput 是列表入参。
type ListInput struct {
	Status   approval.Status
	Limit    int
	CallerID int64
	// All 表示"看全部"，仅超管可置 true（由 handler 判定）。
	All bool
}

// Approve 批准审批单。
func (s *Service) Approve(ctx context.Context, id, approverID int64) (*approval.Approval, error) {
	if err := s.deps.Store.Approve(ctx, id, approverID, s.deps.Now()); err != nil {
		return nil, translate(err)
	}
	a, err := s.deps.Store.Get(ctx, id)
	if err != nil {
		return nil, translate(err)
	}
	s.writeAudit(ctx, approverID, "approval.approve", fmt.Sprintf("%d", id), "批准："+a.Reason, nil,
		map[string]any{"action": a.Action, "app_id": a.AppID, "requested_by": a.RequestedBy}, "success", nil)
	if s.deps.Log != nil {
		s.deps.Log.Info("审批单已批准",
			zap.Int64("approval_id", id), zap.String("action", a.Action),
			zap.Int64("approved_by", approverID))
	}
	return a, nil
}

// Reject 驳回审批单。
func (s *Service) Reject(ctx context.Context, id, approverID int64) (*approval.Approval, error) {
	if err := s.deps.Store.Reject(ctx, id, approverID, s.deps.Now()); err != nil {
		return nil, translate(err)
	}
	a, err := s.deps.Store.Get(ctx, id)
	if err != nil {
		return nil, translate(err)
	}
	s.writeAudit(ctx, approverID, "approval.reject", fmt.Sprintf("%d", id), "驳回："+a.Reason, nil,
		map[string]any{"action": a.Action, "app_id": a.AppID, "requested_by": a.RequestedBy}, "success", nil)
	if s.deps.Log != nil {
		s.deps.Log.Info("审批单已驳回",
			zap.Int64("approval_id", id), zap.String("action", a.Action),
			zap.Int64("rejected_by", approverID))
	}
	return a, nil
}

// Consume 校验并消费审批单（供执行接口的中间件调用）。
//
// 返回的错误已经是面向外部的错误码，调用方直接输出即可。
func (s *Service) Consume(ctx context.Context, id int64, action string, appID *int64, actorID int64) error {
	if err := s.deps.Store.Consume(ctx, id, action, appID, s.deps.Now()); err != nil {
		// 失败也要留痕：一张被反复尝试的审批单（过期了还在用、拿 A 的单做 B）
		// 是"有人在绕流程"的信号，只在日志里出现是查不到的。
		s.writeAudit(ctx, actorID, "approval.consume", fmt.Sprintf("%d", id), "", nil,
			map[string]any{"executed_action": action, "app_id": appID}, "denied", err)
		return translate(err)
	}
	s.writeAudit(ctx, actorID, "approval.consume", fmt.Sprintf("%d", id), "", nil,
		map[string]any{"executed_action": action, "app_id": appID}, "success", nil)
	return nil
}

// IsSuperAdmin 报告该管理员是否是超管（handler 用它决定能否看全部/审批）。
func IsSuperAdmin(u *admin.User) bool { return u != nil && u.Role == admin.RoleSuperAdmin }

// translate 把领域错误翻译成对外错误码。
//
// 每一条都给"下一步该做什么"，而不是只说"不行"：
// 审批单不可用时运维最需要知道的是重新申请，还是等批准，还是换一张单。
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, approval.ErrNotFound):
		return errs.New(errs.CodeNotFound, "审批单不存在")
	case errors.Is(err, approval.ErrSelfApprove):
		return errs.New(errs.CodeForbidden, "不能批准自己提交的申请（双人复核要求另一名超管）")
	case errors.Is(err, approval.ErrExpired):
		return errs.New(errs.CodeAdminConflict, "审批单已过期，请重新提交申请")
	case errors.Is(err, approval.ErrNotPending):
		return errs.New(errs.CodeAdminConflict, "审批单状态已变更（可能已被批准或驳回）")
	case errors.Is(err, approval.ErrNotApproved):
		return errs.New(errs.CodeAdminApprovalRequired, "审批单未批准或已被使用")
	case errors.Is(err, approval.ErrMismatch):
		return errs.New(errs.CodeAdminApprovalRequired, "审批单与本次操作不匹配（动作或应用不一致）")
	default:
		return errs.Wrap(errs.CodeInternal, "审批处理失败", err)
	}
}

// writeAudit 把审批生命周期写进管理端审计表。
//
// 三条约定：
//
//	subject_id 用 "admin:<id>"，与 adminapp 等写操作同一套命名——
//	           审计查询页按 subject 过滤时才不会漏掉审批记录；
//	target     是审批单（approval/<id>），app_id 带上，方便按应用筛；
//	失败只记日志不返回错误：审计写失败时审批本身已经提交，
//	           返回错误会让调用方以为"没批成功"而重试，反而产生第二张单。
func (s *Service) writeAudit(ctx context.Context, actorID int64, action, targetID, reason string,
	before, after map[string]any, result string, cause error,
) {
	if s.deps.Audit == nil {
		return
	}
	if reason == "" {
		// 审计表 reason 是 NOT NULL 且为空字符串会被仓储拒绝，这里给一个
		// 不会误导人的缺省值（而不是编一句"无"）。
		reason = "审批流程：" + action
	}
	ev := &admin.AuditEvent{
		SubjectID:   "admin:" + strconv.FormatInt(actorID, 10),
		Action:      action,
		TargetType:  "approval",
		TargetID:    targetID,
		Reason:      reason,
		BeforeState: before,
		AfterState:  after,
		Result:      result,
		TraceID:     reqmeta.TraceID(ctx),
	}
	if cause != nil {
		if e := errs.From(cause); e != nil {
			ev.ErrorCode = string(e.Code)
		} else {
			ev.ErrorCode = string(errs.CodeInternal)
		}
	}
	if err := s.deps.Audit.Write(ctx, ev); err != nil && s.deps.Log != nil {
		s.deps.Log.Error("写入审批审计失败", zap.String("action", action), zap.Error(err))
	}
}

// hashOrEmpty 归一化 payload 摘要。
//
// 调用方可以传摘要，也可以什么都不传。传了就必须是 64 位十六进制——否则
// 说明它把原始参数（可能含凭证）直接塞进来了，那种"摘要"不能入库。
func hashOrEmpty(v string) string {
	if v == "" {
		return ""
	}
	if len(v) == 64 {
		if _, err := hex.DecodeString(v); err == nil {
			return v
		}
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
