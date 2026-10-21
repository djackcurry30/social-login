// Package merge 是账号合并的用例编排（架构 §7.3，修正 P0-3）。
//
// 这里最容易被写错的一件事：把"落库 + 调远端 + 本地收敛"包进一个事务。
// 那样做的后果不是"性能差"，而是**永久孤儿**——远端合并成功了，
// 本地事务回滚，compensation 任务连记录都扫不到，两个账号在远端已经是一个、
// 在我们这边还是两个，且不可逆。
//
// 所以本包的 Execute 严格按三步走，每步之间没有事务：
//
//	① CreateOp（事务 A，独立提交）
//	② Accounts.Merge（无事务，网络调用）
//	③ Converger.Converge（事务 B，含绑定改挂 + 令牌撤销 + outbox + 审计）
package merge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// Deps 是用例依赖。
type Deps struct {
	Ops       mergex.Store
	Converger mergex.Converger
	Accounts  account.Provider
	Locker    mergex.Locker
	Audit     audit.Writer
	Logger    *zap.Logger
	Now       func() time.Time
	// Tickets 保存"待验证合并"票据（confirm 模式）。
	Tickets ticket.Store
	// Challenges 存验证码挑战。
	Challenges mergex.ChallengeStore
	// Sender 发验证码短信。
	Sender mergex.CodeSender
	// RemoteIdempotent 表示用户中心是否真正实现了按幂等键去重（§D3 硬性要求）。
	//
	// 为 false 时**不做自动重试**，只发告警：非幂等的 Merge 被重复执行会
	// 重复迁移订单/资产，那是比"合并没完成"严重得多的事故（§7.3 明确要求）。
	RemoteIdempotent bool
}

// Trigger 是合并的触发场景。
//
// 必须区分：登录场景（login）下的合并等同"用未经证明的身份吞掉另一个账号"，
// 只有 bind（用户已登录、主动绑定）与管理端手工推进才允许。
type Trigger string

const (
	TriggerBind  Trigger = "bind"
	TriggerAdmin Trigger = "admin"
)

// Request 是一次合并请求。
type Request struct {
	App          *tenant.Application
	TargetUserID string
	SourceUserID string
	// Identity 是触发本次合并的三方身份（用于跨平台判断与事件体）。
	Identity *identity.Identity
	Trigger  Trigger
	Reason   string
	// Verified 表示调用方【已经完成】用户验证（confirm 模式的短信验证）。
	//
	// 只有 merge.Service 自己的验证流程会把它置为 true；HTTP 层不暴露这个
	// 字段——否则调用方可以绕过验证直接声称"我验证过了"，confirm 模式作废。
	Verified bool
}

// Result 是合并结果。
type Result struct {
	OperationID int64
	// AlreadyMerged 表示命中幂等（此前已合并成功），不是错误。
	AlreadyMerged bool
	Remote        *account.MergeResult
}

// ErrNeedVerification 表示 confirm 模式下需要用户先完成验证。
//
// 用哨兵错误而不是返回值：调用方（authflow）需要把"需要验证"与
// "合并失败"走完全不同的响应分支——一个是正常的引导流程，一个是故障。
var ErrNeedVerification = errors.New("merge: 需要用户验证后才能合并")

// ErrRejected 表示按配置规则不允许合并（manual 模式、跨平台未授权等）。
var ErrRejected = errors.New("merge: 按应用配置不允许合并")

// RejectError 携带拒绝原因，便于接入方展示与排障。
type RejectError struct {
	Reason string
	Code   errs.Code
}

func (e *RejectError) Error() string { return e.Reason }
func (e *RejectError) Unwrap() error { return ErrRejected }

// Service 是合并用例。
type Service struct {
	deps Deps
	// appLookup 供补偿时读取应用策略（SetAppLookup 注入）。
	// 不放 Deps 是因为它只在 Resume 路径用到，而主流路径不需要为了
	// "能补偿"把租户仓储塞进每个调用点。
	appLookup AppPolicyLookup
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: d}
}

// Execute 执行一次合并。
//
// 返回 ErrNeedVerification 时【没有产生任何数据变更】，调用方应引导用户验证；
// 返回 *RejectError 时同理，只是原因是配置不允许。
func (s *Service) Execute(ctx context.Context, req Request) (*Result, error) {
	if req.App == nil {
		return nil, errs.New(errs.CodeInternal, "合并缺少应用上下文")
	}
	if req.TargetUserID == "" || req.SourceUserID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "合并缺少目标或源账号")
	}
	if req.TargetUserID == req.SourceUserID {
		// 同一账号"合并到自己"是接入方的逻辑错误，不该静默成功。
		return nil, errs.New(errs.CodeInvalidRequest, "目标账号与源账号相同")
	}

	// 第 0 步：前置校验（只读，不开启事务）。
	mode, err := s.precheck(req)
	if err != nil {
		return nil, err
	}

	// 锁：同一目标账号的合并串行化。
	if s.deps.Locker != nil {
		unlock, lerr := s.deps.Locker.Lock(ctx,
			fmt.Sprintf("lock:merge:%d:%s", req.App.ID, req.TargetUserID), 30*time.Second)
		if lerr != nil {
			if errors.Is(lerr, mergex.ErrLocked) {
				// 并发合并正在跑：这不是失败，是"稍后重试"。
				return nil, errs.New(errs.CodeAdminConflict, "该账号的合并正在进行中，请稍后重试").
					WithDetail("retryable_after_ms", 500)
			}
			return nil, lerr
		}
		defer unlock()
	}

	key := idempotencyKey(req)

	// 第 1 步：独立事务 A —— 先持久化，保证可补偿。
	op, created, err := s.deps.Ops.Create(ctx, &mergex.Operation{
		AppID:          req.App.ID,
		IdempotencyKey: key,
		TargetUserID:   req.TargetUserID,
		SourceUserID:   req.SourceUserID,
		IdentityID:     identityIDOf(req.Identity),
		Status:         mergex.StatusPending,
		Reason:         req.Reason,
	})
	if err != nil {
		return nil, err
	}

	switch op.Status {
	case mergex.StatusDone:
		// 幂等命中：这次重复请求什么也不做。返回成功而非冲突——
		// 用户视角"绑定成功了"在第一次就已经成立。
		return &Result{OperationID: op.ID, AlreadyMerged: true}, nil
	case mergex.StatusRejected:
		return nil, &RejectError{Reason: "该合并此前已被规则拒绝", Code: errs.CodeBindIdentityTaken}
	case mergex.StatusDead:
		return nil, errs.New(errs.CodeAdminConflict, "该合并已进入人工处理队列").
			WithDetail("operation_id", op.ID)
	}

	if !created {
		s.logger().Info("命中未完成的合并操作，继续推进",
			zap.Int64("operation_id", op.ID), zap.String("status", op.Status))
	}

	// 第 2 步：无事务的跨服务调用。
	remote, mergeErr := s.deps.Accounts.Merge(ctx, account.MergeRequest{
		TargetUserID:   req.TargetUserID,
		SourceUserID:   req.SourceUserID,
		IdempotencyKey: op.IdempotencyKey,
		Reason:         req.Reason,
	})
	if mergeErr != nil {
		s.fail(ctx, op, nil, mergeErr)
		return nil, errs.Wrap(errs.CodeAccountUnavailable, "用户中心合并失败，已进入补偿队列", mergeErr).
			WithDetail("operation_id", op.ID)
	}

	// 第 3 步：独立事务 B —— 本地收敛 + 事件 + 审计。
	if err := s.deps.Converger.Converge(ctx, mergex.ConvergeInput{
		AppID:        req.App.ID,
		OperationID:  op.ID,
		TargetUserID: req.TargetUserID,
		SourceUserID: req.SourceUserID,
		IdentityID:   identityIDOf(req.Identity),
		RemoteResult: remoteRef(remote),
		Event:        s.mergedEvent(req, op, remote),
		Audit:        s.mergedAudit(ctx, req, op, remote),
	}); err != nil {
		// 远端已成功、本地收敛失败：这是最需要补偿的状态。
		// 标 failed 而不是 dead——补偿任务会在下一轮重新走第 2、3 步，
		// 而第 2 步因幂等键会命中"已合并"，不会重复迁移数据。
		s.fail(ctx, op, remoteRef(remote), err)
		return nil, errs.Wrap(errs.CodeInternal, "本地收敛失败，已进入补偿队列", err).
			WithDetail("operation_id", op.ID).
			WithDetail("remote_merged", true)
	}

	s.logger().Info("账号合并完成",
		zap.Int64("app_id", req.App.ID),
		zap.Int64("operation_id", op.ID),
		zap.String("target", req.TargetUserID),
		zap.String("source", req.SourceUserID),
		zap.String("mode", mode),
		zap.String("trigger", string(req.Trigger)))

	return &Result{OperationID: op.ID, Remote: remote}, nil
}

// precheck 执行 §7.2 / §7.5.3 的前置校验，返回生效的 mode 供日志使用。
func (s *Service) precheck(req Request) (string, error) {
	p := req.App.Policy.Merge

	switch p.Mode {
	case tenant.MergeModeManual:
		// manual：只提示不处理。记录一条 rejected 便于管理端看到"用户试图合并过"。
		return p.Mode, &RejectError{
			Reason: "应用配置为 manual 模式，不提供账号合并",
			Code:   errs.CodeBindIdentityTaken,
		}
	case tenant.MergeModeConfirm:
		// confirm：需要用户证明对 source 账号的控制权。
		//
		// Verified=true 表示验证流程（POST /v1/bind/resolve → 短信验证码）已完成。
		// 未验证时只返回哨兵错误，绝不降级为 auto——那等于把 confirm 配置
		// 静默改成 auto，是最危险的一类静默失败。
		if req.Verified {
			return p.Mode, nil
		}
		return p.Mode, ErrNeedVerification
	case tenant.MergeModeAuto:
		// auto：用户已登录 target，并成功完成了对 source 身份的授权，
		// 因此双方归属都有实际证据（§7.3 的三个条件之一）。
		//
		// R4 红线 3（跨平台自动合并）在这一路径上【不会触发】：合并发生在
		// 同一个 identity 的原绑定账号与当前账号之间，identity 只有一份，
		// 平台必然相同。跨平台判定属于 login 链路的 claim 归并
		// （on_login=claim_verified），那条路径会显式检查该开关。
		return p.Mode, nil
	default:
		return p.Mode, errs.Newf(errs.CodeConfigInvalid, "未知的合并模式: %s", p.Mode)
	}
}

// Event/Audit 构造 ---

func (s *Service) mergedEvent(req Request, op *mergex.Operation, remote *account.MergeResult) *mergex.ConvergeEvent {
	payload := map[string]any{
		"merge_id":              op.ID,
		"target_user_id":        req.TargetUserID,
		"source_user_id":        req.SourceUserID,
		"trigger":               string(req.Trigger),
		"occurred_at":           s.deps.Now().Format(time.RFC3339),
		"notify_source_account": true,
	}
	if req.Identity != nil {
		payload["identity_id"] = req.Identity.ID
		payload["platform"] = req.Identity.Platform
	}
	if remote != nil && remote.RemoteRef != nil {
		payload["remote_ref"] = remote.RemoteRef
	}
	return &mergex.ConvergeEvent{
		EventID:       event.NewEventID(s.deps.Now()),
		Type:          event.TypeAccountMerged,
		SchemaVersion: 1,
		Payload:       payload,
	}
}

func (s *Service) mergedAudit(ctx context.Context, req Request, op *mergex.Operation, remote *account.MergeResult) *mergex.ConvergeAudit {
	m := reqmeta.From(ctx)
	a := &mergex.ConvergeAudit{
		Action:         audit.ActionMerge,
		ExternalUserID: req.SourceUserID,
		TraceID:        m.TraceID,
		Detail: map[string]any{
			"merge_id":       op.ID,
			"target_user_id": req.TargetUserID,
			"source_user_id": req.SourceUserID,
			"trigger":        string(req.Trigger),
			"merge_mode":     req.App.Policy.Merge.Mode,
			"reason":         req.Reason,
		},
	}
	if req.Identity != nil {
		a.Platform = req.Identity.Platform
		a.Detail["identity_id"] = req.Identity.ID
	}
	if remote != nil {
		a.Detail["already_merged"] = remote.AlreadyMerged
	}
	return a
}

func (s *Service) fail(ctx context.Context, op *mergex.Operation, remote map[string]any, cause error) {
	msg := cause.Error()
	if !s.deps.RemoteIdempotent {
		// 非幂等的远端不能进自动重试链路（§7.3 明确要求）。这里直接 dead，
		// 让管理端 D 组人工核对后推进，而不是让补偿任务反复调用。
		msg += "（用户中心未声明 Merge 幂等，已跳过自动重试，需人工推进）"
		if err := s.deps.Ops.MarkDead(ctx, op.ID, msg); err != nil {
			s.logger().Error("回写合并 dead 状态失败", zap.Int64("operation_id", op.ID), zap.Error(err))
		}
		return
	}
	if err := s.deps.Ops.MarkFailed(ctx, op.ID, remote, msg); err != nil {
		s.logger().Error("回写合并失败状态失败", zap.Int64("operation_id", op.ID), zap.Error(err))
	}
}

// Resume 补偿：按幂等键重放第 2~3 步。
//
// 与 Execute 的差别是【不做前置校验】：操作在初次执行时已经过校验，
// 补偿时若配置被改成 manual，重放会被拒绝——那会让"已经调过远端的合并"
// 永远停在半路。补偿只关心"把已经决定要做的事做完"。
func (s *Service) Resume(ctx context.Context, op *mergex.Operation) error {
	if op == nil {
		return nil
	}
	if op.Status == mergex.StatusDone || op.Status == mergex.StatusRejected {
		return nil
	}
	if !s.deps.RemoteIdempotent {
		// 兜底：即使被别处塞进补偿队列，非幂等远端也不自动重放。
		return nil
	}

	app, err := s.loadAppPolicy(ctx, op)
	if err != nil {
		return err
	}

	remote, mergeErr := s.deps.Accounts.Merge(ctx, account.MergeRequest{
		TargetUserID:   op.TargetUserID,
		SourceUserID:   op.SourceUserID,
		IdempotencyKey: op.IdempotencyKey,
		Reason:         "补偿重试",
	})
	if mergeErr != nil {
		if op.Attempts+1 >= mergex.MaxAttempts {
			_ = s.deps.Ops.MarkDead(ctx, op.ID, "补偿重试达到上限: "+mergeErr.Error())
			return nil
		}
		_ = s.deps.Ops.MarkFailed(ctx, op.ID, nil, mergeErr.Error())
		return nil
	}

	req := Request{
		App:          app,
		TargetUserID: op.TargetUserID,
		SourceUserID: op.SourceUserID,
		Trigger:      TriggerAdmin,
		Reason:       op.Reason,
	}
	if err := s.deps.Converger.Converge(ctx, mergex.ConvergeInput{
		AppID:        op.AppID,
		OperationID:  op.ID,
		TargetUserID: op.TargetUserID,
		SourceUserID: op.SourceUserID,
		IdentityID:   op.IdentityID,
		RemoteResult: remoteRef(remote),
		Event:        s.mergedEvent(req, op, remote),
		Audit:        s.mergedAudit(ctx, req, op, remote),
	}); err != nil {
		if op.Attempts+1 >= mergex.MaxAttempts {
			_ = s.deps.Ops.MarkDead(ctx, op.ID, "本地收敛失败且达到上限: "+err.Error())
			return nil
		}
		_ = s.deps.Ops.MarkFailed(ctx, op.ID, remoteRef(remote), err.Error())
		return nil
	}
	s.logger().Info("合并补偿完成", zap.Int64("operation_id", op.ID))
	return nil
}

// AppPolicyLookup 由调用方注入（避免本包依赖租户仓储的完整接口）。
type AppPolicyLookup func(ctx context.Context, appID int64) (*tenant.Application, error)

func (s *Service) loadAppPolicy(ctx context.Context, op *mergex.Operation) (*tenant.Application, error) {
	if s.appLookup == nil {
		return nil, errs.New(errs.CodeInternal, "合并服务未注入应用查询：无法补偿")
	}
	return s.appLookup(ctx, op.AppID)
}

// SetAppLookup 注入应用查询（装配期调用，避免把大接口塞进 Deps 的必填项）。
func (s *Service) SetAppLookup(fn AppPolicyLookup) { s.appLookup = fn }

func (s *Service) logger() *zap.Logger {
	if s.deps.Logger == nil {
		return zap.NewNop()
	}
	return s.deps.Logger
}

// --- helpers ---

// idempotencyKey 确定性生成幂等键。
//
// 用"场景 + 应用 + 双方"而不是随机值：同一冲突被重复触发时必须命中同一行，
// 否则每次重试都会新开一条 merge_operations，补偿任务会把同一个合并做 N 次。
func idempotencyKey(req Request) string {
	return fmt.Sprintf("merge:%s:%d:%s:%s", req.Trigger, req.App.ID, req.TargetUserID, req.SourceUserID)
}

func identityIDOf(idn *identity.Identity) int64 {
	if idn == nil {
		return 0
	}
	return idn.ID
}

func remoteRef(r *account.MergeResult) map[string]any {
	if r == nil {
		return nil
	}
	out := map[string]any{"merged": r.Merged, "already_merged": r.AlreadyMerged}
	if r.RemoteRef != nil {
		out["ref"] = r.RemoteRef
	}
	return out
}
