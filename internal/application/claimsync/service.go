// Package claimsync 接收用户中心推来的"凭证已失效"通知，并失效本地 claim。
//
// 解决的具体问题：本服务的 identity_claims 记录的是「某次授权中，某平台
// 证明过这个身份拥有该手机号」。账号的权威手机号在用户中心；那边换号或
// 注销后，本地这条记录就过期了。而过期的 claim 会被用于归并判定——
// 两个本该分开的账号可能因此被并到一起（见架构 §8.5）。
//
// 与"归并前强制回源核对"的分工：
//
//	回源核对是最后一道闸门（宁可漏归并，不可错归并），它保证即使本包
//	彻底失效也不会错并；本包只是让本地数据尽快追上权威源，让漂移检测
//	与授权记录不至于长期说谎。两者不是替代关系。
//
// 为什么不做"精确撤销某一条"：用户中心只告诉我们"这个用户的 phone 变了"，
// 不带新旧号码（带过去等于多一份明文在链路上）。所以按 (身份, 类型) 撤销
// 全部有效 claim——宁可多撤一条（下次授权会重新写入），也不留一条错的。
package claimsync

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AuditAction 是写入业务审计的动作名。
//
// 与 login / bind 等并列：排障时要能一眼看出"这条 claim 是被谁失效的"——
// 用户中心的通知、用户自己换绑、还是管理端人工撤销。
const AuditAction = "claim_invalidated"

// Deps 是用例依赖。
type Deps struct {
	Apps     tenant.ApplicationRepository
	Bindings binding.Repository
	Claims   identity.ClaimRepository
	// Audit 可为 nil（测试）。生产必须装配：这是对本地授权数据的写操作。
	Audit   audit.Writer
	Metrics Metrics
	Log     *zap.Logger
	Now     func() time.Time
}

// Metrics 是接收端的指标（nil 安全）。
type Metrics interface {
	// RecordClaimInvalidated 记录一次通知处理。result 取 ok / ignored / failed。
	RecordClaimInvalidated(result string, revoked int)
}

type nopMetrics struct{}

func (nopMetrics) RecordClaimInvalidated(string, int) {}

// Service 是接收用例。
type Service struct {
	deps Deps
}

// New 构造用例。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.Log == nil {
		d.Log = zap.NewNop()
	}
	if d.Metrics == nil {
		d.Metrics = nopMetrics{}
	}
	return &Service{deps: d}
}

// Input 是一条失效通知。
type Input struct {
	// EventID 只用于日志关联（用户中心 outbox 的自增 id）。
	EventID   string
	AppKey    string
	UserID    string
	ClaimType string
	Reason    string
	TraceID   string
	ClientIP  string
}

// Result 是处理结果。
type Result struct {
	// Identities 是被处理的身份数（该账号下的活跃绑定数）。
	Identities int
	// Revoked 是实际被撤销的 claim 行数。
	//
	// 重复投递时是 0：这既不是错误也不是"没事可做"，而是"上一次已经处理过"。
	// 接口对这种情况仍返回成功——投递方据此把事件标记为已投递。
	Revoked int64
}

// Invalidate 失效某账号在某应用下的本地 claim。
//
// 幂等：重复调用返回 Revoked=0 且成功。这是"至少一次投递"能成立的前提。
func (s *Service) Invalidate(ctx context.Context, in Input) (*Result, error) {
	appKey := strings.TrimSpace(in.AppKey)
	userID := strings.TrimSpace(in.UserID)
	if appKey == "" || userID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "app_key 与 user_id 均不能为空")
	}
	claimType := strings.TrimSpace(in.ClaimType)
	if claimType != "" && claimType != "phone" && claimType != "email" {
		// 未知类型必须拒绝（400）：投递方会把它当永久失败进死信，
		// 而不是无限重试一个我们永远认不出的类型。
		return nil, errs.Newf(errs.CodeInvalidRequest, "未知的 claim_type: %q", claimType)
	}

	app, err := s.deps.Apps.FindByAppCode(ctx, appKey)
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			// 未知租户：可能是应用还没同步到本服务。返回 404 让投递方进死信，
			// 因为重试也不会让它变成已知——真有这种情况应该由对账修复应用，
			// 而不是靠无限重投一条通知。
			return nil, errs.Newf(errs.CodeNotFound, "应用不存在: %s", appKey)
		}
		return nil, err
	}

	bindings, err := s.deps.Bindings.ListActiveByExternalUser(ctx, app.ID, userID)
	if err != nil {
		if errors.Is(err, binding.ErrNotFound) {
			// 该账号在本服务没有任何活跃绑定：正常情况（比如用户只在别处登录过），
			// 不是错误。返回成功，让对端把事件标记为已投递。
			s.record(ctx, app, in, 0, 0)
			s.deps.Metrics.RecordClaimInvalidated("ignored", 0)
			return &Result{}, nil
		}
		return nil, err
	}

	now := s.deps.Now()
	var revoked int64
	for _, b := range bindings {
		n, err := s.deps.Claims.RevokeByType(ctx, app.ID, b.IdentityID, claimType, now)
		if err != nil {
			// 单条失败就整体失败：投递方会重试，而重复撤销是幂等的。
			// 不在这里"尽力而为"地继续——部分成功会让对端以为整条都成了。
			s.deps.Metrics.RecordClaimInvalidated("failed", int(revoked))
			return nil, err
		}
		revoked += n
	}

	s.record(ctx, app, in, len(bindings), revoked)
	result := "ok"
	if revoked == 0 {
		// 有绑定但一条都没撤：几乎总是重复投递。单独一档标签，
		// 否则"处理成功"的曲线看不出重投比例。
		result = "ignored"
	}
	s.deps.Metrics.RecordClaimInvalidated(result, int(revoked))

	s.deps.Log.Info("已按用户中心通知失效本地 claim",
		zap.String("app", appKey),
		zap.String("user_id", userID),
		zap.String("claim_type", claimTypeOrAll(claimType)),
		zap.String("reason", in.Reason),
		zap.Int("identities", len(bindings)),
		zap.Int64("revoked", revoked))

	return &Result{Identities: len(bindings), Revoked: revoked}, nil
}

// record 写业务审计。
//
// 失败只记日志：审计是旁路，不能因为它写不进去就让对端重试整条通知——
// 那会把"审计表临时不可写"放大成"claim 迟迟不失效"。
func (s *Service) record(ctx context.Context, app *tenant.Application, in Input, identities int, revoked int64) {
	if s.deps.Audit == nil {
		return
	}
	ev := &audit.Event{
		AppID:          app.ID,
		ExternalUserID: in.UserID,
		// platform/scene 留空：这个动作不是某次授权发生的，而是跨服务的
		// 数据同步。填一个假平台会让按平台统计的看板出现幽灵数据。
		Action:   AuditAction,
		Result:   audit.ResultSuccess,
		TraceID:  in.TraceID,
		ClientIP: in.ClientIP,
		At:       s.deps.Now(),
		Detail: map[string]any{
			"claim_type": claimTypeOrAll(in.ClaimType),
			"reason":     in.Reason,
			"event_id":   in.EventID,
			"identities": identities,
			"revoked":    revoked,
		},
	}
	if err := s.deps.Audit.Write(ctx, ev); err != nil {
		s.deps.Log.Error("写入 claim 失效审计失败", zap.Error(err),
			zap.String("user_id", in.UserID))
	}
}

func claimTypeOrAll(t string) string {
	if t == "" {
		return "all"
	}
	return t
}
