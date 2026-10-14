// Package binding 是引导绑定的用例层（约束 C5 / 需求 R1）。
//
// 这里实现的是"业务方引导用户注册/登录之后，用 bind_ticket 完成绑定"这一步。
// 它是 C4 + C5 组合下唯一能让用户从"三方授权成功"走到"拿到业务账号令牌"的通道。
//
// 安全要点（修正 A16）：bind_ticket 与【具体 identity】绑定、一次性、10 分钟有效。
// 如果 /v1/bind 只凭"业务方说自己登了谁"就能绑身份，那任何人都能把已存在的
// 三方身份抢绑到自己名下——票据是这条链路上唯一的凭证。
package binding

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/17track/social-login/internal/application/tenantconfig"
	"github.com/17track/social-login/internal/application/token"
	"github.com/17track/social-login/internal/domain/audit"
	domainbinding "github.com/17track/social-login/internal/domain/binding"
	"github.com/17track/social-login/internal/domain/ticket"
	"github.com/17track/social-login/internal/pkg/auditx"
	"github.com/17track/social-login/internal/pkg/errs"
	"github.com/17track/social-login/internal/pkg/reqmeta"
)

// Deps 是依赖集合。
type Deps struct {
	Tenant   *tenantconfig.Service
	Tickets  ticket.Store
	Bindings domainbinding.Repository
	Tokens   *token.Service
	Audit    audit.Writer
	Logger   *zap.Logger
}

// Service 提供绑定、解绑与查询。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(deps Deps) *Service { return &Service{deps: deps} }

// BindInput 是 /v1/bind 的入参。
type BindInput struct {
	AppCode string
	// BindTicket 来自 AUTH.NEED_REGISTER 分支（与 identity 绑定的一次性票据）。
	BindTicket string
	// ExternalUserID 是业务方当前已登录的账号（约束 C4 下的外部账号标识）。
	// 生产实现中它由接入层从已验证的访问令牌解出，【不能】由请求体直接提供。
	ExternalUserID string
	// DeviceID 用于绑定成功后签发令牌时记录设备。
	DeviceID string
}

// BindResult 是绑定结果。
type BindResult struct {
	IdentityID int64
	Platform   string
	Scene      string
	Profile    map[string]any
	// Tokens 是绑定成功后直接签发的令牌。
	//
	// 为什么在 bind 里直接签发而不是让业务方再调一次 /v1/token：
	// bind 时我们已经有 appId + identity + 业务账号三要素，再走一次一次性
	// auth_code 只是多一次往返，没有额外的安全性收益。
	Tokens *token.Response
}

// Bind 用 bind_ticket 把三方身份绑定到当前登录账号。
func (s *Service) Bind(ctx context.Context, in BindInput) (*BindResult, error) {
	if in.BindTicket == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "缺少 bind_ticket").
			WithDetail("field", "bind_ticket")
	}
	if in.ExternalUserID == "" {
		return nil, errs.New(errs.CodeUnauthorized, "缺少当前登录账号，无法完成绑定")
	}

	app, err := s.deps.Tenant.Application(ctx, in.AppCode)
	if err != nil {
		return nil, err
	}

	bt, err := s.deps.Tickets.ConsumeBindTicket(ctx, in.BindTicket)
	if err != nil {
		if errors.Is(err, ticket.ErrBindTicketInvalid) {
			return nil, errs.New(errs.CodeBindTicketInvalid,
				"绑定票据无效、已使用或已过期，请重新发起授权")
		}
		return nil, err
	}
	// 票据与应用必须匹配：否则一个持有低权限应用凭据的调用方可以消费别的应用的票据。
	if bt.AppID != app.ID {
		return nil, errs.New(errs.CodeBindTicketInvalid, "绑定票据不属于当前应用")
	}

	b, alreadyExists, err := s.deps.Bindings.Activate(ctx, domainbinding.ActivateInput{
		AppID:          app.ID,
		ExternalUserID: in.ExternalUserID,
		IdentityID:     bt.IdentityID,
		IsPrimary:      true,
		BindSource:     domainbinding.SourceExplicit,
		At:             time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	_ = b

	if alreadyExists {
		// 竞态：票据是一次性的，正常流程不会走到这里。能走到说明存在并发请求
		// 或调用方在重放票据——两种情况都应告警，而不是静默成功。
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("绑定票据被重复消费",
				zap.Int64("app_id", app.ID),
				zap.Int64("identity_id", bt.IdentityID))
		}
		return nil, errs.New(errs.CodeBindTicketInvalid,
			"绑定票据已被使用，请重新发起授权")
	}

	res := &BindResult{
		IdentityID: bt.IdentityID,
		Platform:   bt.Platform,
		Scene:      bt.Scene,
		Profile:    bt.Profile,
	}

	tokens, err := s.deps.Tokens.IssueForBoundIdentity(ctx, token.BoundIdentity{
		AppCode:        app.AppCode,
		ExternalUserID: in.ExternalUserID,
		DeviceID:       in.DeviceID,
		AMR:            ticket.AMR(bt.Platform, bt.Scene),
	})
	if err != nil {
		return nil, err
	}
	res.Tokens = tokens

	auditx.Emit(ctx, s.deps.Audit, s.deps.Logger, &audit.Event{
		AppID:          app.ID,
		ExternalUserID: in.ExternalUserID,
		Platform:       bt.Platform,
		Scene:          bt.Scene,
		Action:         audit.ActionBind,
		Result:         audit.ResultSuccess,
		TraceID:        reqmeta.TraceID(ctx),
		Detail:         map[string]any{"identity_id": bt.IdentityID},
		At:             time.Now().UTC(),
	})
	return res, nil
}

// BindingView 是绑定关系的对外视图。
type BindingView struct {
	IdentityID int64  `json:"identity_id"`
	Platform   string `json:"platform"`
	Scene      string `json:"scene,omitempty"`
	IsPrimary  bool   `json:"is_primary"`
	BindSource string `json:"bind_source"`
	BoundAt    string `json:"bound_at"`
}

// ListBindings 查询某账号已绑的全部渠道（引导绑定页面的数据源）。
//
// 注意：scene 不在 oauth_identities 表里（身份由 app_id + platform +
// provider_app_id + open_id 唯一确定）。要展示 scene 需要经渠道配置反查，
// 属于管理端与前端展示的细节，第三期随引导绑定页一起补齐。
func (s *Service) ListBindings(ctx context.Context, appCode, externalUserID string) ([]BindingView, error) {
	if externalUserID == "" {
		return nil, errs.New(errs.CodeUnauthorized, "缺少账号标识")
	}
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return nil, err
	}
	rows, err := s.deps.Bindings.ListActiveByExternalUser(ctx, app.ID, externalUserID)
	if err != nil {
		return nil, err
	}
	out := make([]BindingView, 0, len(rows))
	for _, r := range rows {
		out = append(out, BindingView{
			IdentityID: r.IdentityID,
			IsPrimary:  r.IsPrimary,
			BindSource: r.BindSource,
			BoundAt:    r.BoundAt.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// Unbind 解绑（DELETE /v1/bind/{identity_id}）。
//
// 有一条业务规则必须由本层把关：**不能解绑最后一个登录方式**。
// 否则用户会把自己锁在账号外面，且无法自助恢复。
func (s *Service) Unbind(ctx context.Context, appCode, externalUserID string, identityID int64) error {
	if externalUserID == "" || identityID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "解绑参数不完整")
	}
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return err
	}

	b, err := s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, identityID)
	if err != nil {
		if errors.Is(err, domainbinding.ErrNotFound) {
			return errs.New(errs.CodeBindNotFound, "绑定关系不存在或已解绑")
		}
		return err
	}
	// 归属校验：不允许解绑他人账号的绑定。
	if b.ExternalUserID != externalUserID {
		return errs.New(errs.CodeForbidden, "该绑定不属于当前账号")
	}

	active, err := s.deps.Bindings.CountActive(ctx, app.ID, externalUserID)
	if err != nil {
		return err
	}
	if active <= 1 {
		return errs.New(errs.CodeInvalidRequest,
			"这是账号的最后一个登录方式，解绑后将无法登录")
	}

	if err := s.deps.Bindings.Unbind(ctx, app.ID, identityID, time.Now().UTC()); err != nil {
		if errors.Is(err, domainbinding.ErrNotFound) {
			return errs.New(errs.CodeBindNotFound, "绑定关系不存在或已解绑")
		}
		return err
	}

	auditx.Emit(ctx, s.deps.Audit, s.deps.Logger, &audit.Event{
		AppID:          app.ID,
		ExternalUserID: externalUserID,
		Action:         audit.ActionUnbind,
		Result:         audit.ResultSuccess,
		TraceID:        reqmeta.TraceID(ctx),
		Detail:         map[string]any{"identity_id": identityID},
		At:             time.Now().UTC(),
	})
	return nil
}
