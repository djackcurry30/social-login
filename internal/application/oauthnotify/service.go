// Package oauthnotify 处理三方平台发来的【服务端通知】（S2S notification）。
//
// 与授权回调（/v1/oauth/callback）的根本区别在于信任基础：
//
//	授权回调  带一次性 state 票据 → 票据证明"这条回调属于某次我们发起的授权"
//	服务端通知 没有票据、没有 app_id → 只能靠【报文签名】证明来源可信
//
// 因此本包的第一条铁律：**验签能力必须显式存在**。不能因为渠道实现了
// "无需验签返回 nil" 的宽容语义就认为通知可信（见 identitysource.CallbackCapability）。
//
// 第二条铁律：**平台的重试必须被容忍**。平台在收不到 2xx 时会重复投递，
// 因此"绑定已经解绑过了"、"身份不存在"这类结果必须以成功语义返回，
// 否则会陷入无限重投。
package oauthnotify

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	domainbinding "github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/identitysource"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/auditx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// TenantResolver 是用例需要的配置解析能力（由 tenantconfig.Service 满足）。
//
// 依赖窄接口而不是具体类型，是为了让本用例的测试不必构造整套仓储：
// 通知处理的安全逻辑（验签闸门、幂等、零绑定判定）必须能被单测覆盖，
// 而这些逻辑与"配置从哪张表来"毫无关系。
type TenantResolver interface {
	Application(ctx context.Context, appCode string) (*tenant.Application, error)
	Channel(ctx context.Context, appID int64, platform, scene, configKey string) (*tenantconfig.Channel, error)
}

// SourceRegistry 是来源查找端口。
//
// 只声明用得到的那个方法，而不是直接依赖 *identitysource.Registry：
// 测试里就能塞一个返回假 Source 的实现，不必构造完整注册表。
type SourceRegistry interface {
	Lookup(platform, scene string) (identitysource.Source, error)
}

// Deps 是用例依赖。
type Deps struct {
	Tenant     TenantResolver
	Sources    SourceRegistry
	Identities identity.Repository
	Bindings   domainbinding.Repository
	Audit      audit.Writer
	Logger     *zap.Logger
}

// Service 处理平台服务端通知。
type Service struct {
	deps Deps
	log  *zap.Logger
}

// New 构造服务。
func New(deps Deps) *Service {
	log := deps.Logger
	if log == nil {
		log = zap.NewNop()
	}
	return &Service{deps: deps, log: log}
}

// Input 是一条待处理的服务端通知。
type Input struct {
	// AppCode 用于定位业务应用。通知报文本身不含 app_id，
	// 由各平台的通知地址在注册时带上（Apple 的 S2S 端点是按 App 配置的）。
	AppCode   string
	Platform  string
	Scene     string
	ConfigKey string
	// Raw 是原始报文，含 body / query / header，交由适配器验签与解析。
	Raw *provider.CallbackPayload
}

// Output 是处理结果。
//
// Handled=false 表示"报文合法但无需动作"（重复投递、不相关事件等）。
// 调用方对它也应回 2xx——理由见包的文档。
type Output struct {
	Event          string `json:"event"`
	Handled        bool   `json:"handled"`
	IdentityID     int64  `json:"identity_id,omitempty"`
	ExternalUserID string `json:"external_user_id,omitempty"`
	// Reason 说明未处理的原因，便于平台侧与我们自己对账。
	Reason string `json:"reason,omitempty"`
}

// Handle 处理一条服务端通知。
func (s *Service) Handle(ctx context.Context, in Input) (*Output, error) {
	if in.AppCode == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "缺少 app_id：服务端通知地址必须携带 app_id").
			WithDetail("field", "app_id")
	}
	if in.Platform == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "缺少 platform").
			WithDetail("field", "platform")
	}
	if in.Raw == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "通知报文为空")
	}
	// 通知的 scene 由调用方（路由）补默认值，但必须与适配器注册的场景一致，
	// 否则会查到一个根本不存在的来源。
	if in.Raw.Platform == "" {
		in.Raw.Platform = in.Platform
	}
	if in.Raw.Scene == "" {
		in.Raw.Scene = in.Scene
	}

	app, err := s.deps.Tenant.Application(ctx, in.AppCode)
	if err != nil {
		return nil, err
	}
	ch, err := s.deps.Tenant.Channel(ctx, app.ID, in.Platform, in.Scene, in.ConfigKey)
	if err != nil {
		return nil, err
	}
	src, err := s.deps.Sources.Lookup(in.Platform, in.Scene)
	if err != nil {
		return nil, err
	}

	// 告诉适配器"这条报文应当属于哪个客户端"。通知报文本身不含 app_id，
	// 只有从渠道配置拿到 ProviderAppID 才能做 aud 比对（防跨应用重放）。
	// 必须在验签前注入——验签与 aud 校验是同一个原子判断。
	in.Raw.Audience = ch.Config.ProviderAppID

	// 能力必须是"真的存在"，不能靠 VerifyCallback 返回 nil 推断。
	capability, ok := src.(identitysource.CallbackCapability)
	if !ok || !capability.SupportsCallbackVerify() {
		s.log.Error("渠道未实现通知验签，拒绝处理",
			zap.String("platform", in.Platform),
			zap.String("scene", in.Scene),
			zap.Int64("app_id", app.ID))
		return nil, errs.Newf(errs.CodeProviderNotSupported,
			"渠道 %s 不支持服务端通知验签，无法安全处理该通知",
			provider.Key(in.Platform, in.Scene)).
			WithDetail("platform", in.Platform).
			WithDetail("scene", in.Scene)
	}

	// 顺序很重要：先验签、再解析。
	// 解析器内部也会验签（防止调用方绕过），这里是显式的第一道闸门。
	verifier := src.(identitysource.CallbackVerifier)
	if err := verifier.VerifyCallback(ctx, in.Raw); err != nil {
		s.log.Warn("服务端通知验签失败",
			zap.String("platform", in.Platform),
			zap.String("scene", in.Scene),
			zap.Error(err))
		return nil, err
	}

	parser, ok := src.(identitysource.CallbackParser)
	if !ok {
		return nil, provider.NotSupported("parse_callback")
	}
	ev, err := parser.ParseCallback(ctx, in.Raw)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, errs.New(errs.CodeInternal, "通知解析结果为空")
	}

	return s.apply(ctx, app.ID, ch.Config.ProviderAppID, ch.Config.Scene, ev)
}

// apply 把归一化事件落到本地状态。
func (s *Service) apply(ctx context.Context, appID int64, providerAppID, scene string, ev *provider.CallbackEvent) (*Output, error) {
	out := &Output{Event: ev.Type}
	now := time.Now().UTC()

	switch ev.Type {
	case provider.CallbackEventConsentRevoked, provider.CallbackEventAccountDelete:
		return s.revoke(ctx, appID, providerAppID, scene, ev, now, out)
	case provider.CallbackEventEmailDisabled:
		// 邮箱停用只影响资料可信度，不动绑定关系。
		// 但必须留痕：它是"用户正在收回 Apple 侧信息"的前兆，
		// 频繁出现往往意味着 consent-revoked 即将到达。
		out.Reason = "email_disabled_does_not_affect_binding"
		s.emitAudit(ctx, appID, "", "", scene, audit.ActionRevoke, audit.ResultSuccess, map[string]any{
			"source":      "platform_notify",
			"event":       ev.Type,
			"open_id":     ev.OpenID,
			"occurred_at": ev.OccurredAt,
			"note":        "邮箱停用不影响绑定关系",
		}, now)
		return out, nil
	default:
		// 未知事件：留痕但不报错，避免平台在重试队列里堆积。
		out.Reason = "unknown_event"
		s.emitAudit(ctx, appID, "", "", scene, audit.ActionRevoke, audit.ResultSuccess, map[string]any{
			"source":  "platform_notify",
			"event":   ev.Type,
			"open_id": ev.OpenID,
			"detail":  ev.Detail,
		}, now)
		s.log.Warn("收到未建模的服务端通知事件",
			zap.String("event", ev.Type),
			zap.Int64("app_id", appID))
		return out, nil
	}
}

// revoke 处理"平台侧已撤销授权 / 已删号"：解除绑定。
//
// 这里刻意【不复用】binding.Service.Unbind，因为后者有一条业务规则：
// "不能解绑最后一个登录方式"。那条规则保护的是【用户误操作】，
// 而平台侧的撤销是用户在三方那里主动做的，平台是权威来源——
// 我们若为了保护"最后一个登录方式"而拒绝执行，本地状态就与平台不一致了：
// 用户下次点击 Apple 登录会直接失败，而我们的库里还显示"已绑定"。
//
// 正确做法是照做，并把"这是最后一个登录方式"作为高风险信号写进审计，
// 让业务侧据此引导用户改用其它方式登录或重新授权。
func (s *Service) revoke(ctx context.Context, appID int64, providerAppID, scene string, ev *provider.CallbackEvent, now time.Time, out *Output) (*Output, error) {
	if ev.OpenID == "" {
		out.Reason = "missing_open_id"
		s.log.Warn("撤销类通知缺少 open_id，无法定位身份",
			zap.Int64("app_id", appID), zap.String("event", ev.Type))
		return out, nil
	}

	idn, err := s.deps.Identities.FindByOpenID(ctx, identity.FindQuery{
		AppID:         appID,
		Platform:      ev.Platform,
		ProviderAppID: providerAppID,
		OpenID:        ev.OpenID,
	})
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// 身份不存在是【正常情况】：用户可能从未在本应用完成登录，
			// 平台仍然会推送通知（如账号删除）。回 2xx 让它停止重投。
			out.Reason = "identity_not_found"
			s.log.Info("通知对应的身份不存在，忽略",
				zap.Int64("app_id", appID),
				zap.String("event", ev.Type))
			return out, nil
		}
		return nil, err
	}
	out.IdentityID = idn.ID

	b, err := s.deps.Bindings.FindActiveByIdentity(ctx, appID, idn.ID)
	if err != nil {
		if errors.Is(err, domainbinding.ErrNotFound) {
			out.Reason = "binding_already_unbound"
			return out, nil
		}
		return nil, err
	}
	out.ExternalUserID = b.ExternalUserID

	if err := s.deps.Bindings.Unbind(ctx, appID, idn.ID, now); err != nil {
		if errors.Is(err, domainbinding.ErrNotFound) {
			// 并发重复投递：另一条通知已经解绑了。
			out.Reason = "binding_already_unbound"
			return out, nil
		}
		return nil, err
	}

	// 判断是否已成为"零绑定"账号：这是需要业务侧介入的高风险状态。
	remaining, err := s.deps.Bindings.CountActive(ctx, appID, b.ExternalUserID)
	if err != nil {
		// 计数失败不影响解绑结果，只降低审计信息量。
		s.log.Warn("统计剩余绑定数失败", zap.Error(err))
	}

	out.Handled = true
	s.emitAudit(ctx, appID, b.ExternalUserID, b.ExternalUserID, scene, audit.ActionUnbind, audit.ResultSuccess, map[string]any{
		"source":          "platform_notify",
		"event":           ev.Type,
		"identity_id":     idn.ID,
		"open_id":         ev.OpenID,
		"occurred_at":     ev.OccurredAt,
		"remaining_binds": remaining,
		"zero_binding":    remaining == 0,
	}, now)

	if remaining == 0 {
		s.log.Warn("平台撤销授权导致账号失去全部登录方式，需业务侧引导用户重新授权",
			zap.Int64("app_id", appID),
			zap.String("external_user_id", b.ExternalUserID),
			zap.String("event", ev.Type))
	}
	return out, nil
}

// emitAudit 写审计。审计失败不阻断主流程（audit.Writer 的契约）。
func (s *Service) emitAudit(ctx context.Context, appID int64, externalUserID, _ string, scene string, action, result string, detail map[string]any, at time.Time) {
	auditx.Emit(ctx, s.deps.Audit, s.log, &audit.Event{
		AppID:          appID,
		ExternalUserID: externalUserID,
		Scene:          scene,
		Action:         action,
		Result:         result,
		TraceID:        reqmeta.TraceID(ctx),
		Detail:         detail,
		At:             at,
	})
}
