// Package token 是本地令牌体系的用例层（架构 §8）。
//
// 令牌形态的分工（§8.1）是不能互换的：
//   - access_token：JWT（ES256），15 分钟，业务方本地验签、零网络开销。
//     代价是【撤销存在最长 15 分钟窗口】——这是设计权衡，不是缺陷。
//   - refresh_token：不透明随机串，30 天，查库比对哈希。换来的是可撤销能力。
//
// 二者的选择标准是"校验频率 vs 撤销时效"：高频校验的一侧优先免网络开销，
// 低频但需要撤销能力的一侧优先可撤销。
package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/auditx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/pkg/jwtkit"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// AccessTokenTTL 是 access_token 有效期（架构 §8.1）。
//
// 15 分钟不是随意取的：它同时是"撤销生效的最坏延迟"。调小会让业务方频繁刷新，
// 调大则会在账号劫持场景下延长攻击窗口。
const AccessTokenTTL = 15 * time.Minute

// RefreshTokenTTL 是 refresh_token 有效期（30 天）。
const RefreshTokenTTL = session.TTLRefreshToken

// Config 是令牌服务配置。
type Config struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// DefaultScope 是正常登录的默认 scope。
	DefaultScope string
}

// Deps 是依赖集合。
type Deps struct {
	Signer   *jwtkit.Signer
	Tickets  ticket.Store
	Sessions session.Repository
	// Revocation 是高危撤销名单（§8.4）。为 nil 时 check_revocation
	// 会退化为"仅本地验签"，与未接黑名单的部署语义一致。
	Revocation session.RevocationList
	Tenant     *tenantconfig.Service
	Audit      audit.Writer
	Logger     *zap.Logger
}

// Service 提供令牌签发、轮转、校验与撤销。
type Service struct {
	cfg  Config
	deps Deps
}

// New 构造服务。
func New(cfg Config, deps Deps) *Service {
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = AccessTokenTTL
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = RefreshTokenTTL
	}
	if cfg.DefaultScope == "" {
		cfg.DefaultScope = identity.ScopeOpenIDProfile
	}
	return &Service{cfg: cfg, deps: deps}
}

// Response 是令牌响应。
type Response struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        string   `json:"scope"`
	Subject      string   `json:"sub"`
	AMR          []string `json:"amr,omitempty"`
}

// ExchangeAuthCode 用一次性授权码换取令牌（grant_type=authorization_code）。
func (s *Service) ExchangeAuthCode(ctx context.Context, appCode, code, deviceID string) (*Response, error) {
	if code == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "缺少 code")
	}
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return nil, err
	}

	ac, err := s.deps.Tickets.ConsumeAuthCode(ctx, code)
	if err != nil {
		if errors.Is(err, ticket.ErrAuthCodeInvalid) {
			// 不区分"不存在"与"已使用"：区分会让攻击者用它做探测
			// （架构 §10.1 用户枚举的同类问题）。
			return nil, errs.New(errs.CodeAuthInvalidState,
				"授权码无效、已使用或已过期，请重新发起授权")
		}
		return nil, err
	}

	// client_id 校验：授权码只在签发它的应用内可用。
	// 这不是冗余检查——没有它，任何持有 app_secret 的应用都能用别人的 code 换令牌。
	if ac.AppID != app.ID {
		return nil, errs.New(errs.CodeUnauthorized, "授权码不属于当前应用")
	}

	subject := subjectOf(ac)
	return s.issue(ctx, issueInput{
		appID:          app.ID,
		appCode:        app.AppCode,
		subject:        subject,
		scope:          ac.Scope,
		amr:            ac.AMR,
		identityID:     ac.IdentityID,
		externalUserID: ac.ExternalUserID,
		deviceID:       deviceID,
		platform:       firstAMRPlatform(ac.AMR),
	})
}

// Refresh 轮转刷新令牌（grant_type=refresh_token）。
//
// 实现 RFC 6819 的 Refresh Token Rotation + Reuse Detection：
// 每次刷新签发新令牌并把旧令牌置为已撤销；若已撤销的令牌再次出现，
// 说明它极可能被窃取（攻击者与真实用户各持一份），此时撤销整条链并要求重新登录。
func (s *Service) Refresh(ctx context.Context, appCode, rawRefreshToken, deviceID string) (*Response, error) {
	if rawRefreshToken == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "缺少 refresh_token")
	}
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return nil, err
	}

	hash := session.HashToken(rawRefreshToken)
	rt, err := s.deps.Sessions.FindByHash(ctx, app.ID, hash)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return nil, errs.New(errs.CodeTokenInvalid, "refresh_token 无效")
		}
		return nil, err
	}

	now := time.Now().UTC()
	if rt.Revoked {
		// 重放检测：撤销整条会话链。
		n, revErr := s.deps.Sessions.RevokeChainFrom(ctx, app.ID, rt.ID, "reuse_detected")
		if revErr != nil && s.deps.Logger != nil {
			s.deps.Logger.Error("撤销令牌链失败",
				zap.Int64("app_id", app.ID), zap.Int64("token_id", rt.ID), zap.Error(revErr))
		}
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("检测到刷新令牌重放，已撤销整条会话链",
				zap.Int64("app_id", app.ID),
				zap.Int64("refresh_token_id", rt.ID),
				zap.Int64("revoked_count", int64(n)),
				zap.String("external_user_id", rt.ExternalUserID))
		}
		auditx.Emit(ctx, s.deps.Audit, s.deps.Logger, &audit.Event{
			AppID:          app.ID,
			ExternalUserID: rt.ExternalUserID,
			Action:         audit.ActionRevoke,
			Result:         audit.ResultFailure,
			ErrorCode:      string(errs.CodeTokenRevoked),
			TraceID:        reqmeta.TraceID(ctx),
			Detail:         map[string]any{"reason": "refresh_token_reuse_detected"},
			At:             now,
		})
		return nil, errs.New(errs.CodeTokenRevoked,
			"检测到令牌重放，该会话已全部失效，请重新登录")
	}
	if !rt.Valid(now) {
		return nil, errs.New(errs.CodeTokenExpired, "refresh_token 已过期")
	}

	// 轮转：签发新令牌，并让新令牌指向旧令牌（单向链，无需回写旧记录）。
	newRaw, err := s.newOpaqueToken()
	if err != nil {
		return nil, err
	}
	created, err := s.deps.Sessions.Create(ctx, session.CreateInput{
		AppID:          app.ID,
		ExternalUserID: rt.ExternalUserID,
		TokenHash:      session.HashToken(newRaw),
		DeviceID:       pick(deviceID, rt.DeviceID),
		Scope:          rt.Scope,
		ExpiresAt:      now.Add(s.cfg.RefreshTokenTTL),
		RotatedFrom:    &rt.ID,
		At:             now,
	})
	if err != nil {
		return nil, err
	}
	if err := s.deps.Sessions.Revoke(ctx, app.ID, rt.ID, "rotated"); err != nil {
		return nil, err
	}

	// 重新签发 access_token。scope 沿用原令牌，避免刷新时被悄悄提权。
	subject := rt.ExternalUserID
	if subject == "" {
		return nil, errs.New(errs.CodeTokenInvalid, "刷新令牌缺少主体信息")
	}
	accessToken, claims, err := s.deps.Signer.Issue(jwtkit.IssueInput{
		Subject:  subject,
		Audience: app.AppCode,
		Scope:    rt.Scope,
		TTL:      s.cfg.AccessTokenTTL,
	})
	if err != nil {
		return nil, err
	}
	_ = created

	return &Response{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: newRaw,
		Scope:        rt.Scope,
		Subject:      subject,
		AMR:          claims.AMR,
	}, nil
}

// IntrospectResult 是令牌校验结果。
type IntrospectResult struct {
	Active    bool
	Subject   string
	AppCode   string
	Scope     string
	AMR       []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	JWTID     string
}

// Introspect 校验访问令牌。
//
// 默认【纯本地验签】，不查任何远程状态——这是保住"业务方零网络开销"的关键。
// 仅当调用方传 checkRevocation=true 时才查 jti 黑名单（第四期实现），
// 用于改密、提现、绑定新渠道等安全敏感操作（架构 §8.4）。
func (s *Service) Introspect(ctx context.Context, appCode, accessToken string, checkRevocation bool) (*IntrospectResult, error) {
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return nil, err
	}
	claims, err := s.deps.Signer.Parse(accessToken)
	if err != nil {
		// 校验失败不返回错误而是 active=false，符合 RFC 7662 的约定：
		// introspect 的回答是"令牌是否有效"，而不是"校验过程是否成功"。
		return &IntrospectResult{Active: false}, nil
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != app.AppCode {
		return &IntrospectResult{Active: false}, nil
	}
	if checkRevocation && s.deps.Revocation == nil {
		// 调用方要的是强校验。没接黑名单就说没接，不能静默降级成纯本地验签——
		// 那会让"改密前先 check_revocation"这道防线看起来存在、实际不存在。
		return nil, errs.New(errs.CodeProviderNotSupported,
			"check_revocation 需要撤销名单（Redis），当前未装配")
	}
	if checkRevocation {
		// 高危撤销校验（§8.4）：jti 黑名单 + 账号级水位。
		//
		// 只在调用方显式要求时才查——绝大多数业务请求由业务方自行验签，
		// 不该为一次改密/提现之外的操作付出 Redis 往返。
		issuedAt := time.Time{}
		if claims.IssuedAt != nil {
			issuedAt = claims.IssuedAt.Time
		}
		revoked, rerr := session.Revoked(ctx, s.deps.Revocation,
			app.ID, claims.Subject, claims.ID, issuedAt)
		if rerr != nil {
			// 查不到黑名单就返回错误而不是 active=true：
			// 调用方要的是"强校验"，给不了就必须说给不了。
			return nil, rerr
		}
		if revoked {
			return &IntrospectResult{Active: false}, nil
		}
	}
	out := &IntrospectResult{
		Active:  true,
		Subject: claims.Subject,
		AppCode: app.AppCode,
		Scope:   claims.Scope,
		AMR:     claims.AMR,
		JWTID:   claims.ID,
	}
	if claims.ExpiresAt != nil {
		out.ExpiresAt = claims.ExpiresAt.Time
	}
	if claims.IssuedAt != nil {
		out.IssuedAt = claims.IssuedAt.Time
	}
	return out, nil
}

// Revoke 撤销令牌 / 登出。
//
// 分层撤销语义（架构 §8.4）：
//   - 传入 refresh_token → 撤销该设备会话
//   - 传入 access_token  → 普通登出场景下不做处理，等它自然过期（≤15 分钟）；
//     高危撤销需要 jti 黑名单，属第四期
//
// 返回值 revoked 表示实际撤销的令牌形态，便于调用方判断生效延迟。
func (s *Service) Revoke(ctx context.Context, appCode, rawToken, reason string) (string, error) {
	if rawToken == "" {
		return "", errs.New(errs.CodeInvalidRequest, "缺少待撤销的令牌")
	}
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return "", err
	}
	if reason == "" {
		reason = "user_logout"
	}

	rt, err := s.deps.Sessions.FindByHash(ctx, app.ID, session.HashToken(rawToken))
	if err == nil {
		if err := s.deps.Sessions.Revoke(ctx, app.ID, rt.ID, reason); err != nil {
			return "", err
		}
		auditx.Emit(ctx, s.deps.Audit, s.deps.Logger, &audit.Event{
			AppID:          app.ID,
			ExternalUserID: rt.ExternalUserID,
			Action:         audit.ActionRevoke,
			Result:         audit.ResultSuccess,
			TraceID:        reqmeta.TraceID(ctx),
			Detail:         map[string]any{"token_type": "refresh_token", "reason": reason},
			At:             time.Now().UTC(),
		})
		return "refresh_token", nil
	}
	if !errors.Is(err, session.ErrNotFound) {
		return "", err
	}

	// 不是 refresh_token：可能是 access_token。校验一下形态，
	// 避免把明显非法的输入当成"已处理"。
	if _, perr := s.deps.Signer.Parse(rawToken); perr != nil {
		return "", errs.New(errs.CodeTokenInvalid, "令牌无效，无法撤销")
	}
	return "access_token", nil
}

// --- 内部 ---

type issueInput struct {
	appID          int64
	appCode        string
	subject        string
	scope          string
	amr            []string
	identityID     int64
	externalUserID string
	deviceID       string
	platform       string
}

func (s *Service) issue(ctx context.Context, in issueInput) (*Response, error) {
	if in.scope == "" {
		in.scope = s.cfg.DefaultScope
	}
	accessToken, claims, err := s.deps.Signer.Issue(jwtkit.IssueInput{
		Subject:  in.subject,
		Audience: in.appCode,
		Scope:    in.scope,
		AMR:      in.amr,
		TTL:      s.cfg.AccessTokenTTL,
	})
	if err != nil {
		return nil, err
	}

	// identity_only 是"身份可信但尚未注册"的受限 scope，此时没有业务账号，
	// 因此不签发 refresh_token——没有账号可以刷新，签发它只会产生一个
	// 无法续期的死令牌。
	if in.scope == identity.ScopeIdentityOnly || in.externalUserID == "" {
		return &Response{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   int(s.cfg.AccessTokenTTL.Seconds()),
			Scope:       in.scope,
			Subject:     in.subject,
			AMR:         claims.AMR,
		}, nil
	}

	raw, err := s.newOpaqueToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err := s.deps.Sessions.Create(ctx, session.CreateInput{
		AppID:          in.appID,
		ExternalUserID: in.externalUserID,
		TokenHash:      session.HashToken(raw),
		DeviceID:       in.deviceID,
		Scope:          in.scope,
		ExpiresAt:      now.Add(s.cfg.RefreshTokenTTL),
		At:             now,
	}); err != nil {
		return nil, err
	}

	return &Response{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: raw,
		Scope:        in.scope,
		Subject:      in.subject,
		AMR:          claims.AMR,
	}, nil
}

// subjectOf 决定 JWT 的 sub 取值。
//
// 约束 C4 下 sub 直接用业务方账号标识，本服务不再生成一层别名——业务方本来就
// 知道自己的 userId，多一层映射只会让每次调用都要反查一次。
//
// 例外是 identity_only 分支：此时还没有业务账号，只能退化为身份标识
// （idn_<identityID>）。业务方看到这个前缀即应知道"此人尚未注册"。
func subjectOf(ac *ticket.AuthCode) string {
	if ac.ExternalUserID != "" {
		return ac.ExternalUserID
	}
	return "idn_" + strconv.FormatInt(ac.IdentityID, 10)
}

func (s *Service) newOpaqueToken() (string, error) {
	// 32 字节密码学随机数 → 不透明令牌。
	// 高熵使得"存哈希"是安全的：不存在被暴力枚举的可能，因此不需要慢哈希。
	buf, err := ids.RandomToken(32)
	if err != nil {
		return "", errs.Wrap(errs.CodeInternal, "生成刷新令牌失败", err)
	}
	return base64URL(buf), nil
}

func firstAMRPlatform(amr []string) string {
	if len(amr) == 0 {
		return ""
	}
	return amr[0]
}

func pick(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// constantTimeEqual 用于比较敏感串，避免时序侧信道。
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
