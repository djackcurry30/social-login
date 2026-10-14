package authflow

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/alex/social-login/internal/domain/account"
	"github.com/alex/social-login/internal/domain/audit"
	"github.com/alex/social-login/internal/domain/binding"
	"github.com/alex/social-login/internal/domain/identity"
	"github.com/alex/social-login/internal/domain/provider"
	"github.com/alex/social-login/internal/domain/tenant"
	"github.com/alex/social-login/internal/domain/ticket"
	"github.com/alex/social-login/internal/pkg/auditx"
	"github.com/alex/social-login/internal/pkg/errs"
	"github.com/alex/social-login/internal/pkg/ids"
	"github.com/alex/social-login/internal/pkg/reqmeta"
)

// finishLogin 处理 login 模式的分支（架构 §7.1 的决策流程）。
//
// accClaims 是本次授权中平台已验证的凭证明文，只在需要调用户中心 Create 时使用。
// claimConflicts 是"该凭证已被另一身份验证过"的条数，仅用于 detect_only 提示。
func (s *Service) finishLogin(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	out *CallbackOutput,
	accClaims []account.Claim,
	claimConflicts int,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	b, err := s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, idn.ID)
	switch {
	case err == nil:
		// 已有活跃绑定：直接登录该账号，这是最常见的主路径。
		return s.issueAuthCode(ctx, app, tc, idn, b.ExternalUserID,
			identity.ScopeOpenIDProfile, out, audit.ResultSuccess, meta, started)

	case errors.Is(err, binding.ErrNotFound):
		// 未绑定分支（约束 C4）。

	default:
		return nil, err
	}

	// detect_only：只读判定、不写任何数据，检测到"同手机号已有账号"时返回提示，
	// 由前端引导用户主动合并。这个档位解决了 v0.7 的一处自相矛盾——
	// confirm 模式既声明"不读 claim"又声明"可检测同手机号"。
	if app.Policy.Merge.OnLogin == tenant.OnLoginDetectOnly && claimConflicts > 0 {
		out.Hint = "same_claim_exists"
	}

	switch app.Policy.OnUnboundLogin {
	case tenant.OnUnboundAutoCreate:
		return s.autoCreateAndBind(ctx, app, tc, idn, out, accClaims, meta, started)

	case tenant.OnUnboundSessionOnly:
		// 签发受限令牌：身份可信但尚未注册，业务方只允许走注册引导流程。
		out.Scope = identity.ScopeIdentityOnly
		return s.issueAuthCode(ctx, app, tc, idn, "",
			identity.ScopeIdentityOnly, out, audit.ResultSuccess, meta, started)

	default:
		// need_register（默认）：本服务无法自己产出账号，返回绑定票据让业务方引导注册。
		return s.needRegister(ctx, app, tc, idn, out, meta, started)
	}
}

// needRegister 走"引导注册"分支，返回一次性 bind_ticket。
func (s *Service) needRegister(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	out *CallbackOutput,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	bt := &ticket.BindTicket{
		Ticket:     ids.New(ids.PrefixBindTick),
		AppID:      app.ID,
		AppCode:    app.AppCode,
		IdentityID: idn.ID,
		Platform:   tc.Platform,
		Scene:      tc.Scene,
		Profile:    out.Profile,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.deps.Tickets.SaveBindTicket(ctx, bt, ticket.TTLBindTicket); err != nil {
		return nil, err
	}

	out.NeedRegister = true
	out.BindTicket = bt.Ticket
	out.Scope = identity.ScopeIdentityOnly

	q := url.Values{}
	q.Set("error", string(errs.CodeAuthNeedRegister))
	q.Set("error_description", "该三方身份尚未绑定账号，请先完成注册或登录")
	q.Set("bind_ticket", bt.Ticket)
	out.RedirectURL = buildRedirect(tc, q)

	s.auditLogin(ctx, app.ID, idn.ID, "", tc, audit.ResultFailure,
		errs.CodeAuthNeedRegister, meta, started)
	return out, nil
}

// autoCreateAndBind 走 on_unbound_login=auto_create 分支。
//
// ⚠️ 这条路径要求用户中心提供 Create 能力。若用户中心不提供，应把配置改成
// need_register——否则首次登录会直接失败。
func (s *Service) autoCreateAndBind(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	out *CallbackOutput,
	accClaims []account.Claim,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	acc, err := s.deps.Accounts.Create(ctx, account.CreateRequest{
		Claims:    accClaims,
		Nickname:  profileString(out.Profile, "nickname"),
		AvatarURL: profileString(out.Profile, "avatar_url"),
		// 幂等键固定可按 (app, identity) 推导：同一个三方身份的重复首次登录
		// 不应产生两个账号。
		IdempotencyKey: "first_login:" + app.AppCode + ":" + strconv.FormatInt(idn.ID, 10),
	})
	if err != nil {
		if errs.CodeOf(err) == errs.CodeAccountNotSupported {
			return nil, errs.New(errs.CodeAuthInvalidConfig,
				"当前应用配置为 on_unbound_login=auto_create，但用户中心未提供 Create 能力，请改为 need_register").
				WithDetail("app_id", app.AppCode)
		}
		return nil, err
	}

	_, alreadyExists, err := s.deps.Bindings.Activate(ctx, binding.ActivateInput{
		AppID:          app.ID,
		ExternalUserID: acc.UserID,
		IdentityID:     idn.ID,
		IsPrimary:      true,
		BindSource:     binding.SourceLogin,
		At:             time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	if alreadyExists {
		// 并发下被另一个请求抢先绑定，重查一次拿到真实归属。
		b, ferr := s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, idn.ID)
		if ferr != nil {
			return nil, ferr
		}
		return s.issueAuthCode(ctx, app, tc, idn, b.ExternalUserID,
			identity.ScopeOpenIDProfile, out, audit.ResultSuccess, meta, started)
	}
	return s.issueAuthCode(ctx, app, tc, idn, acc.UserID,
		identity.ScopeOpenIDProfile, out, audit.ResultSuccess, meta, started)
}

// finishBind 处理 bind 模式：把三方身份绑到当前登录账号（约束 C5 的引导绑定）。
func (s *Service) finishBind(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	out *CallbackOutput,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	target := tc.BindExternalUserID
	if target == "" {
		return nil, errs.New(errs.CodeInternal, "绑定模式缺少目标账号（票据异常）")
	}

	b, err := s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, idn.ID)
	switch {
	case err == nil:
		if b.ExternalUserID == target {
			// 幂等：已经绑在目标账号上，重复操作直接成功。
			return s.issueAuthCode(ctx, app, tc, idn, target,
				identity.ScopeOpenIDProfile, out, audit.ResultSuccess, meta, started)
		}
		return s.bindConflict(ctx, app, tc, idn, b, out, meta, started)

	case errors.Is(err, binding.ErrNotFound):
		_, already, actErr := s.deps.Bindings.Activate(ctx, binding.ActivateInput{
			AppID:          app.ID,
			ExternalUserID: target,
			IdentityID:     idn.ID,
			BindSource:     binding.SourceExplicit,
			At:             time.Now().UTC(),
		})
		if actErr != nil {
			return nil, actErr
		}
		if already {
			// 并发下被抢绑，按冲突处理。
			cur, ferr := s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, idn.ID)
			if ferr != nil {
				return nil, ferr
			}
			return s.bindConflict(ctx, app, tc, idn, cur, out, meta, started)
		}
		return s.issueAuthCode(ctx, app, tc, idn, target,
			identity.ScopeOpenIDProfile, out, audit.ResultSuccess, meta, started)

	default:
		return nil, err
	}
}

// bindConflict 处理"该身份已被另一个账号占用"。
//
// 这是需求 R1 的主场景：用户先在小程序登录得到账号 B，之后在 App 登录得到
// 账号 C，在 C 里点"绑定微信小程序"时必然命中这里。
//
// ⚠️ 当前状态：三种 merge mode 的合并链路属于第三期交付。第一期在此统一返回
// BIND.IDENTITY_TAKEN，并在 details 里带上 merge_mode 与 pending 标记，
// 由接入方展示"该渠道已绑定其他账号"。第三期会按 mode 分叉到
// verify_then_merge / auto_merge（架构 §7.2、§7.3）。
func (s *Service) bindConflict(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	existing *binding.Binding,
	out *CallbackOutput,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	if s.deps.Logger != nil {
		s.deps.Logger.Warn("绑定冲突：合并链路尚未交付（第三期）",
			zap.String("app_code", app.AppCode),
			zap.String("merge_mode", app.Policy.Merge.Mode),
			zap.Int64("app_id", app.ID),
			zap.Int64("identity_id", idn.ID),
			zap.String("occupied_by", existing.ExternalUserID))
	}

	code := errs.CodeBindIdentityTaken
	err := errs.New(code, "该三方身份已绑定其他账号").
		WithDetail("merge_mode", app.Policy.Merge.Mode).
		WithDetail("pending_feature", "merge").
		WithDetail("action", "请改用原账号登录，或等待合并能力上线后走验证合并")

	s.auditLogin(ctx, app.ID, idn.ID, existing.ExternalUserID, tc, audit.ResultFailure, code, meta, started)
	_ = out
	return nil, err
}

// issueAuthCode 生成一次性 auth_code 并拼出回跳地址。
func (s *Service) issueAuthCode(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	externalUserID string,
	scope string,
	out *CallbackOutput,
	result string,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	ac := &ticket.AuthCode{
		Code:           ids.New(ids.PrefixAuthCode),
		AppID:          app.ID,
		AppCode:        app.AppCode,
		ExternalUserID: externalUserID,
		IdentityID:     idn.ID,
		Mode:           tc.Mode,
		Scope:          scope,
		AMR:            ticket.AMR(tc.Platform, tc.Scene),
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.deps.Tickets.SaveAuthCode(ctx, ac, ticket.TTLAuthCode); err != nil {
		return nil, err
	}

	out.AuthCode = ac.Code
	out.ExternalUserID = externalUserID
	out.Scope = scope

	q := url.Values{}
	q.Set("code", ac.Code)
	out.RedirectURL = buildRedirect(tc, q)

	s.auditLogin(ctx, app.ID, idn.ID, externalUserID, tc, result, "", meta, started)
	return out, nil
}

// persistClaims 把三方返回的可信凭证写入 identity_claims。
//
// 返回两个列表：
//   - persisted：本次成功写入/已存在的凭证
//   - conflicts：该凭证已被【另一个身份】验证过——这不是错误，而是需求 R1
//     要处理的状态（同一手机号出现在两个身份上），因此不阻断登录，
//     只作为提示交给业务方。
func (s *Service) persistClaims(
	ctx context.Context,
	appID, identityID int64,
	u *provider.ExternalUser,
) (persisted []identity.Claim, conflicts []identity.Claim, err error) {
	type candidate struct {
		claimType string
		value     string
		source    string
	}

	candidates := make([]candidate, 0, 2)
	if u.Phone != "" && identity.IsTrustedSource(u.PhoneVerifiedBy) {
		candidates = append(candidates, candidate{identity.ClaimTypePhone, u.Phone, u.PhoneVerifiedBy})
	}
	if u.Email != "" && identity.IsTrustedSource(u.EmailVerifiedBy) {
		candidates = append(candidates, candidate{identity.ClaimTypeEmail, u.Email, u.EmailVerifiedBy})
	}
	if len(candidates) == 0 {
		return nil, nil, nil
	}

	now := time.Now().UTC()
	for _, c := range candidates {
		normalized := identity.Normalize(c.claimType, c.value)
		if normalized == "" {
			continue
		}
		in := identity.ClaimUpsertInput{
			AppID:      appID,
			IdentityID: identityID,
			Type:       c.claimType,
			// 注意：只存归一化后的哈希，明文不落库。
			// 哈希用应用级静态盐，否则"按手机号反查身份"会失效（见 crypto.ClaimHasher）。
			ValueHash: s.deps.Hasher.Hash(appID, c.claimType, normalized),
			Verified:  true,
			Source:    c.source,
			At:        now,
		}
		got, insErr := s.deps.Claims.Insert(ctx, in)
		if insErr == nil {
			persisted = append(persisted, *got)
			continue
		}
		if errors.Is(insErr, identity.ErrClaimTaken) {
			conflicts = append(conflicts, identity.Claim{
				AppID: appID, IdentityID: identityID,
				Type: c.claimType, ValueHash: in.ValueHash,
				Verified: true, Source: c.source,
			})
			continue
		}
		return persisted, conflicts, insErr
	}
	return persisted, conflicts, nil
}

// buildRedirect 在业务方回跳地址上追加查询参数。
func buildRedirect(tc *ticket.Context, extra url.Values) string {
	target, err := url.Parse(tc.RedirectURI)
	if err != nil {
		// 回跳地址在 Authorize 阶段已校验过，理论上不会失败。
		return tc.RedirectURI
	}
	q := target.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	// 业务侧透传的 state 始终原样回传，便于业务方关联自己发起的那次授权。
	if tc.BusinessState != "" {
		q.Set("state", tc.BusinessState)
	}
	target.RawQuery = q.Encode()
	return target.String()
}

// redirectError 把失败回跳业务方。
func (s *Service) redirectError(tc *ticket.Context, e *errs.Error) *CallbackOutput {
	q := url.Values{}
	q.Set("error", string(e.Code))
	q.Set("error_description", e.Message)
	if e.Retryable {
		q.Set("retryable", "true")
	}
	if len(e.Details) > 0 {
		// 只回传可安全外发的字段，绝不带出 provider_error 之外的内部细节。
		if v, ok := e.Details["provider_error"].(string); ok {
			q.Set("provider_error", v)
		}
	}
	return &CallbackOutput{
		RedirectURL:      buildRedirect(tc, q),
		ErrorCode:        string(e.Code),
		ErrorDescription: e.Message,
		Retryable:        e.Retryable,
		BusinessState:    tc.BusinessState,
		Platform:         tc.Platform,
		Scene:            tc.Scene,
	}
}

// auditLogin 写登录审计。失败只记日志（审计是旁路）。
func (s *Service) auditLogin(
	ctx context.Context,
	appID int64,
	identityID int64,
	externalUserID string,
	tc *ticket.Context,
	result string,
	errorCode errs.Code,
	meta reqmeta.Meta,
	started time.Time,
) {
	detail := map[string]any{
		"identity_id": identityID,
		"mode":        tc.Mode,
		"duration_ms": time.Since(started).Milliseconds(),
	}
	auditx.Emit(ctx, s.deps.Audit, s.deps.Logger, &audit.Event{
		AppID:          appID,
		ExternalUserID: externalUserID,
		Platform:       tc.Platform,
		Scene:          tc.Scene,
		Client:         tc.Client,
		Action:         audit.ActionLogin,
		Result:         result,
		ErrorCode:      string(errorCode),
		ClientIP:       meta.ClientIP,
		UserAgent:      meta.UserAgent,
		TraceID:        meta.TraceID,
		Detail:         detail,
		At:             time.Now().UTC(),
	})
}

// userAccountClaims 从三方用户信息构造用户中心需要的已验证凭证。
//
// 两个必须遵守的约束：
//  1. 只取【可信来源】的凭证。用户手填的（source=manual）不能作为"已验证"下发给
//     用户中心，否则等于在后端重新打开 R4 红线 1。
//  2. 明文只在本函数与 Create 调用之间存活，不写日志、不入快照
//     （profile 快照刻意不含明文手机号/邮箱）。
func userAccountClaims(u *provider.ExternalUser) []account.Claim {
	if u == nil {
		return nil
	}
	out := make([]account.Claim, 0, 2)
	if p := identity.NormalizePhone(u.Phone); p != "" && identity.IsTrustedSource(u.PhoneVerifiedBy) {
		out = append(out, account.Claim{
			Type:   identity.ClaimTypePhone,
			Value:  p,
			Source: u.PhoneVerifiedBy,
		})
	}
	if e := identity.NormalizeEmail(u.Email); e != "" && identity.IsTrustedSource(u.EmailVerifiedBy) {
		out = append(out, account.Claim{
			Type:   identity.ClaimTypeEmail,
			Value:  e,
			Source: u.EmailVerifiedBy,
		})
	}
	return out
}

func profileString(profile map[string]any, key string) string {
	if profile == nil {
		return ""
	}
	v, _ := profile[key].(string)
	return v
}
