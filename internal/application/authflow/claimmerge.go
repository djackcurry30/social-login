// claimmerge.go 实现 on_login = claim_verified 的登录期归并（§7.4 的 S2 行为）。
//
// 场景：用户先用微信小程序登录（账号 A，手机号由微信侧验证），之后在 App 里
// 用支付宝授权了同一个手机号。这个支付宝身份是全新的、没有绑定；按 C5 默认
// 应当走"引导注册"（need_register）。应用显式打开 claim_verified 后，语义变成
// "同一个人从不同渠道来，应该登进同一个账号"，于是把新身份挂到账号 A 上。
//
// 为什么不能简化成"按手机号字符串匹配"：
//
//  1. 依据必须是平台侧已验证的凭证（R4 红线 1）。手填手机号参与归并是直接的
//     账号劫持路径——攻击者注册时填上受害者的号码即可。
//  2. claim 表只记录"某次授权中平台证明过这个值"，账号当前的手机号权威源在
//     用户中心（§8.5 P0-6）。所以命中 claim 之后必须回源核对：用户换过号、
//     claim 尚未同步时，只看本地表会把新身份挂到一个已经不用这个号的账号上。
//  3. 跨平台（微信 ↔ 支付宝）两边手机号可能属于不同实名主体，默认关闭
//     （R4 红线 3），需要应用显式打开 allow_cross_platform_auto。
package authflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/auditx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// applePrivateRelaySuffix 是 Apple 的私密中继邮箱后缀。
//
// 它在同一 App 内对同一用户稳定，可以用于本应用内的归并；但它不是用户真实
// 邮箱，跨平台匹配会误命中（§7.5.3 红线 1 的特殊说明）。
const applePrivateRelaySuffix = "@privaterelay.appleid.com"

// resolvedClaim 是一条"经过全部校验、可以据此归并"的凭证。
type resolvedClaim struct {
	claim account.Claim
	from  *identity.Identity
	bind  *binding.Binding
	acc   *account.Account
	cross bool
}

// tryClaimMerge 用本次已验证的凭证把当前身份归并到既有账号。
//
// 返回 (nil, nil) 表示未命中——调用方应当继续走 on_unbound_login 分支。
//
// 两轮结构不是多余的：
//
//	第一轮  只读解析每条凭证指向哪个账号，收集结果
//	第二轮  确认全部指向同一个账号后，才执行归并
//
// 如果"命中第一条就直接归并"，而用户本次同时验证了手机号与邮箱、两者分别
// 指向账号 A 和 B，那么先遍历到哪条就替用户选哪个账号——那是随机的。
// 这种数据不一致只能交给人工判断，所以第一轮发现分歧就拒绝。
func (s *Service) tryClaimMerge(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	accClaims []account.Claim,
	out *CallbackOutput,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	if len(accClaims) == 0 {
		return nil, nil
	}

	resolved := make([]resolvedClaim, 0, len(accClaims))
	for _, c := range accClaims {
		r, ok, err := s.resolveClaim(ctx, app, idn, c)
		if err != nil {
			return nil, err
		}
		if ok {
			resolved = append(resolved, r)
		}
	}
	if len(resolved) == 0 {
		return nil, nil
	}

	for _, r := range resolved[1:] {
		if r.acc.UserID != resolved[0].acc.UserID {
			// 同一人的两条凭证指向两个账号：数据侧已不一致，不能替用户选。
			return nil, errs.New(errs.CodeAccountMultiple,
				"本次授权的多个凭证指向不同账号，已拒绝自动归并，请引导用户选择").
				WithDetail("claim_type", resolved[0].claim.Type).
				WithDetail("conflict_claim_type", r.claim.Type)
		}
	}

	return s.applyClaimMerge(ctx, app, tc, idn, resolved[0], out, meta, started)
}

// resolveClaim 校验单条凭证能否作为归并依据，能则返回目标账号。
//
// 这里集中了全部安全判定，顺序有讲究：先做零成本、不涉及外部调用的检查
// （本地 claim → 身份存在 → 跨平台红线），最后才回源用户中心。
func (s *Service) resolveClaim(
	ctx context.Context,
	app *tenant.Application,
	idn *identity.Identity,
	c account.Claim,
) (resolvedClaim, bool, error) {
	normalized := identity.Normalize(c.Type, c.Value)
	if normalized == "" {
		return resolvedClaim{}, false, nil
	}

	hash := s.deps.Hasher.Hash(app.ID, c.Type, normalized)
	claim, err := s.deps.Claims.FindVerified(ctx, app.ID, c.Type, hash)
	if errors.Is(err, identity.ErrNotFound) {
		return resolvedClaim{}, false, nil
	}
	if err != nil {
		return resolvedClaim{}, false, err
	}
	// 命中自己：这个凭证本来就属于当前身份（例如同一身份第二次登录），
	// 不需要任何归并动作。
	if claim.IdentityID == idn.ID {
		return resolvedClaim{}, false, nil
	}

	other, err := s.deps.Identities.FindByID(ctx, app.ID, claim.IdentityID)
	if errors.Is(err, identity.ErrNotFound) {
		// claim 指向的身份已不存在（数据清理 / 手工删除）。
		// 不归并也不报错：这条 claim 已经没用，交给 J 组的漂移排查。
		s.noteSkip(app, idn, c, "claim 指向的身份不存在")
		return resolvedClaim{}, false, nil
	}
	if err != nil {
		return resolvedClaim{}, false, err
	}

	crossPlatform := other.Platform != idn.Platform
	if crossPlatform && !app.Policy.Merge.AllowCrossPlatformAuto {
		// R4 红线 3：跨平台自动归并默认关闭。两边手机号可能属于不同实名主体，
		// 自动合并等于替用户做了一次他可能不同意的账号绑定。
		s.noteSkip(app, idn, c, "跨平台自动归并未开启（merge.allow_cross_platform_auto=false）")
		return resolvedClaim{}, false, nil
	}
	if crossPlatform && c.Type == identity.ClaimTypeEmail &&
		strings.HasSuffix(strings.ToLower(normalized), applePrivateRelaySuffix) {
		// Apple 私密中继邮箱只在本应用内稳定，不能作为跨平台依据。
		s.noteSkip(app, idn, c, "Apple 私密中继邮箱不支持跨平台归并")
		return resolvedClaim{}, false, nil
	}

	// 目标身份必须有活跃绑定——没有绑定就不是"已有账号"，归并过去无处可去。
	b, err := s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, other.ID)
	if errors.Is(err, binding.ErrNotFound) {
		return resolvedClaim{}, false, nil
	}
	if err != nil {
		return resolvedClaim{}, false, err
	}

	// P0-6 回源核对：claim 表是"某次证明过"，不是"现在仍然如此"。
	acc, err := s.deps.Accounts.GetByClaim(ctx, c)
	switch {
	case errors.Is(err, account.ErrNotFound):
		s.noteSkip(app, idn, c, "用户中心未找到持有该凭证的账号")
		return resolvedClaim{}, false, nil
	case errors.Is(err, account.ErrMultipleAccounts):
		// 命中多个账号：不能择一（§7.4 护栏），也不该静默放行。
		return resolvedClaim{}, false, errs.New(errs.CodeAccountMultiple,
			"该凭证在用户中心命中多个账号，已拒绝自动归并").
			WithDetail("claim_type", c.Type)
	case err != nil:
		// 用户中心不可用：快速失败。登录链路无法确认账号归属时，
		// 宁可让本次登录失败，也不能猜一个账号进去（§6.2）。
		return resolvedClaim{}, false, err
	}

	if acc.UserID != b.ExternalUserID {
		// 本地绑定与用户中心不一致：可能 merge 改挂过、也可能 claim 已漂移。
		// 这是需要人工排查的状态，自动归并会把错误放大。
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("凭证归并跳过：用户中心账号与本地绑定不一致",
				zap.Int64("app_id", app.ID),
				zap.Int64("identity_id", idn.ID),
				zap.Int64("claim_identity_id", other.ID),
				zap.String("account_user_id", acc.UserID),
				zap.String("bound_user_id", b.ExternalUserID))
		}
		return resolvedClaim{}, false, nil
	}
	if acc.Status != account.StatusActive {
		// 冻结 / 注销的账号不能作为归并目标：那等于让用户登进一个已被停用的账号。
		s.noteSkip(app, idn, c, "目标账号状态非 active")
		return resolvedClaim{}, false, nil
	}

	return resolvedClaim{claim: c, from: other, bind: b, acc: acc, cross: crossPlatform}, true, nil
}

// applyClaimMerge 执行归并：建绑定 → 审计 → 签发 auth_code。
//
// 归并的本质是【建一条绑定】，不是迁移账号数据：当前 identity 从来没有绑定过，
// 它只是"新渠道上的同一个身份"。所以这里不需要 merge_operations、不需要补偿，
// 也不会动既有账号的任何数据。
func (s *Service) applyClaimMerge(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	r resolvedClaim,
	out *CallbackOutput,
	meta reqmeta.Meta,
	started time.Time,
) (*CallbackOutput, error) {
	now := time.Now().UTC()
	nb, already, err := s.deps.Bindings.Activate(ctx, binding.ActivateInput{
		AppID:          app.ID,
		ExternalUserID: r.acc.UserID,
		IdentityID:     idn.ID,
		IsPrimary:      false,
		BindSource:     binding.SourceMerge,
		At:             now,
	})
	if err != nil {
		return nil, err
	}
	if already {
		// 并发下另一个请求先把这条 identity 绑走了。
		// 读回来看绑到了谁：一致才继续，不一致说明被别人抢占，不能登进去。
		nb, err = s.deps.Bindings.FindActiveByIdentity(ctx, app.ID, idn.ID)
		if err != nil {
			return nil, err
		}
		if nb.ExternalUserID != r.acc.UserID {
			return nil, nil
		}
	}

	if s.deps.Logger != nil {
		s.deps.Logger.Info("登录期凭证归并完成（on_login=claim_verified）",
			zap.Int64("app_id", app.ID),
			zap.Int64("identity_id", idn.ID),
			zap.Int64("merged_into_identity_id", r.from.ID),
			zap.String("external_user_id", r.acc.UserID),
			zap.String("claim_type", r.claim.Type),
			zap.String("claim_source", r.claim.Source),
			zap.Bool("cross_platform", r.cross))
	}
	s.auditClaimMerge(ctx, app, tc, idn, r, nb, meta, started)

	return s.issueAuthCode(ctx, app, tc, idn, r.acc.UserID,
		identity.ScopeOpenIDProfile, out, audit.ResultSuccess, meta, started)
}

// auditClaimMerge 记录一条 merge 类型的审计。
//
// 用 ActionMerge 而不是 ActionLogin：对业务方与合规来说，这是一次"身份被挂到
// 某个既有账号上"的事实，需要能按 merge 检索出来；混在 login 里就查不到了。
// 明细里不放凭证明文——审计库的访问门槛低于用户中心，手机号不该出现在这里。
func (s *Service) auditClaimMerge(
	ctx context.Context,
	app *tenant.Application,
	tc *ticket.Context,
	idn *identity.Identity,
	r resolvedClaim,
	nb *binding.Binding,
	meta reqmeta.Meta,
	started time.Time,
) {
	bindingID := int64(0)
	if nb != nil {
		bindingID = nb.ID
	}
	auditx.Emit(ctx, s.deps.Audit, s.deps.Logger, &audit.Event{
		AppID:          app.ID,
		ExternalUserID: r.acc.UserID,
		Platform:       idn.Platform,
		Scene:          tc.Scene,
		Client:         tc.Client,
		Action:         audit.ActionMerge,
		Result:         audit.ResultSuccess,
		ClientIP:       meta.ClientIP,
		UserAgent:      meta.UserAgent,
		TraceID:        meta.TraceID,
		Detail: map[string]any{
			"reason":               "claim_verified",
			"identity_id":          idn.ID,
			"merged_into_identity": r.from.ID,
			"merged_into_platform": r.from.Platform,
			"binding_id":           bindingID,
			"claim_type":           r.claim.Type,
			"claim_source":         r.claim.Source,
			"cross_platform":       r.cross,
			"duration_ms":          time.Since(started).Milliseconds(),
		},
		At: time.Now().UTC(),
	})
}

// noteSkip 记录"本可以归并但被跳过"的原因。
//
// 这类日志是 J 组（凭证一致性运维）的输入：用户反馈"我明明是同一个手机号，
// 怎么进了新账号"，排查第一步就是看这条日志说了什么。
func (s *Service) noteSkip(app *tenant.Application, idn *identity.Identity, c account.Claim, why string) {
	if s.deps.Logger == nil {
		return
	}
	s.deps.Logger.Info("凭证归并跳过",
		zap.Int64("app_id", app.ID),
		zap.Int64("identity_id", idn.ID),
		zap.String("platform", idn.Platform),
		zap.String("claim_type", c.Type),
		zap.String("claim_source", c.Source),
		zap.String("reason", why))
}
