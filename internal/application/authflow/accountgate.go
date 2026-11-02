// accountgate.go 是"已绑定用户登录时向用户中心回源核对"的闸门。
//
// 背景：绑定（oauth_bindings）存在本服务，账号主数据存在用户中心。主路径
// （FindActiveByIdentity 命中）原先签发令牌时【完全不问用户中心】，于是：
//
//  1. 账号在用户中心被停用/注销后，用户仍能登录，直到本地绑定被清理为止；
//  2. 用户在平台侧换了手机号，本服务的凭据与用户中心的账号长期不一致，
//     直到下一次合并或人工处理——而 J 组的漂移记录只会事后变多。
//
// 这两个都是"数据分叉"，不是性能问题。所以在这里补一次回源，并且明确
// 划清代价：
//
//	每次老用户登录多一次用户中心调用（本地缓存刻意不做，见下）；
//	用户中心不可用时按配置决定放行还是拒绝（架构 §6.2 选的是拒绝）。
//
// 为什么不做短 TTL 缓存：缓存会把"账号刚被停用"的生效时间从 0 变成 TTL，
// 而停用通常出于安全原因；为了省一次亚毫秒的单行查询引入一个"停用不立即
// 生效"的窗口，收益与风险不成比例。
package authflow

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// defaultAccountCheckTimeout 是单次回源核对的超时。
//
// 取 1s 而不是登录链路整体的 3s：这一步是"核对"，不是"必经的业务动作"。
// 让它长时间占着请求，只会把用户中心的慢，转换成用户看到的"登录转圈"。
const defaultAccountCheckTimeout = time.Second

// gateBoundAccount 在签发令牌前核对目标账号，并按需要修正平台侧凭证变更。
//
// 返回 nil 表示可以继续登录；返回错误表示必须拒绝（调用方负责审计与回跳）。
func (s *Service) gateBoundAccount(
	ctx context.Context,
	app *tenant.Application,
	b *binding.Binding,
	accClaims []account.Claim,
) error {
	if !s.cfg.AccountCheck.Enabled {
		return nil
	}

	callCtx, cancel := context.WithTimeout(ctx, s.accountCheckTimeout())
	defer cancel()

	acc, err := s.deps.Accounts.Get(callCtx, app.AppCode, b.ExternalUserID)
	if err != nil {
		return s.handleAccountLookupError(ctx, app, b, err)
	}
	if acc == nil {
		// 实现方不该返回 (nil, nil)，但真发生了也不能继续——否则后面
		// 会以 nil 解引用崩在签发链路上，表现为 500 而不是可读的拒绝。
		return errs.New(errs.CodeAccountUnavailable, "用户中心返回了空账号")
	}

	if acc.Status != account.StatusActive {
		// 冻结与注销都拒绝登录。这里不做"注销还能登录一次"的宽容：
		// 用户中心已经给出明确状态，再签令牌等于让本服务推翻对方的判断。
		s.logGateRejected(app, b, acc.Status)
		return errs.New(errs.CodeForbidden, "该账号已被停用或注销，无法登录").
			WithDetail("status", string(acc.Status))
	}

	// 状态没问题才做凭证修正：对一个不能登录的账号换绑没有意义。
	s.syncPlatformClaims(ctx, app, acc, accClaims)
	return nil
}

// handleAccountLookupError 决定"查不到/查不了"时是否放行。
func (s *Service) handleAccountLookupError(
	ctx context.Context,
	app *tenant.Application,
	b *binding.Binding,
	err error,
) error {
	// 明确答案：账号不存在。本地还留着活跃绑定，说明两边已经分叉。
	// 这种情况放行只会让业务方拿到一个指向不存在账号的令牌，必须拒绝。
	if errors.Is(err, account.ErrNotFound) {
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("绑定指向的账号在用户中心不存在，拒绝登录",
				zap.String("app_code", app.AppCode),
				zap.String("user_id", b.ExternalUserID),
				zap.Int64("identity_id", b.IdentityID))
		}
		return errs.New(errs.CodeAccountNotFound,
			"账号在用户中心已不存在，请联系业务方重新绑定").
			WithDetail("user_id", b.ExternalUserID)
	}

	// 没有答案：对端超时/5xx/网络不可达。此时【无法确认账号是否被停用】。
	//
	// 架构 §6.2 选择快速失败：不知道状态就不签发令牌。代价是把用户中心的
	// 可用性直接传给了登录链路——这是有意的取舍，不是疏漏。
	// 部署侧若判断"登录本身比封禁更关键"，可以打开 allow_on_unavailable。
	if s.cfg.AccountCheck.AllowOnUnavailable {
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("用户中心不可用，按配置放行登录（无法校验账号状态）",
				zap.String("app_code", app.AppCode),
				zap.String("user_id", b.ExternalUserID),
				zap.Error(err))
		}
		return nil
	}

	if s.deps.Logger != nil {
		s.deps.Logger.Warn("用户中心不可用，拒绝登录（结构 §6.2 的快速失败）",
			zap.String("app_code", app.AppCode),
			zap.String("user_id", b.ExternalUserID),
			zap.Error(err))
	}
	// 不可用是可重试的：业务方稍后重试就能登进来，不要把用户引向"账号有问题"。
	return errs.New(errs.CodeAccountUnavailable,
		"用户中心暂时不可用，无法确认账号状态，请稍后重试").
		WithDetail("cause", errs.CodeOf(err))
}

// syncPlatformClaims 把"平台这次证明的凭证"同步到用户中心。
//
// 场景：用户在微信里换了手机号，平台这次返回的是新号，而用户中心的账号
// 还挂着旧号。不换的话，下一次按手机号归并就会落到旧号上（找不到人或
// 找到别人），J 组的漂移记录也会持续增加。
//
// 三条纪律：
//
//  1. 只在平台明确给出凭证时动，且只动同一类型——不猜、不补。
//  2. 失败不阻断登录。换绑是"修正数据"，不是登录的前提；把它变成登录
//     的硬依赖，会让一次对端 409 变成用户登不进来。
//  3. 日志不写凭证值（手机号是 PII），只记类型与账号标识。
func (s *Service) syncPlatformClaims(
	ctx context.Context,
	app *tenant.Application,
	acc *account.Account,
	accClaims []account.Claim,
) {
	if len(accClaims) == 0 {
		return
	}
	replacer, ok := s.deps.Accounts.(account.ClaimReplacer)
	if !ok {
		// 桩实现与部分假对端没有换绑能力。这不是错误：能力在编译期就可知，
		// 缺了就跳过，而不是每次登录都报一次 NOT_SUPPORTED。
		return
	}

	for _, c := range accClaims {
		old := findAccountClaim(acc.Claims, c.Type)
		if old == nil {
			// 账号本来就没有这类凭证。补一条需要"新增凭证"的能力，
			// 而契约里只有 Create 与 Replace——不在这里越权造语义。
			continue
		}
		// 两边都归一化后再比：平台可能返回 +86 前缀或大写邮箱，
		// 直接比字符串会导致每次登录都发一次"换了但没换"的请求。
		if identity.Normalize(c.Type, old.Value) == identity.Normalize(c.Type, c.Value) {
			continue
		}

		repCtx, cancel := context.WithTimeout(ctx, s.accountCheckTimeout())
		_, repErr := replacer.ReplaceClaim(repCtx, account.ReplaceClaimRequest{
			AppKey: app.AppCode,
			UserID: acc.UserID,
			Claim:  c,
		})
		cancel()

		switch {
		case repErr == nil:
			if s.deps.Logger != nil {
				s.deps.Logger.Info("平台侧凭证已变更，已调用用户中心换绑",
					zap.String("app_code", app.AppCode),
					zap.String("user_id", acc.UserID),
					zap.String("claim_type", c.Type),
					zap.String("source", c.Source))
			}
		case errs.CodeOf(repErr) == errs.CodeBindIdentityTaken:
			// 新号码已经被另一个账号占用。此时换绑不能成功，但登录本身
			// 仍然有效——拒绝登录会让用户既进不去、又不知道号码在谁名下。
			// 留下 Warn 供客服按 user_id 排查，用户侧由业务方引导合并。
			if s.deps.Logger != nil {
				s.deps.Logger.Warn("平台侧凭证已被其他账号占用，跳过换绑（登录继续）",
					zap.String("app_code", app.AppCode),
					zap.String("user_id", acc.UserID),
					zap.String("claim_type", c.Type))
			}
		default:
			if s.deps.Logger != nil {
				s.deps.Logger.Warn("调用用户中心换绑失败，登录继续（数据待下一轮修正）",
					zap.String("app_code", app.AppCode),
					zap.String("user_id", acc.UserID),
					zap.String("claim_type", c.Type),
					zap.Error(repErr))
			}
		}
	}
}

// findAccountClaim 找某类型的活跃凭证（用户中心返回的视图里只有活跃凭证）。
func findAccountClaim(claims []account.Claim, claimType string) *account.Claim {
	for i := range claims {
		if claims[i].Type == claimType {
			return &claims[i]
		}
	}
	return nil
}

func (s *Service) accountCheckTimeout() time.Duration {
	if s.cfg.AccountCheck.Timeout > 0 {
		return s.cfg.AccountCheck.Timeout
	}
	return defaultAccountCheckTimeout
}

func (s *Service) logGateRejected(app *tenant.Application, b *binding.Binding, status account.Status) {
	if s.deps.Logger == nil {
		return
	}
	s.deps.Logger.Warn("账号状态非 active，拒绝登录",
		zap.String("app_code", app.AppCode),
		zap.String("user_id", b.ExternalUserID),
		zap.Int64("identity_id", b.IdentityID),
		zap.String("status", string(status)))
}
