// Package accountclose 是账号注销（数据合规）的用例层。
//
// 约束 C4 下账号主数据在用户中心，本服务持有的是"这个三方身份绑到了哪个
// 账号"以及令牌。所以注销必然是一次跨服务编排：
//
//	用户中心关账号  →  本服务级联解除绑定 / 撤销令牌 / 清除凭证密文
//
// 【顺序不能反】。先清本地再关对端，一旦中途失败，用户中心里的账号仍然
// active，而本地已无绑定——他下次用微信登录会走"未绑定"分支，自动创建一个
// 新账号。用户以为自己注销了，实际得到的是"旧数据还在、外加一个空账号"。
// 反过来（先关对端）失败时，最坏情况是账号已 closed、本地绑定还在，
// 此时登录会被状态闸门拦下（AUTH.FORBIDDEN），不会复活，重试即可补齐本地。
//
// 本服务【不标记账号状态】（约束 C4）：status 的权威在用户中心。
// 这里只做三件事——关对端、断本地关联、抹掉本地 PII。
package accountclose

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	domainbinding "github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/auditx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// defaultAccessTTL 是撤销水位的 TTL，取 access_token 的有效期。
//
// 水位只需要覆盖"已经签发出去、还没自然过期的 access_token"：
// 过了这段时间，那批令牌本身就不被接受了，水位再留着没有意义。
const defaultAccessTTL = 15 * time.Minute

// AppResolver 只做一件事：按 app_code 解析出应用。
//
// 声明成接口而不是直接用 *tenantconfig.Service，是为了让注销流程可被单测
// 覆盖——这个流程的价值全在顺序与失败分支上（先关对端、级联失败不阻断），
// 那些分支必须能构造出来才测得到。
type AppResolver interface {
	Application(ctx context.Context, appCode string) (*tenant.Application, error)
}

// Deps 是依赖集合。
type Deps struct {
	Tenant   AppResolver
	Accounts account.Provider
	Bindings domainbinding.Repository
	// Identities 用于取绑定的渠道（平台），生成"去哪里撤销授权"的提示。
	// 为 nil 时提示退化为通用文案，注销本身不受影响。
	Identities identity.Repository
	Sessions   session.Repository
	// Revocation 是账号级撤销名单。为 nil 时跳过写水位并记 Warn：
	// 注销是合规动作，不能因为"没接黑名单"就整体失败——那会让用户的
	// 删除请求永远无法完成。但必须留下日志，因为这意味着已签发的
	// access_token 会继续有效到自然过期。
	Revocation session.RevocationList
	Claims     identity.ClaimRepository
	Audit      audit.Writer
	Logger     *zap.Logger
	// AccessTTL 留空取 15 分钟。
	AccessTTL time.Duration
}

// Service 实现账号注销。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(deps Deps) *Service {
	if deps.AccessTTL <= 0 {
		deps.AccessTTL = defaultAccessTTL
	}
	return &Service{deps: deps}
}

// Result 是注销结果。
//
// 字段全部是"实际发生了什么"，而不是"我们尝试了什么"：注销之后用户与客服
// 都会问"到底清掉了没有"，一个只回 {"closed":true} 的响应无法回答这个问题。
type Result struct {
	UserID string `json:"user_id"`
	// ClosedBindings 是本次解除的绑定数。
	ClosedBindings int `json:"closed_bindings"`
	// RevokedTokens 是撤销的 refresh_token 条数。
	RevokedTokens int64 `json:"revoked_tokens"`
	// PurgedClaims 是物理删除的身份凭证条数（手机号/邮箱密文）。
	PurgedClaims int64 `json:"purged_claims"`
	// Warnings 是需要用户自行处理的残留，主要是三方平台侧的授权。
	Warnings []Warning `json:"warnings,omitempty"`
}

// Warning 是一条需要用户注意的残留。
type Warning struct {
	Code     string `json:"code"`
	Platform string `json:"platform,omitempty"`
	Message  string `json:"message"`
}

// WarningUnbindManual 表示三方平台侧的授权需要用户手动撤销。
const WarningUnbindManual = "unbind_manual_required"

// Close 注销当前账号。
//
// 幂等：对已注销的账号重复调用会返回成功。这是必需的——客户端超时重试、
// 以及"本地级联失败后用户再点一次"都会走到这里，把重复调用当错误会让用户
// 永远卡在中间态。
func (s *Service) Close(ctx context.Context, appCode, externalUserID, reason string) (*Result, error) {
	if externalUserID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "注销缺少账号标识")
	}
	app, err := s.deps.Tenant.Application(ctx, appCode)
	if err != nil {
		return nil, err
	}

	// ① 先关对端。
	//
	// 缺少该能力时【整体拒绝】而不是"只清本地"：本地清干净了、对端账号还在，
	// 用户下次三方登录就会拿到一个全新账号，而旧数据仍留在用户中心。
	// 这种"看起来成功了"的注销比直接报错有害得多。
	closer, ok := s.deps.Accounts.(account.AccountCloser)
	if !ok {
		return nil, errs.New(errs.CodeAccountNotSupported,
			"当前账号服务不支持注销，已拒绝本次请求（避免只清本地造成数据分叉）")
	}
	if err := closer.Close(ctx, app.AppCode, externalUserID); err != nil {
		s.audit(ctx, app.ID, externalUserID, reason, audit.ResultFailure, err)
		return nil, err
	}

	res := &Result{UserID: externalUserID}
	now := time.Now().UTC()

	// ② 解除全部活跃绑定，并为每个渠道产出"需人工撤销"的提示。
	bindings, err := s.deps.Bindings.ListActiveByExternalUser(ctx, app.ID, externalUserID)
	if err != nil {
		s.audit(ctx, app.ID, externalUserID, reason, audit.ResultFailure, err)
		return nil, err
	}
	identityIDs := make([]int64, 0, len(bindings))
	platforms := make([]string, 0, len(bindings))
	for _, b := range bindings {
		identityIDs = append(identityIDs, b.IdentityID)
		if s.deps.Identities != nil {
			// 取平台只为生成提示文案；查不到不影响注销，所以失败只记 debug。
			if idn, ierr := s.deps.Identities.FindByID(ctx, app.ID, b.IdentityID); ierr == nil {
				platforms = append(platforms, idn.Platform)
			}
		}
	}
	for _, b := range bindings {
		if err := s.deps.Bindings.Unbind(ctx, app.ID, b.IdentityID, now); err != nil {
			// 单条解绑失败不中断：其余账号关联仍然应该被清掉，
			// 而失败的那条会在重试时被再次选中（仍是 active）。
			s.logger().Warn("注销时解除绑定失败",
				zap.Int64("app_id", app.ID),
				zap.Int64("identity_id", b.IdentityID),
				zap.Error(err))
			continue
		}
		res.ClosedBindings++
	}
	res.Warnings = unbindWarnings(platforms)

	// ③ 撤销全部 refresh_token。
	//
	// 放在删除凭证之前：万一后续步骤失败，至少"不能再刷新令牌"这个最关键
	// 的安全效果已经生效。
	n, err := s.deps.Sessions.RevokeAllByUser(ctx, app.ID, externalUserID, "account_closed")
	if err != nil {
		s.audit(ctx, app.ID, externalUserID, reason, audit.ResultFailure, err)
		return nil, err
	}
	res.RevokedTokens = n

	// ④ 写账号级撤销水位（架构 §8.4 的"高危撤销"）。
	//
	// ⚠️ 生效范围要说准，不要写成"令牌立刻全部失效"：
	//   - 对 refresh_token：立即失效（上一步已在库里撤销，换不出新令牌）。
	//   - 对 access_token：只对【调用 introspect 且 check_revocation=true】
	//     的消费方立即失效。本服务自己的用户端点（/v1/userinfo 等）与业务方
	//     的本地验签都不查水位——它们只看签名与 exp。
	//
	// 实测证据：注销后拿旧 access_token 打 /v1/userinfo 仍是 200，
	// 打 /v1/introspect?check_revocation=true 是 {"active":false}。
	//
	// 为什么不把水位检查塞进这些端点：那等于给每个用户请求加一次 Redis
	// 往返，并让 Redis 故障直接变成"用户接口全 500"；而这段时间里令牌能做的
	// 事只有读自己那份已被清空的绑定。这个取舍写在 §34 的"残留窗口"里。
	if s.deps.Revocation != nil {
		if err := s.deps.Revocation.RevokeUser(ctx, app.ID, externalUserID, now, s.deps.AccessTTL); err != nil {
			// 不中断：令牌撤销与 PII 清除哪个更重要，答案一定是后者。
			s.logger().Error("注销时写入账号撤销水位失败，已签发的 access_token 将存活到自然过期",
				zap.Int64("app_id", app.ID), zap.Error(err))
		}
	} else {
		s.logger().Warn("未装配撤销名单，注销后已签发的 access_token 将存活到自然过期",
			zap.Int64("app_id", app.ID))
	}

	// ⑤ 物理删除身份凭证密文（手机号 / 邮箱）。
	purged, err := s.deps.Claims.PurgeByIdentities(ctx, app.ID, identityIDs)
	if err != nil {
		s.audit(ctx, app.ID, externalUserID, reason, audit.ResultFailure, err)
		return nil, err
	}
	res.PurgedClaims = purged

	s.audit(ctx, app.ID, externalUserID, reason, audit.ResultSuccess, nil,
		int64(res.ClosedBindings), res.RevokedTokens, res.PurgedClaims)
	return res, nil
}

// unbindWarnings 为每个渠道产出人工撤销提示。
//
// 为什么不在这里调用 Provider.Unbind：本服务从不持久化渠道的 refresh_token
// （exchange 完即丢弃，见 implementation-status §33.3），而各适配器的 Unbind
// 需要它。调用必然返回 NotSupported，然后我们照样落到"请手动撤销"分支——
// 那就是把一个已知必然失败的动作包装成"尽力了"。
//
// 结论对用户完全一致：本地解绑立即生效，三方侧的授权由用户自己去关。
// 区别只是我们不再假装尝试过。真做撤销需要一个前置决策（是否持久化渠道
// 用户凭据），属安全评审范围。
func unbindWarnings(platforms []string) []Warning {
	if len(platforms) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(platforms))
	out := make([]Warning, 0, len(platforms))
	for _, p := range platforms {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, Warning{
			Code:     WarningUnbindManual,
			Platform: p,
			Message:  revokeHint(p),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// revokeHint 给出各平台撤销授权的入口。
//
// 用户看到"已注销"却仍能在授权管理里看到本应用，是最常见的客服问题；
// 直接告诉他去哪点，比让他自己找菜单有效得多。
func revokeHint(platform string) string {
	switch platform {
	case "wechat", "wechat_mini", "wechat_web":
		return "请在微信「我 → 设置 → 隐私 → 授权管理」中取消对本应用的授权"
	case "apple":
		return "请在 iPhone「设置 → Apple ID → 使用 Apple 登录」中停止使用本应用"
	case "alipay":
		return "请在支付宝「我的 → 设置 → 隐私 → 授权管理」中取消对本应用的授权"
	case "google":
		return "请在 Google 账号的「安全性 → 第三方应用访问权限」中移除本应用"
	default:
		return fmt.Sprintf("请到 %s 的授权管理页面取消对本应用的授权", platform)
	}
}

func (s *Service) audit(ctx context.Context, appID int64, userID, reason, result string, cause error,
	counts ...int64) {
	if s.deps.Audit == nil {
		return
	}
	detail := map[string]any{}
	var closedBindings int64
	var revokedTokens int64
	var purged int64
	if len(counts) > 0 {
		closedBindings = counts[0]
	}
	if len(counts) > 1 {
		revokedTokens = counts[1]
	}
	if len(counts) > 2 {
		purged = counts[2]
	}
	detail["closed_bindings"] = closedBindings
	detail["revoked_tokens"] = revokedTokens
	detail["purged_claims"] = purged
	if reason != "" {
		// 用户自述原因进审计但不进日志正文：它是自由文本，可能含联系方式
		// 之类的内容，而审计表本身有访问控制。
		detail["reason"] = reason
	}
	if cause != nil {
		detail["error"] = cause.Error()
	}

	ev := &audit.Event{
		AppID: appID,
		// 审计里保留 user_id 是刻意的：注销之后最常被问的问题就是
		// "这个 id 有没有被注销"。它本身不是 PII（用户中心的对外标识，
		// 不可枚举，见 §8.1），而删掉它会让这条记录失去追溯价值。
		ExternalUserID: userID,
		Action:         "account.close",
		Result:         result,
		TraceID:        reqmeta.TraceID(ctx),
		Detail:         detail,
		At:             time.Now().UTC(),
	}
	if cause != nil {
		ev.ErrorCode = string(errs.CodeOf(cause))
	}
	auditx.Emit(ctx, s.deps.Audit, s.logger(), ev)
}

func (s *Service) logger() *zap.Logger {
	if s.deps.Logger == nil {
		return zap.NewNop()
	}
	return s.deps.Logger
}
