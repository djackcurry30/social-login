// Package tenant 是租户配置的领域模型：业务应用与其渠道配置。
//
// 术语（架构文首）：Application 是【完全独立的业务单元】（App1、App2），
// 拥有独立 appId/appSecret、独立渠道配置、独立账号空间（约束 C1）。
// 它不等于同一应用下的 iOS / Android / 小程序等承载形态。
package tenant

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/alex/social-login/internal/domain/provider"
	"github.com/alex/social-login/internal/pkg/errs"
)

// ErrNotFound 表示应用或渠道配置不存在。
var ErrNotFound = errors.New("tenant: not found")

// 账号模式。约束 C4 固定为 remote。
const (
	AccountModeRemote = "remote"
)

// 未绑定身份的处置方式（D3 / §5.2）。
const (
	// OnUnboundNeedRegister 返回 AUTH.NEED_REGISTER + bind_ticket，由业务方引导注册。
	// 这是默认值：C4 下本服务不能自己产出账号。
	OnUnboundNeedRegister = "need_register"
	// OnUnboundAutoCreate 调 AccountProvider.Create 建号并绑定。
	OnUnboundAutoCreate = "auto_create"
	// OnUnboundSessionOnly 签发 scope=identity_only 的受限令牌。
	OnUnboundSessionOnly = "session_only"
)

// 合并模式（需求 R2）。
const (
	MergeModeAuto    = "auto"
	MergeModeConfirm = "confirm"
	MergeModeManual  = "manual"
)

// confirm 模式下的验证强度。
const (
	VerificationNone            = "none"
	VerificationExistingBinding = "existing_binding"
	VerificationSMS             = "sms"
	VerificationStrict          = "strict"
)

// 登录时的归并行为（§7.5.1）。
const (
	// OnLoginOff 关闭：登录时只按 open_id 精确匹配已有绑定（C5 默认）。
	OnLoginOff = "off"
	// OnLoginDetectOnly 只读判定、不写数据：检测到同手机号已有账号时返回
	// hint 让前端引导用户主动合并。这个档位解决了 v0.7 的一处自相矛盾
	// （confirm 模式既说"不读 claim"又说"可检测同手机号"）。
	OnLoginDetectOnly = "detect_only"
	// OnLoginClaimVerified 按平台已验证凭证自动归并（等价于原方案 S2）。
	OnLoginClaimVerified = "claim_verified"
)

// 被合并账号的处置方式。
const (
	DisposalMarkMerged    = "mark_merged"
	DisposalRequestDelete = "request_delete"
)

// MergePolicy 是合并行为配置（§7.5.1）。
type MergePolicy struct {
	Mode                   string `json:"mode"`
	Verification           string `json:"verification"`
	OnLogin                string `json:"on_login"`
	NotifySourceAccount    bool   `json:"notify_source_account"`
	SourceDisposal         string `json:"source_disposal"`
	AllowCrossPlatformAuto bool   `json:"allow_cross_platform_auto"`
}

// Policy 是 applications.policy 的结构化视图（JSONB 存储）。
type Policy struct {
	OnUnboundLogin string      `json:"on_unbound_login"`
	Merge          MergePolicy `json:"merge"`
	// AllowedRedirectURIs 是允许回跳的业务方地址白名单。
	//
	// 这一项是【必需】的，不是可选加固：/v1/authorize 接收业务方传入的
	// redirect_uri，若不校验就回跳，本服务会变成一个开放重定向器——
	// 攻击者可构造指向自己域名的授权链接，把一次性 auth_code 骗到手。
	//
	// 匹配规则：以 "/" 结尾的条目按前缀匹配（用于站点内多路径），
	// 其余按完整 URL 精确匹配。列表为空时【拒绝所有授权请求】——
	// 失败关闭优于默认放行。
	AllowedRedirectURIs []string `json:"allowed_redirect_uris"`
}

// DefaultPolicy 返回安全默认值：需要注册、用户确认后合并、短信验证。
func DefaultPolicy() Policy {
	return Policy{
		OnUnboundLogin: OnUnboundNeedRegister,
		Merge: MergePolicy{
			Mode:                   MergeModeConfirm,
			Verification:           VerificationSMS,
			OnLogin:                OnLoginOff,
			NotifySourceAccount:    true,
			SourceDisposal:         DisposalMarkMerged,
			AllowCrossPlatformAuto: false,
		},
	}
}

// Normalize 用默认值补全未设置字段。
//
// ⚠️ 它【无法】补全布尔类安全开关（当前只有 NotifySourceAccount）：
// Go 的 bool 零值与"显式配置为 false"在结构体上无法区分，而这两者的语义完全相反
// （未设置 → 应取安全默认 true；显式 false → 必须拒绝）。
//
// 因此约定：**调用方必须从 DefaultPolicy() 出发再逐字段覆盖**，
// 而不是从零值 Policy 出发。读取 JSONB 时正是这么做的（见 postgres.policyFromModel）：
// 只有 JSON 里真的出现了该键，才覆盖默认值。从零值出发会让未配置的安全开关
// 静默变成 false，而 Validate 会拒绝它——失败关闭，不会静默放行。
func (p *Policy) Normalize() {
	d := DefaultPolicy()
	if p.OnUnboundLogin == "" {
		p.OnUnboundLogin = d.OnUnboundLogin
	}
	if p.Merge.Mode == "" {
		p.Merge.Mode = d.Merge.Mode
	}
	if p.Merge.Verification == "" {
		p.Merge.Verification = d.Merge.Verification
	}
	if p.Merge.OnLogin == "" {
		p.Merge.OnLogin = d.Merge.OnLogin
	}
	if p.Merge.SourceDisposal == "" {
		p.Merge.SourceDisposal = d.Merge.SourceDisposal
	}
}

// ValidationResult 是配置校验结果。
type ValidationResult struct {
	// Warnings 是可放行但需要提醒的问题（如 manual 模式下 verification 被忽略）。
	Warnings []string
	// Normalized 是校验过程中被修正后的配置（如 auto+跨平台降级为 confirm）。
	Normalized Policy
}

// Validate 执行 §7.5.4 的配置一致性校验。
//
// 原则（v0.8 确立）：凡"配置生效但行为不符"一律【拒绝】而非静默降级——
// 静默降级会让运维以为开了自动合并却发现没有，是最难排查的一类故障。
// 唯一的例外是"降级后行为更保守"的场景（auto+跨平台 → confirm），
// 这种降级会明确返回 Warning。
func (p Policy) Validate() (*ValidationResult, error) {
	res := &ValidationResult{Normalized: p}

	switch p.Merge.Mode {
	case MergeModeAuto, MergeModeConfirm, MergeModeManual:
	default:
		return nil, errs.Newf(errs.CodeConfigInvalid, "未知的合并模式: %s", p.Merge.Mode).
			WithDetail("field", "merge.mode").
			WithDetail("valid", []string{MergeModeAuto, MergeModeConfirm, MergeModeManual})
	}

	switch p.OnUnboundLogin {
	case OnUnboundNeedRegister, OnUnboundAutoCreate, OnUnboundSessionOnly:
	default:
		return nil, errs.Newf(errs.CodeConfigInvalid, "未知的未绑定处置方式: %s", p.OnUnboundLogin).
			WithDetail("field", "on_unbound_login")
	}

	// 红线 2：被合并账号必须收到通知，不可关闭。
	if !p.Merge.NotifySourceAccount {
		return nil, errs.New(errs.CodeConfigInvalid,
			"notify_source_account 不可关闭：被合并账号的通知是安全红线（R4）").
			WithDetail("field", "merge.notify_source_account")
	}

	switch p.Merge.Mode {
	case MergeModeAuto:
		// auto 模式必须基于平台已验证凭证，因此没有"不验证"这一说。
		if p.Merge.Verification == VerificationNone {
			return nil, errs.New(errs.CodeConfigInvalid,
				"mode=auto 时 verification 不可为 none：自动归并的依据必须是平台侧已验证凭证（R4 红线 1）").
				WithDetail("field", "merge.verification")
		}
	case MergeModeConfirm:
		// confirm 模式的全部意义就是验证；none 会让它退化成 auto 却丢掉安全红线。
		if p.Merge.Verification == VerificationNone {
			return nil, errs.New(errs.CodeConfigInvalid,
				"mode=confirm 时 verification 不可为 none：那等于自动合并却少了验证（§7.5.4）").
				WithDetail("field", "merge.verification")
		}
		// confirm 下强制 on_login=off 或 detect_only：不允许在登录阶段静默归并。
		switch p.Merge.OnLogin {
		case OnLoginOff, OnLoginDetectOnly:
		case OnLoginClaimVerified:
			return nil, errs.New(errs.CodeConfigInvalid,
				"mode=confirm 时 on_login 不可为 claim_verified：那会在登录阶段静默归并，与 confirm 的语义冲突").
				WithDetail("field", "merge.on_login")
		default:
			return nil, errs.Newf(errs.CodeConfigInvalid, "未知的 on_login 取值: %s", p.Merge.OnLogin).
				WithDetail("field", "merge.on_login")
		}
	case MergeModeManual:
		// manual 下 verification / on_login 无意义，忽略并告警（可放行）。
		if p.Merge.Verification != VerificationNone && p.Merge.Verification != VerificationSMS {
			res.Warnings = append(res.Warnings,
				"mode=manual 时 verification 不生效，建议置为 none")
		}
		if p.Merge.OnLogin != OnLoginOff {
			res.Normalized.Merge.OnLogin = OnLoginOff
			res.Warnings = append(res.Warnings,
				"mode=manual 时 on_login 不生效，已归一化为 off")
		}
	}

	// auto + 未开启跨平台 + 该配置确实涉及跨平台场景时，降级为 confirm 并告警。
	// 这里无法在配置校验阶段判断"是否涉及跨平台"，因此只在显式开启跨平台
	// 但模式为 confirm 时给出提示；真正的跨平台判定在归并链路中执行（§7.5.3 红线 3）。
	if p.Merge.Mode == MergeModeAuto && p.Merge.AllowCrossPlatformAuto {
		res.Warnings = append(res.Warnings,
			"allow_cross_platform_auto=true 存在风险：不同平台的手机号可能属于不同实名主体，请确认业务可接受")
	}

	return res, nil
}

// IsRedirectURIAllowed 判断回跳地址是否在白名单内。
func (p Policy) IsRedirectURIAllowed(uri string) bool {
	if uri == "" {
		return false
	}
	target, err := url.Parse(uri)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return false
	}
	for _, allowed := range p.AllowedRedirectURIs {
		if allowed == "" {
			continue
		}
		if strings.HasSuffix(allowed, "/") {
			if strings.HasPrefix(uri, allowed) {
				return true
			}
			continue
		}
		if uri == allowed {
			return true
		}
	}
	return false
}

// Application 是一个业务应用。
type Application struct {
	ID            int64
	AppCode       string
	Name          string
	AppSecretHash string
	Status        int16
	AccountMode   string
	Policy        Policy
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Enabled 判断应用是否启用。
func (a *Application) Enabled() bool { return a.Status == 1 }

// ProviderConfig 是一个业务应用在某接入场景下的渠道凭据。
//
// 唯一键 = (app_id, platform, scene, config_key, env)，不含承载形态（规则 2）。
type ProviderConfig struct {
	ID            int64
	AppID         int64
	Platform      string
	Scene         string
	ConfigKey     string
	ProviderAppID string

	// SecretCipher 是信封加密后的凭据。明文只在调用三方接口的瞬间存在于内存。
	SecretCipher []byte
	// SecretCipherPrev 是上一版凭据，用于轮换过渡期双验证（扩展性 E6）。
	SecretCipherPrev []byte
	SecretRotatedAt  *time.Time
	SecretDEKID      string

	// Env 用于环境隔离（扩展性 E5）：prod | test。
	Env     string
	Extra   map[string]any
	Version int64
	Status  int16

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Enabled 判断渠道配置是否启用。
func (c *ProviderConfig) Enabled() bool { return c.Status == 1 }

// Key 返回路由键，便于日志与错误提示。
func (c *ProviderConfig) Key() string { return provider.Key(c.Platform, c.Scene) }

// SecretResolver 负责把加密凭据解成明文。
//
// 定义成独立端口而不是让仓储直接返回明文，是为了让"解密"这个敏感动作
// 有明确的调用点，便于审计与将来接入 KMS（第四期替换本地主密钥）。
type SecretResolver interface {
	// Resolve 返回当前有效凭据与（可能为空的）上一版凭据明文。
	Resolve(cfg *ProviderConfig) (current string, previous string, err error)
}

// ApplicationRepository 是应用配置的持久化端口。
type ApplicationRepository interface {
	// FindByAppCode 按对外 app_id 查找。未找到返回 ErrNotFound。
	FindByAppCode(ctx context.Context, appCode string) (*Application, error)
	// FindByID 按主键查找。
	FindByID(ctx context.Context, id int64) (*Application, error)
}

// ProviderConfigRepository 是渠道配置的持久化端口。
type ProviderConfigRepository interface {
	// Find 精确查找一份渠道配置。configKey 为空时取 "default"。
	Find(ctx context.Context, appID int64, platform, scene, configKey, env string) (*ProviderConfig, error)
	// ListByApp 列出某应用的全部渠道配置（管理端与引导绑定页需要）。
	ListByApp(ctx context.Context, appID int64) ([]ProviderConfig, error)
}
