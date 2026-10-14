package identity

import (
	"context"
	"strings"
	"time"

	"github.com/17track/social-login/internal/pkg/errs"
)

// ClaimType 是凭证类型。
const (
	ClaimTypePhone   = "phone"
	ClaimTypeEmail   = "email"
	ClaimTypeUnionID = "union_id"
	ClaimTypeCustom  = "custom"
)

// 凭证来源权威枚举（修正 A6，必须与 DDL 注释、§7.5.3 白名单一致）。
//
// 分两类，界限不可模糊：
//
//	平台/服务端已验证 —— 可作为自动归并依据（R4 红线 1 的白名单）
//	  wechat_phone / alipay_phone / sms_verified / apple_email
//	用户手填 —— 【永不参与自动归并】
//	  manual
const (
	SourceWeChatPhone = "wechat_phone"
	SourceAlipayPhone = "alipay_phone"
	SourceSMSVerified = "sms_verified"
	SourceAppleEmail  = "apple_email"
	SourceManual      = "manual"
)

// trustedSources 是 R4 红线 1 的凭证来源白名单。
//
// 这张表是安全边界本身，不是配置项：如果允许用户手填的手机号参与归并，
// 攻击者只需在注册时填上受害者的手机号，就能在下次登录时被自动归并进
// 受害者账号——这是直接的账号劫持路径。
var trustedSources = map[string]bool{
	SourceWeChatPhone: true,
	SourceAlipayPhone: true,
	SourceSMSVerified: true,
	SourceAppleEmail:  true,
}

// IsTrustedSource 判断凭证来源是否可信（可用于自动归并）。
func IsTrustedSource(source string) bool { return trustedSources[source] }

// IsValidSource 判断来源取值是否在权威枚举内。
func IsValidSource(source string) bool {
	_, ok := trustedSources[source]
	return ok || source == SourceManual
}

// Claim 是一条归并依据。
//
// 注意语义（架构 §8.5，修正 P0-6）：本表的 claim 【不是】账号当前手机号，
// 而是"某次授权中，某平台证明过这个身份拥有该凭证"的记录。账号当前手机号
// 的权威源在用户中心。因此归并前必须调 AccountProvider.GetByClaim 回源核对。
type Claim struct {
	ID          int64
	AppID       int64
	IdentityID  int64
	Type        string
	ValueHash   string
	ValueCipher []byte
	Verified    bool
	VerifiedAt  *time.Time
	Source      string
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// UpsertInput 是写入凭证的入参。
type ClaimUpsertInput struct {
	AppID       int64
	IdentityID  int64
	Type        string
	ValueHash   string
	ValueCipher []byte
	Verified    bool
	Source      string
	At          time.Time
}

// ClaimHasher 计算凭证的匹配哈希。
//
// ⚠️ 实现必须使用【应用级静态盐】而不是每行随机盐。原因：claim 的核心用途是
// "按手机号反查身份"，随机盐会让同一个手机号每次算出不同哈希，这个功能直接失效。
// 静态盐的代价是同一应用内可以识别相同手机号——这正是功能所需；跨应用因盐不同
// 而无法关联，反而是符合 C1 隔离要求的额外收益。
type ClaimHasher interface {
	Hash(appID int64, claimType, normalizedValue string) string
}

// ClaimRepository 是凭证的持久化端口。
type ClaimRepository interface {
	// Insert 写入一条 claim。
	//
	// 唯一约束是部分唯一索引 (app_id, claim_type, claim_value_hash)
	// WHERE verified = true AND revoked_at IS NULL（修正 P0-1）：
	// 未验证的手填凭证不占用唯一键，被撤销的凭证释放号码。
	// 因此插入冲突（duplicate key）是【正常业务信号】——表示"该凭证已被
	// 另一个身份验证过"，调用方据此走冲突/合并流程，而不是当成系统错误。
	Insert(ctx context.Context, in ClaimUpsertInput) (*Claim, error)

	// FindVerified 按已验证凭证反查归属身份。未找到返回 ErrNotFound。
	FindVerified(ctx context.Context, appID int64, claimType, valueHash string) (*Claim, error)

	// ListByIdentity 列出某身份的全部有效凭证。
	ListByIdentity(ctx context.Context, appID, identityID int64) ([]Claim, error)

	// Revoke 撤销某身份下的指定凭证（换号/解绑）。
	Revoke(ctx context.Context, appID, identityID int64, claimType, valueHash string, at time.Time) error
}

// ErrClaimTaken 表示该凭证已被另一个身份验证过（唯一索引冲突）。
var ErrClaimTaken = errs.New(errs.CodeBindIdentityTaken, "该凭证已被其他身份占用")

// NormalizePhone 归一化手机号。
//
// 只保留数字，并去掉中国大陆的 86 国家码前缀——同一个号码经不同渠道返回的
// 格式不同（微信带区号、支付宝不带），归一化不一致会导致归并失效。
func NormalizePhone(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) == 13 && strings.HasPrefix(s, "86") {
		s = s[2:]
	}
	return s
}

// NormalizeEmail 归一化邮箱：去空白 + 转小写。
// 本地部分理论上大小写敏感，但主流邮箱服务商实际不区分，统一小写是通行做法。
func NormalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// Normalize 按类型归一化凭证值。
func Normalize(claimType, raw string) string {
	switch claimType {
	case ClaimTypePhone:
		return NormalizePhone(raw)
	case ClaimTypeEmail:
		return NormalizeEmail(raw)
	default:
		return strings.TrimSpace(raw)
	}
}
