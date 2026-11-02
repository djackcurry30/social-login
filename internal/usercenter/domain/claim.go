package domain

import (
	"strings"
	"time"
)

// 凭证类型。
//
// 只有 phone / email 两种，与 DDL 的 CHECK 约束一致（E1：新增类型 = 一条迁移
// + 一个 switch case；类型多到需要动态配置时，再把校验从 CHECK 挪到应用层）。
const (
	ClaimTypePhone = "phone"
	ClaimTypeEmail = "email"
)

// IsValidClaimType 判断凭证类型是否受支持。
func IsValidClaimType(t string) bool {
	return t == ClaimTypePhone || t == ClaimTypeEmail
}

// Claim 是一条【已验证】凭证。
//
// 与 social-login 的 identity.Claim 的区别：那边记的是"某次授权证明过这个
// 身份拥有该凭证"的流水，会漂移；这里的记录是账号当前持有的凭证，
// 是权威值。两者靠 by-claim 反查对齐（J 组的漂移检测就是在查这件事）。
type Claim struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// NormalizePhone 归一化手机号。
//
// 规则必须与 social-login 的 domain/identity/claim.go **逐字一致**（§7）：
// 只保留数字；13 位且以 86 开头时去掉国家码前缀。
//
// 不一致的后果很具体：同一个号码经微信返回带区号、经支付宝不带，
// 本地算出的 hash 与这里算出的不同，于是"本地查得到、UC 查不到"，
// 归并判定与回源核对同时失效。所以两边各有一组边界用例（+86 138-0000-0000 /
// 8613800000000 / 138 0000 0000 必须得到同一个结果）。
func NormalizePhone(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
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
//
// 本地部分理论上大小写敏感，但主流服务商实际不区分，统一小写是通行做法；
// 更重要的是"两边规则一致"，而不是哪种更学院派。
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

// ValidateClaimValue 校验归一化后的凭证值是否像一个真实值。
//
// 只做"显然不成立"的拦截，不做严格的格式校验：号码段规则各国不同、
// 邮箱的完整语法（RFC 5322）没人真的全实现。这里的目标是挡住空值、
// 极端长度与明显不是手机号的输入——它们一旦入库，会在唯一索引上
// 制造"垃圾值被占用"的假冲突。
func ValidateClaimValue(claimType, normalized string) error {
	switch claimType {
	case ClaimTypePhone:
		// 中文手机号 11 位；其他国家 6~15 位（E.164 上限 15 位）。
		// 放宽下限到 6 而不是卡 11：本服务不假设只有中国大陆用户。
		if len(normalized) < 6 || len(normalized) > 15 {
			return Newf(CodeInvalid, "手机号格式不合法（去除非数字后长度为 %d）", len(normalized))
		}
	case ClaimTypeEmail:
		if len(normalized) < 3 || len(normalized) > 254 {
			return New(CodeInvalid, "邮箱长度不合法")
		}
		at := strings.LastIndex(normalized, "@")
		if at <= 0 || at == len(normalized)-1 {
			return New(CodeInvalid, "邮箱格式不合法：缺少本地部分或域名")
		}
	default:
		return Newf(CodeInvalid, "不支持的凭证类型: %q", claimType)
	}
	return nil
}

// ClaimRecord 是凭证的持久化视图。
//
// 同时带 hash 与密文：hash 供查询，密文供展示/审计（§3.1）。
// Value 是解密后的明文，只在读路径上临时填充，绝不写日志。
type ClaimRecord struct {
	ID           int64
	AccountID    int64
	Type         string
	ValueHash    []byte
	HashVersion  int16
	ValueCipher  []byte
	DEKID        string
	Source       string
	VerifiedAt   time.Time
	RevokedAt    *time.Time
	RevokeReason string
}
