package wechat

import (
	"strconv"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// wxError 是微信 OpenAPI 的统一错误字段。
//
// 关键事实：微信的错误几乎都以 HTTP 200 + errcode != 0 返回。
// 只看 HTTP 状态码会把"code 已使用"当成成功，把"appsecret 错误"当成成功，
// 然后在解析用户信息时以"缺少 openid"这种误导性错误暴露出来。
type wxError struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func (e wxError) failed() bool { return e.ErrCode != 0 }

// 微信错误码 → 本服务错误码的映射。
//
// 分类原则（架构 §5.6.4）：
//   - 业务语义的拒绝（code 无效 / 已使用）→ PROVIDER.REJECTED，【不计入熔断】
//   - 平台侧故障（系统繁忙 / 限频）→ PROVIDER.UNAVAILABLE / QUOTA_EXCEEDED，计入熔断
//   - 我们的配置错误（appsecret 错 / 无接口权限）→ AUTH.INVALID_CONFIG，
//     计入熔断但单独告警（它不会自愈，等下去只是浪费流量）
const (
	codeInvalidCode        = 40029 // code 无效
	codeCodeUsed           = 40163 // code 已被使用
	codeInvalidAppID       = 40013 // appid 无效
	codeInvalidSecret      = 40125 // appsecret 无效
	codeAPIUnauthorized    = 48001 // 接口未授权（公众号 scope 不足）
	codeUserNotExist       = 40003 // openid 无效
	codeRateLimit          = 45011 // 频率限制
	codeSystemBusy         = -1    // 系统繁忙
	codeTokenExpired       = 42001 // access_token 过期
	codeInvalidCredential  = 40001 // 凭据无效
)

func wxErr(e wxError, platform string) *errs.Error {
	msg := e.ErrMsg
	if msg == "" {
		msg = "微信返回错误（无描述）"
	}
	switch e.ErrCode {
	case codeInvalidCode, codeCodeUsed, codeUserNotExist:
		// 用户重放了 code，或 code 已过期。这是正常的业务失败，
		// 接入方需要重开一次授权流程，而不是等我们自愈。
		return errs.Newf(errs.CodeProviderRejected, "微信授权码无效或已使用: %s", msg).
			WithDetail("platform", platform).
			WithDetail("wx_errcode", e.ErrCode).
			WithDetail("wx_errmsg", msg)

	case codeRateLimit:
		return errs.Newf(errs.CodeProviderQuotaExceeded, "微信接口频率受限: %s", msg).
			WithDetail("platform", platform).
			WithDetail("wx_errcode", e.ErrCode).
			WithDetail("wx_errmsg", msg)

	case codeInvalidAppID, codeInvalidSecret, codeInvalidCredential, codeAPIUnauthorized:
		// 我们的配置问题：appid 与 secret 不匹配、或该 appid 没有开通对应接口。
		// 这类错误在管理端点一次 verify 就能发现，落到线上只说明配置被改坏了。
		return errs.Newf(errs.CodeAuthInvalidConfig, "微信渠道配置有误: %s", msg).
			WithDetail("platform", platform).
			WithDetail("wx_errcode", e.ErrCode).
			WithDetail("wx_errmsg", msg)

	case codeSystemBusy:
		return errs.Newf(errs.CodeProviderUnavailable, "微信服务繁忙: %s", msg).
			WithDetail("platform", platform).
			WithDetail("wx_errcode", e.ErrCode).
			WithDetail("wx_errmsg", msg)

	default:
		// 未归类的错误码一律按平台不可用处理：宁可让它计入熔断，
		// 也不要吞掉一个我们还不认识的故障信号。details 里保留原始码供排障。
		return errs.Newf(errs.CodeProviderUnavailable,
			"微信返回未预期错误（errcode=%s）", strconv.Itoa(e.ErrCode)).
			WithDetail("platform", platform).
			WithDetail("wx_errcode", e.ErrCode).
			WithDetail("wx_errmsg", msg)
	}
}
