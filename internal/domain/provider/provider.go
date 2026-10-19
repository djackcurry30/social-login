package provider

import (
	"context"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Provider 是所有三方渠道必须实现的契约。
//
// 一个实现对应一个 (平台, 场景) 组合，例如 wechat:mini_program。
//
// 三条实现约定：
//
//  1. 【不做网络重试】（约束 C6，架构 §5.5）。一次失败即返回错误。
//     重试单位是"整个授权流程"，由接入方重新发起 /v1/authorize 完成。
//  2. Exchange / Refresh 这类"已发出即不可撤销"的调用，必须使用调用方传入的
//     ctx（由上层用 httpx.Detach 构造），不得自行取消或收窄超时——否则客户端
//     断网会导致授权码被平台消费而结果丢失（架构 §5.7 第 3 条）。
//  3. 所有错误必须归一化为 *errs.Error，并给出正确的 retryable 语义。
type Provider interface {
	// Metadata 返回渠道的静态描述，用于路由与能力查询。
	Metadata() Metadata

	// AuthURL 生成三方授权跳转地址。
	// 小程序等无授权页的场景返回空 URL，并标记 Immediate=true。
	AuthURL(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error)

	// Exchange 用授权凭证换取三方令牌。
	// 不同场景的入参语义由 Extra 承载，由实现自行解释。
	Exchange(ctx context.Context, req ExchangeRequest) (*TokenSet, error)

	// UserInfo 拉取三方用户信息并归一化。
	UserInfo(ctx context.Context, req UserInfoRequest) (*ExternalUser, error)

	// Refresh 刷新三方令牌。平台不支持时返回 NotSupported("refresh")。
	Refresh(ctx context.Context, req RefreshRequest) (*TokenSet, error)

	// Unbind 在三方平台侧解除授权（如微信拉黑、Apple 撤销令牌）。
	// 平台不支持时返回 NotSupported("unbind")。
	Unbind(ctx context.Context, req UnbindRequest) error
}

// CallbackVerifier 由需要回调验签的平台实现（Apple / 支付宝）。
//
// 编排层用类型断言探测此能力，不强制所有 Provider 实现。
type CallbackVerifier interface {
	VerifyCallback(ctx context.Context, raw *CallbackPayload) error
}

// 归一化的服务端通知事件类型。
//
// 名称刻意用下划线而非 Apple 原始的连字符：它要进审计与日志的 detail，
// 保持全系统一种分隔符，避免同一事件出现 consent-revoked / consent_revoked
// 两种写法导致查询漏数据。
const (
	// CallbackEventConsentRevoked 表示用户在三方平台侧撤销了授权。
	// 处理方式是立刻解绑——不能等下次登录才发现。
	CallbackEventConsentRevoked = "consent_revoked"
	// CallbackEventAccountDelete 表示用户在平台侧删除了账号。
	CallbackEventAccountDelete = "account_delete"
	// CallbackEventEmailDisabled 表示平台侧中转邮箱被停用（Apple 隐私邮箱）。
	// 只影响资料里的邮箱可信度，【不解除绑定】。
	CallbackEventEmailDisabled = "email_disabled"
	// CallbackEventUnknown 表示平台发来了我们不认识的事件。
	// 必须显式建模这个值，不能吞掉：未知事件要留痕，否则平台新增事件类型时
	// 我们会静默失联。
	CallbackEventUnknown = "unknown"
)

// CallbackEvent 是平台服务端通知（S2S）归一化后的结果。
//
// 为什么不让编排层直接解析平台报文：报文结构是渠道私有的（Apple 是 JWT，
// 支付宝是 form 参数 + RSA2 签名），把它泄漏到用例层会让每加一个平台都要
// 改一次编排代码——那正是 §3 分层要避免的。
type CallbackEvent struct {
	// Type 取 CallbackEvent* 常量之一。
	Type string
	// Platform / Scene 让编排层核对来源，防止"用 A 渠道的配置处理 B 渠道的通知"。
	Platform string
	Scene    string
	// OpenID 是平台侧用户标识（Apple 的 sub），用于定位是哪条身份。
	// 为空表示该事件不针对具体用户（如平台级公告），调用方应忽略。
	OpenID string
	// OccurredAt 是平台声明的事件时间，平台未提供时为零值。
	OccurredAt time.Time
	// Detail 是脱敏后的原始事件字段，供审计与排障。
	// 【禁止】放入 access_token / id_token / session_key。
	Detail map[string]any
}

// CallbackParser 由需要处理服务端通知的平台实现（Apple / 支付宝）。
//
// 与 CallbackVerifier 分开的理由：验签是"能不能信这条报文"，解析是"这条
// 报文说了什么"。两者失败语义完全不同——验签失败是安全事件（必须告警），
// 解析失败是兼容性问题（平台改字段了）。混在一个方法里，调用方无法区分。
type CallbackParser interface {
	ParseCallback(ctx context.Context, raw *CallbackPayload) (*CallbackEvent, error)
}

// HealthChecker 由需要平台健康探测的适配器实现（可选）。
//
// ⚠️ 职责边界：HealthChecker 只用于【管理台展示与告警】，
// 【不参与熔断决策】——熔断完全基于真实业务调用的被动统计（架构 §5.6.6）。
// 主动探测走的不是真实业务路径，用它决定熔断必然误判。
type HealthChecker interface {
	// Ping 探测三方平台可达性。
	Ping(ctx context.Context) error
}

// NotSupported 返回统一的能力未实现错误。
//
// 用错误的返回值而非 error 变量，是为了让 details 里带上具体能力名，
// 排障时能直接看出是"平台不支持"还是"我们没实现"。
func NotSupported(capability string) *errs.Error {
	return errs.Newf(errs.CodeProviderNotSupported, "该渠道不支持此能力: %s", capability).
		WithDetail("capability", capability)
}
