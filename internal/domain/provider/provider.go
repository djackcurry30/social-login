package provider

import (
	"context"

	"github.com/17track/social-login/internal/pkg/errs"
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
