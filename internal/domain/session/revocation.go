package session

import (
	"context"
	"time"
)

// RevocationList 是"高危撤销"的生效通道（架构 §8.4，修正 P0-5）。
//
// 为什么需要它：access_token 是本地验签的 JWT（15 分钟），撤 refresh_token
// 只挡住"下一次刷新"，已经发出去的 access_token 仍能用到自然过期。
// 账号劫持、管理员强制下线这类场景不能等 15 分钟，于是需要一份短期的
// 撤销名单，让 introspect 能立即回答"这个令牌已经不可信"。
//
// 设计上的两个维度，缺一不可：
//
//	jti 级   已知具体令牌（例如某个 refresh 轮转出的 access_token）
//	账号级   管理员强制下线时并不知道有哪些 jti 在飞，只能按"账号 + 时间"作废
//
// 账号级用"水位"（revoked_at）而不是枚举 jti：签发时间早于水位的令牌全部失效。
// 水位只需保留一个 access_token 生命周期（15 分钟）——超过这个时间，
// 所有旧令牌都已自然过期，水位没有继续存在的意义。
type RevocationList interface {
	// RevokeJTI 把单个 jti 加入黑名单。ttl 应为该令牌的剩余有效期。
	RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error

	// IsJTIRevoked 判断 jti 是否在黑名单中。
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)

	// RevokeUser 记录"该账号在 at 之前签发的令牌全部失效"。
	//
	// ttl 应覆盖 access_token 的剩余寿命（通常就是 access TTL）：
	// 水位过期后，那批令牌本身也已经过期了。
	RevokeUser(ctx context.Context, appID int64, userID string, at time.Time, ttl time.Duration) error

	// RevokedAt 返回账号级撤销水位。零值表示从未被撤销。
	RevokedAt(ctx context.Context, appID int64, userID string) (time.Time, error)
}

// Revoked 综合判断一个令牌是否已被撤销。
//
// 抽出这个函数而不是让调用方自己比对水位与 jti：两处判定逻辑一旦分叉，
// "introspect 说有效但网关说无效"这种问题极难排查。
func Revoked(ctx context.Context, rl RevocationList, appID int64, userID, jti string, issuedAt time.Time) (bool, error) {
	if rl == nil {
		// 未装配时【不声称"已撤销"】：拒绝所有请求的"安全默认"会让一次
		// 装配遗漏变成全站不可用。调用方（introspect）的默认行为是不查，
		// 因此这里返回 false 与"没接黑名单"的语义一致。
		return false, nil
	}
	if jti != "" {
		hit, err := rl.IsJTIRevoked(ctx, jti)
		if err != nil {
			return false, err
		}
		if hit {
			return true, nil
		}
	}
	at, err := rl.RevokedAt(ctx, appID, userID)
	if err != nil {
		return false, err
	}
	if at.IsZero() {
		return false, nil
	}
	// 水位是"撤销发生的时刻"，早于这一刻签发的令牌全部作废。
	return !issuedAt.After(at), nil
}

// AdminFilter 是管理端 E 组的会话查询条件（与关系）。
//
// 注意 Active 是三态（nil 表示全部）：用 bool 的话"查全部"与"查已撤销"
// 无法区分，而排查客诉时恰恰要能只看已失效的会话。
type AdminFilter struct {
	AppID          int64
	ExternalUserID string
	DeviceID       string
	Active         *bool
	Page           int
	PageSize       int
}

// AdminLister 是管理端会话查询端口。
//
// 独立于 Repository：授权链路只需要 Create / FindByHash / Revoke*，
// 让核心接口为运维查询背债会增加每次改动的审视范围。
type AdminLister interface {
	ListAdmin(ctx context.Context, f AdminFilter) ([]RefreshToken, int64, error)
}
