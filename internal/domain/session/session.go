// Package session 是本地会话（刷新令牌）的领域模型。
//
// 为什么 refresh_token 用不透明随机串而不是 JWT（架构 §8.1）：
// 它需要"可撤销"能力——JWT 的自包含特性恰恰意味着服务端无法在有效期内作废它。
// 因此 refresh_token 走"查库比对哈希"的路子，代价是一次数据库读，换来撤销能力。
// 反过来 access_token 用 JWT，因为它是高频校验、必须免网络开销。
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// TTLRefreshToken 是刷新令牌有效期（架构 §8.1）。
const TTLRefreshToken = 30 * 24 * time.Hour

// ErrNotFound 表示刷新令牌不存在。
var ErrNotFound = errors.New("session: refresh token not found")

// ErrReused 表示检测到刷新令牌重放（令牌已被使用过又再来一次）。
//
// 这是 RFC 6819 推荐的 Refresh Token Rotation + Reuse Detection 的触发信号：
// 一旦出现，说明令牌极可能被窃取，必须撤销整条轮转链并要求重新登录（架构 §8.2）。
var ErrReused = errors.New("session: refresh token reused")

// RefreshToken 是一条刷新令牌记录。只存哈希，不存明文。
type RefreshToken struct {
	ID             int64
	AppID          int64
	ExternalUserID string
	TokenHash      string
	DeviceID       string
	Scope          string
	ExpiresAt      time.Time
	// RotatedFrom 指向被轮转掉的旧令牌，形成单向链。
	//
	// 单向链的好处是无需回写旧记录（旧记录只需置 revoked），减少写放大；
	// 重放检测时沿链回溯即可定位整个会话链（修正 A7）。
	RotatedFrom   *int64
	Revoked       bool
	RevokedReason string
	CreatedAt     time.Time
}

// Valid 判断令牌是否仍可用。
func (t *RefreshToken) Valid(now time.Time) bool {
	return !t.Revoked && now.Before(t.ExpiresAt)
}

// CreateInput 是签发刷新令牌的入参。
type CreateInput struct {
	AppID          int64
	ExternalUserID string
	TokenHash      string
	DeviceID       string
	Scope          string
	ExpiresAt      time.Time
	RotatedFrom    *int64
	At             time.Time
}

// Repository 是刷新令牌的持久化端口。
type Repository interface {
	// Create 写入一条刷新令牌。
	Create(ctx context.Context, in CreateInput) (*RefreshToken, error)

	// FindByHash 按哈希查找。未找到返回 ErrNotFound。
	FindByHash(ctx context.Context, appID int64, tokenHash string) (*RefreshToken, error)

	// Revoke 撤销单条令牌。
	Revoke(ctx context.Context, appID, id int64, reason string) error

	// RevokeChainFrom 撤销以该令牌为根的整条轮转链（含其全部后代）。
	//
	// ⚠️ 方向说明：轮转链的指针是【新 → 旧】（RotatedFrom 指向父亲），
	// 所以要作废"整条会话"必须【向后代展开】，而不是向上回溯祖先。
	// 被泄露的旧令牌所派生出的每一个后继令牌都需要撤销，
	// 否则重放检测会留下一个仍然可用的令牌。
	// 返回被撤销的令牌数。
	RevokeChainFrom(ctx context.Context, appID, id int64, reason string) (int, error)

	// RevokeAllByUser 撤销某业务账号的全部令牌。
	// 高风险场景使用：账号劫持、账号注销、管理员强制下线、合并后清理 source。
	RevokeAllByUser(ctx context.Context, appID int64, externalUserID, reason string) (int64, error)
}

// HashToken 计算不透明令牌的存储哈希。
//
// 这里用裸 SHA-256 而不是 bcrypt/argon2：令牌本身是 32 字节密码学随机数，
// 熵足够高，不存在"被暴力枚举"的风险；慢哈希只会让每次刷新请求白付 CPU。
// 慢哈希适用于低熵的用户口令，而本服务不存用户口令。
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
