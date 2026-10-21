package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

const (
	keyPrefixRevokedJTI  = "oauth:revoked_jti:"
	keyPrefixRevokedUser = "oauth:revoked_user:"
)

// RevocationStore 是 session.RevocationList 的 Redis 实现。
//
// 为什么放 Redis 而不是数据库：这是"15 分钟内的临时事实"，
// 写频率与强制下线次数同量级（很低），但读在 introspect 的热路径上
// （check_revocation=true 时）。放数据库会让安全敏感操作多一次跨库往返，
// 放 Redis 则与其它令牌态数据同源。
type RevocationStore struct {
	rdb *redis.Client
}

// NewRevocationStore 构造撤销名单。
func NewRevocationStore(rdb *redis.Client) *RevocationStore {
	return &RevocationStore{rdb: rdb}
}

var _ session.RevocationList = (*RevocationStore)(nil)

// RevokeJTI 把单个 jti 加入黑名单。
func (s *RevocationStore) RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error {
	if jti == "" {
		return nil
	}
	if ttl <= 0 {
		// TTL 为 0 会被 Redis 当成"立即过期"，黑名单形同没写。
		return errs.New(errs.CodeInternal, "撤销 jti 必须给出正的 TTL（该令牌的剩余有效期）")
	}
	if err := s.rdb.Set(ctx, keyPrefixRevokedJTI+jti, "1", ttl).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "写入 jti 黑名单失败", err)
	}
	return nil
}

// IsJTIRevoked 判断 jti 是否在黑名单中。
func (s *RevocationStore) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	n, err := s.rdb.Exists(ctx, keyPrefixRevokedJTI+jti).Result()
	if err != nil {
		return false, errs.Wrap(errs.CodeInternal, "查询 jti 黑名单失败", err)
	}
	return n > 0, nil
}

// RevokeUser 写入账号级撤销水位。
//
// 用 SET 覆盖而不是"取较晚者"：一次强制下线就是一次新水位，
// 更晚的水位天然涵盖更早的水位（早于较晚时刻的令牌全部失效）。
func (s *RevocationStore) RevokeUser(ctx context.Context, appID int64, userID string, at time.Time, ttl time.Duration) error {
	if userID == "" {
		return errs.New(errs.CodeInternal, "账号级撤销缺少 external_user_id")
	}
	if ttl <= 0 {
		return errs.New(errs.CodeInternal, "账号级撤销必须给出正的 TTL（覆盖 access_token 剩余寿命）")
	}
	key := revokedUserKey(appID, userID)
	if err := s.rdb.Set(ctx, key, strconv.FormatInt(at.UnixNano(), 10), ttl).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "写入账号撤销水位失败", err)
	}
	return nil
}

// RevokedAt 读取账号级撤销水位。
func (s *RevocationStore) RevokedAt(ctx context.Context, appID int64, userID string) (time.Time, error) {
	if userID == "" {
		return time.Time{}, nil
	}
	raw, err := s.rdb.Get(ctx, revokedUserKey(appID, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, errs.Wrap(errs.CodeInternal, "查询账号撤销水位失败", err)
	}
	ns, perr := strconv.ParseInt(raw, 10, 64)
	if perr != nil {
		// 值坏了当作"没有撤销"而不是"已撤销"：后者会误伤全部用户，
		// 前者最多回到"15 分钟生效窗口"的默认语义。
		return time.Time{}, nil
	}
	return time.Unix(0, ns).UTC(), nil
}

func revokedUserKey(appID int64, userID string) string {
	return fmt.Sprintf("%s%d:%s", keyPrefixRevokedUser, appID, userID)
}
