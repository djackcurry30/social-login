package cache

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/domain/sessionkey"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// keyPrefixSessionKey 是会话密钥的键前缀。
//
// 与票据（oauth:*）分开命名空间：票据是"一次性、读后即删"，
// 会话密钥是"覆盖写、按 TTL 过期"，两者的运维动作不同（前者可以整批清、
// 后者清了只会让用户重新授权），混在一个前缀下容易误伤。
const keyPrefixSessionKey = "mp:sk:"

// SessionKeyStore 是 sessionkey.Store 的 Redis 实现。
//
// 值以密文形式落库：session_key 是能解开用户手机号的密钥材料，
// Redis 一旦被读（未授权访问、备份泄漏、运维误 cat），明文就等于
// 手机号全部可解。这里复用渠道凭据那套信封加密（KeyManager），
// 使"拿到 Redis 快照"与"拿到手机号"之间还隔着一层 KEK。
type SessionKeyStore struct {
	rdb *redis.Client
	km  *crypto.KeyManager
}

var _ sessionkey.Store = (*SessionKeyStore)(nil)

// NewSessionKeyStore 构造会话密钥存储。km 为 nil 时退化为明文存储，
// 仅供本地调试——生产装配必须传 KeyManager（bootstrap 里是硬传的）。
func NewSessionKeyStore(rdb *redis.Client, km *crypto.KeyManager) *SessionKeyStore {
	return &SessionKeyStore{rdb: rdb, km: km}
}

// Put 写入或覆盖密钥。
func (s *SessionKeyStore) Put(ctx context.Context, appID, openID, key string, ttl time.Duration) error {
	if key == "" {
		// 空密钥没有意义，且会把"没有密钥"写成存在状态，误导后续判断。
		return nil
	}
	if appID == "" || openID == "" {
		return errs.New(errs.CodeInternal, "保存会话密钥缺少 app_id 或 open_id")
	}
	if ttl <= 0 {
		ttl = sessionkey.DefaultTTL
	}

	value := key
	if s.km != nil {
		ct, err := s.km.Encrypt(key)
		if err != nil {
			return errs.Wrap(errs.CodeInternal, "加密会话密钥失败", err)
		}
		value = base64.StdEncoding.EncodeToString(ct)
	}

	// SET 天然是覆盖写，同时刷新 TTL：旧密钥不会残留成第二份。
	if err := s.rdb.Set(ctx, s.key(appID, openID), value, ttl).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "保存会话密钥失败", err)
	}
	return nil
}

// Get 读取密钥。不存在、已过期或无法解密时统一返回 sessionkey.ErrNotFound。
func (s *SessionKeyStore) Get(ctx context.Context, appID, openID string) (string, error) {
	if appID == "" || openID == "" {
		return "", sessionkey.ErrNotFound
	}
	raw, err := s.rdb.Get(ctx, s.key(appID, openID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", sessionkey.ErrNotFound
	}
	if err != nil {
		return "", errs.Wrap(errs.CodeInternal, "读取会话密钥失败", err)
	}
	if s.km == nil {
		return raw, nil
	}

	ct, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// 值被写坏或写入时未加密（例如从明文实现切换过来）。
		// 视为不可用而不是内部错误：这类数据的正确处置是让用户重新授权，
		// 不是让整个登录失败。
		return "", fmt.Errorf("%w: 密文编码非法", sessionkey.ErrNotFound)
	}
	plain, err := s.km.Decrypt(ct)
	if err != nil {
		// KEK 轮换后旧密文无法解开。同样按"不可用"处理，并用 %w 保留
		// ErrNotFound 语义，调用方可以 errors.Is 判断后要求重新授权。
		return "", fmt.Errorf("%w: 解密失败（KEK 可能已轮换）", sessionkey.ErrNotFound)
	}
	return plain, nil
}

// Delete 丢弃密钥。不存在不算错误。
func (s *SessionKeyStore) Delete(ctx context.Context, appID, openID string) error {
	if appID == "" || openID == "" {
		return nil
	}
	if err := s.rdb.Del(ctx, s.key(appID, openID)).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "删除会话密钥失败", err)
	}
	return nil
}

func (s *SessionKeyStore) key(appID, openID string) string {
	return keyPrefixSessionKey + appID + ":" + openID
}
