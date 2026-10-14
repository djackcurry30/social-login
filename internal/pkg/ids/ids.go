// Package ids 统一生成对外标识。
//
// 选 ULID 而不是 UUIDv4 / 自增 ID 的原因（架构 §8.1）：
//   - 相对 UUIDv4：ULID 前 48 位是时间戳，字典序即时间序，日志与数据库中
//     天然按时间排列，排障时不需要额外索引；且是 26 字符 Base32，比 UUID 短。
//   - 相对自增 ID：不可枚举。本服务对外暴露的 sub 直接用业务方 user_id，
//     但事件 ID、jti、ticket 等标识仍必须不可枚举，否则会有探测面。
package ids

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// 业务前缀。带前缀的标识在日志里可以肉眼区分类型，排障时省一轮猜测。
const (
	PrefixEvent    = "evt"
	PrefixJTI      = "jti"
	PrefixTicket   = "tkt"
	PrefixBindTick = "btk"
	PrefixAuthCode = "ac"
	PrefixTrace    = "tr"
	PrefixMergeOp  = "mrg"
)

// ULID 返回一个新的 ULID 字符串（26 字符 Crockford Base32，时间有序）。
func ULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// New 返回带业务前缀的标识，如 evt_01J8XK...
func New(prefix string) string {
	if prefix == "" {
		return ULID()
	}
	return prefix + "_" + ULID()
}

// IsValid 判断字符串是否为合法 ULID。
func IsValid(s string) bool {
	_, err := ulid.ParseStrict(s)
	return err == nil
}

// RandomToken 返回 n 字节密码学随机数的原始字节，供 refresh_token 等不透明令牌使用。
func RandomToken(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
