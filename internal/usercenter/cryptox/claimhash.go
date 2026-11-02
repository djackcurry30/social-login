// Package cryptox 提供凭证的哈希与信封加密。
//
// 为什么本服务自己实现一份，而不复用 social-login 的 infrastructure/crypto：
//
//   - 那个包的 ClaimHasher 签名依赖 social-login 的 app_id（本地自增主键），
//     而本服务的 app_id 是另一个库的主键，两套编号毫无关系。直接复用会把
//     "看起来是同一套标识"这个错觉写进代码。
//   - 那个包的 Resolve 依赖 social-login 的 tenant 领域类型。
//     本服务只需要"加密一个字符串、解密一个字符串"。
//
// 算法本身（HMAC-SHA256 派生 + AES-256-GCM）必须与之一致：
// 这不是复用代码，而是两边对同一类数据用同一套可审计的做法。
package cryptox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// HashVersion 是当前哈希算法/盐的版本号，写入 account_claims.hash_version。
//
// 换盐或换算法时，新数据写新版本、老数据保留旧版本，查询时按版本分别计算
// 并合并结果——这样"换盐"是一次可灰度的迁移，而不是一次全表重算的停机。
const HashVersion int16 = 1

// MinSaltLen 是盐的最小长度。
//
// 8 字节的下限很低，但它拦的是"忘了配置、用了空盐"这种事故：
// 空盐下 HMAC 退化成裸 SHA256，手机号空间只有 11 位数字，
// 彩虹表几秒钟就能反查全部。
const MinSaltLen = 8

// ClaimHasher 计算凭证的匹配哈希。
//
// 盐按应用派生（HMAC 的 key 是全局盐，消息里带 appID），因此：
//   - 同一应用、同一类型、同一归一化值 ⇒ 恒等（按手机号反查成立）
//   - 跨应用同一手机号 ⇒ 哈希不同（即使拿到库也无法跨租户关联，
//     这是 C1 隔离的纵深防御，而不是功能需求）
type ClaimHasher struct {
	salt []byte
}

// NewClaimHasher 构造哈希器。
func NewClaimHasher(salt []byte) (*ClaimHasher, error) {
	if len(salt) < MinSaltLen {
		return nil, domain.New(domain.CodeInternal,
			"凭证哈希盐过短：至少需要 8 字节（security.claim_salt）")
	}
	cp := make([]byte, len(salt))
	copy(cp, salt)
	return &ClaimHasher{salt: cp}, nil
}

// Hash 计算 value_hash（32 字节）。
//
// 消息布局：appID(8, 大端) || len(type)(4) || type || len(value)(4) || value。
//
// 用【长度前缀】而不是分隔符：分隔符方案下 ("a", "\x00b") 与 ("a\x00", "b")
// 会拼出同一条消息，从而哈希相同——这是单测抓到的真实碰撞（见
// TestHashRejectsSeparatorCollision）。长度前缀让字段边界由字节数决定，
// 与内容无关，不依赖调用方"值里不许出现分隔符"这种口头纪律。
func (h *ClaimHasher) Hash(appID int64, claimType, normalizedValue string) []byte {
	mac := hmac.New(sha256.New, h.salt)

	var idBuf [8]byte
	binary.BigEndian.PutUint64(idBuf[:], uint64(appID))
	mac.Write(idBuf[:])
	writeLenPrefixed(mac, claimType)
	writeLenPrefixed(mac, normalizedValue)
	return mac.Sum(nil)
}

// writeLenPrefixed 写入 4 字节长度前缀 + 内容。
func writeLenPrefixed(mac hash.Hash, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	mac.Write(n[:])
	mac.Write([]byte(s))
}

// Version 返回当前哈希版本。
func (h *ClaimHasher) Version() int16 { return HashVersion }
