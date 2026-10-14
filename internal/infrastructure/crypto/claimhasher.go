package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/alex/social-login/internal/domain/identity"
)

// ClaimHasher 用【应用级静态盐】计算凭证的匹配哈希。
//
// ⚠️ 这是本项目最容易踩的一个坑（tech-stack §3.9）：如果图省事用每行随机盐，
// 同一个手机号每次会算出不同哈希，"按手机号反查身份"这个功能会直接失效，
// 而归并判定完全依赖它。
//
// 这里用 HMAC-SHA256(masterSalt, appID || claimType || value)：
//   - 对同一应用、同一凭证类型、同一归一化值，结果恒等 → 功能成立
//   - 盐由 masterSalt 与 appID 派生，因此【跨应用无法关联】同一手机号，
//     这正好是约束 C1（账号按业务应用隔离）想要的效果
//   - 明文不落库，只存哈希；需要回显时另有 claim_value_cipher 密文列
type ClaimHasher struct {
	masterSalt []byte
}

// NewClaimHasher 构造哈希器。masterSalt 应来自配置且不进版本库。
func NewClaimHasher(masterSalt []byte) *ClaimHasher {
	return &ClaimHasher{masterSalt: masterSalt}
}

// Hash 计算匹配哈希，返回 64 位十六进制字符串（256 bit）。
//
// 签名与 identity.ClaimHasher 端口一致，可直接注入领域层。
func (h *ClaimHasher) Hash(appID int64, claimType, normalizedValue string) string {
	mac := hmac.New(sha256.New, h.masterSalt)

	var idBuf [8]byte
	binary.BigEndian.PutUint64(idBuf[:], uint64(appID))
	mac.Write(idBuf[:])
	mac.Write([]byte{0})
	mac.Write([]byte(claimType))
	mac.Write([]byte{0})
	mac.Write([]byte(normalizedValue))

	return hex.EncodeToString(mac.Sum(nil))
}

// 编译期断言：ClaimHasher 满足领域层端口。
var _ identity.ClaimHasher = (*ClaimHasher)(nil)
