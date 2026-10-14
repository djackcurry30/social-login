package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// AppSecretHasher 计算并校验应用密钥（app_secret）的哈希。
//
// ⚠️ 为什么用 SHA-256 而不是 bcrypt / argon2（tech-stack §3.9）：
// app_secret 是 32 字节的密码学随机串，熵足够高，不存在"被暴力枚举"的风险；
// 慢哈希在这里的唯一效果是让每一次带凭据的 API 调用白付几十毫秒 CPU。
// 慢哈希适用于低熵的用户口令，而本服务不存用户口令。
//
// 加静态盐的理由不是抗暴力破解，而是防止"同一个 secret 在别处出现时被关联"——
// 属于纵深防御，成本为零。
type AppSecretHasher struct {
	salt []byte
}

// NewAppSecretHasher 构造校验器。salt 应来自配置且不进版本库。
func NewAppSecretHasher(salt []byte) *AppSecretHasher {
	return &AppSecretHasher{salt: salt}
}

// Hash 返回密钥的存储哈希（十六进制）。
func (h *AppSecretHasher) Hash(secret string) string {
	mac := hmac.New(sha256.New, h.salt)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify 以恒定时间比较，避免通过响应耗时逐字节试探密钥。
//
// 用 constant-time 比较而不是 ==：Go 的字符串比较会在首个不同字节处提前返回，
// 理论上允许攻击者通过测量耗时逐字节还原哈希。这类攻击在网络的噪声下不现实，
// 但恒定时间比较的成本只有一个函数调用，没有理由不做。
func (h *AppSecretHasher) Verify(secret, storedHash string) bool {
	if secret == "" || storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h.Hash(secret)), []byte(storedHash)) == 1
}
