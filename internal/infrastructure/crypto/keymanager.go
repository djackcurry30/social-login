// Package crypto 提供渠道凭据的信封加密与凭证哈希。
//
// 现状与演进（决策 D6）：第一期用【本地主密钥】实现信封加密，密文写入
// app_provider_configs.secret_cipher，secret_dek_id 记录密钥版本（kid）。
// 第四期把本地主密钥换成 KMS 托管，只需替换本包实现——因为上层只依赖
// tenant.SecretResolver 这一端口，不依赖具体加密方式。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// MasterKeySize 是主密钥长度（AES-256）。
const MasterKeySize = 32

// KeyManager 用本地主密钥做信封加密。
//
// 密文格式：nonce(12) || ciphertext || tag(16)，整体写入 BYTEA 字段。
// 不额外存储 wrapped DEK——schema 里只有 secret_dek_id 一列，因此本实现
// 用"主密钥 + kid"的方式表达密钥版本；换成真 KMS 后，DEK 与 wrapped DEK
// 由 KMS 管理，密文格式不变。
type KeyManager struct {
	kekID string
	aead  cipher.AEAD
}

// NewKeyManager 构造密钥管理器。masterKey 必须是 32 字节。
func NewKeyManager(kekID string, masterKey []byte) (*KeyManager, error) {
	if kekID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "主密钥版本标识（kekID）不能为空")
	}
	if len(masterKey) != MasterKeySize {
		return nil, errs.Newf(errs.CodeAuthInvalidConfig,
			"主密钥长度必须为 %d 字节，当前 %d 字节", MasterKeySize, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "初始化加密算法失败", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "初始化 GCM 失败", err)
	}
	return &KeyManager{kekID: kekID, aead: aead}, nil
}

// KEKID 返回主密钥版本标识。
func (k *KeyManager) KEKID() string { return k.kekID }

// Encrypt 加密明文，返回 nonce||ciphertext||tag。
func (k *KeyManager) Encrypt(plaintext string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成随机数失败", err)
	}
	// 把 kekID 作为附加认证数据：换密钥版本后旧密文无法被新密钥解出，
	// 避免"轮换后误用错误密钥解出乱码"这种静默故障。
	out := k.aead.Seal(nonce, nonce, []byte(plaintext), []byte(k.kekID))
	return out, nil
}

// Decrypt 解密。
func (k *KeyManager) Decrypt(ciphertext []byte) (string, error) {
	ns := k.aead.NonceSize()
	if len(ciphertext) < ns+k.aead.Overhead() {
		return "", errs.New(errs.CodeAuthInvalidConfig, "凭据密文格式非法")
	}
	plain, err := k.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], []byte(k.kekID))
	if err != nil {
		return "", errs.Wrap(errs.CodeAuthInvalidConfig, "凭据解密失败（主密钥不匹配或密文损坏）", err)
	}
	return string(plain), nil
}

// Resolve 实现 tenant.SecretResolver：把渠道配置中的密文解成明文。
//
// previous 用于密钥轮换过渡期（扩展性 E6）：平台侧新旧 secret 同时有效时，
// 校验失败可以再用上一版重试一次。
func (k *KeyManager) Resolve(cfg *tenant.ProviderConfig) (current string, previous string, err error) {
	if cfg == nil {
		return "", "", errs.New(errs.CodeAuthInvalidConfig, "渠道配置为空")
	}
	if len(cfg.SecretCipher) == 0 {
		// 无凭据的渠道是合法的（如 PKCE + 公开客户端、自定义 OAuth2 无需 secret）。
		return "", "", nil
	}
	current, err = k.Decrypt(cfg.SecretCipher)
	if err != nil {
		return "", "", err
	}
	if len(cfg.SecretCipherPrev) > 0 {
		if prev, perr := k.Decrypt(cfg.SecretCipherPrev); perr == nil {
			previous = prev
		}
		// 上一版解不开不是错误：可能用了不同的 kekID，只影响轮换过渡期能力。
	}
	return current, previous, nil
}

// GenerateMasterKey 生成一把随机主密钥，供开发环境引导使用。
// 生产环境的主密钥应由 KMS 或密钥管理系统的引导流程提供，不通过本函数。
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	return key, nil
}

// EncodeMasterKey 把主密钥编码为配置文件中可安全书写的 Base64 字符串。
func EncodeMasterKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// DecodeMasterKey 解析配置文件中的主密钥。
func DecodeMasterKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "主密钥不是合法的 Base64", err)
	}
	if len(key) != MasterKeySize {
		return nil, errs.Newf(errs.CodeAuthInvalidConfig,
			"主密钥长度必须为 %d 字节，当前 %d 字节", MasterKeySize, len(key))
	}
	return key, nil
}
