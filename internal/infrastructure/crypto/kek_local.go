package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// LocalKEK 是"主密钥放在配置/环境变量里"的实现，用于开发环境与尚未接入
// KMS 的部署。
//
// ⚠️ 它不是生产形态：主密钥与密文同处一套凭证体系里，泄漏一把就等于
// 泄漏全部密文。真正的隔离要求密钥存放在 KMS 中、只在调用瞬间使用。
type LocalKEK struct {
	keyID string
	aead  cipher.AEAD
}

var (
	_ KEK             = (*LocalKEK)(nil)
	_ LegacyDecrypter = (*LocalKEK)(nil)
)

// NewLocalKEK 构造本地 KEK。masterKey 必须是 32 字节。
func NewLocalKEK(keyID string, masterKey []byte) (*LocalKEK, error) {
	if keyID == "" {
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
	return &LocalKEK{keyID: keyID, aead: aead}, nil
}

// KeyID 实现 KEK。
func (k *LocalKEK) KeyID() string { return k.keyID }

// Wrap 用主密钥加密一个 DEK。
//
// AAD 用固定标签而不是 keyID：DEK 的密文会被 rewrap（换 KEK 但保留数据密文），
// 若把 keyID 绑进 AAD，换密钥时这份密文就必须重算——那正是信封加密要避免的。
// "这把 DEK 属于哪把 KEK"由 KMS/主密钥自身保证（解不开就是解不开）。
func (k *LocalKEK) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, errs.New(errs.CodeInternal, "待包装的数据密钥为空")
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成随机数失败", err)
	}
	return k.aead.Seal(nonce, nonce, dek, []byte(aadDEK)), nil
}

// Unwrap 解密一个 DEK。
func (k *LocalKEK) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(wrapped) < ns+k.aead.Overhead() {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "被包装的数据密钥格式非法")
	}
	dek, err := k.aead.Open(nil, wrapped[:ns], wrapped[ns:], []byte(aadDEK))
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "数据密钥解包失败（KEK 不匹配或密文损坏）", err)
	}
	return dek, nil
}

// DecryptLegacy 解开 v1 密文：AAD 是当时的 kekID，直接用主密钥加密数据。
//
// 版本号不匹配时给出明确错误，而不是让 GCM 报"message authentication failed"——
// 后者会让运维去怀疑密文损坏，而真相只是"配置里的 kek_id 被改过"。
func (k *LocalKEK) DecryptLegacy(ciphertext []byte, kekID string) (string, error) {
	if kekID != "" && kekID != k.keyID {
		return "", errs.Newf(errs.CodeAuthInvalidConfig,
			"该凭据由 %s 加密，当前主密钥是 %s：旧格式（v1）无法跨版本解密，请用 keyrewrap 迁移",
			kekID, k.keyID)
	}
	ns := k.aead.NonceSize()
	if len(ciphertext) < ns+k.aead.Overhead() {
		return "", errs.New(errs.CodeAuthInvalidConfig, "凭据密文格式非法")
	}
	plain, err := k.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], []byte(k.keyID))
	if err != nil {
		return "", errs.Wrap(errs.CodeAuthInvalidConfig, "凭据解密失败（主密钥不匹配或密文损坏）", err)
	}
	return string(plain), nil
}
