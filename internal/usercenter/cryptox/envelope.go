package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// KeySize 是 AES-256 密钥长度。
const KeySize = 32

// aadPrefix 参与 AES-GCM 的附加认证数据。
//
// 与 dekID 一起做 AAD 的作用：密文被搬到另一行、或用另一把密钥解时，
// GCM 校验直接失败，而不是"解出一段看起来像手机号的乱码"。
// 静默错值比报错危险得多——它会以"用户手机号变了"的形式出现在登录链路上。
const aadPrefix = "uc:claim:v1:"

// Envelope 用本地主密钥做信封加密。
//
// 密文格式：nonce(12) || ciphertext || tag(16)，整体写 BYTEA。
// 不单独存 wrapped DEK——本实现用"主密钥 + dek_id"表达密钥版本，
// 接 KMS 后（E7）由 KMS 管理 DEK，密文格式不变。
//
// 支持多把密钥共存（AddKey），因为一旦轮换主密钥，历史密文必须仍能解开；
// 只支持一把密钥的实现会让"轮换"变成"全部历史凭证不可读"。
type Envelope struct {
	current string
	aeads   map[string]cipher.AEAD
}

// NewEnvelope 构造加密器并登记当前密钥。
func NewEnvelope(dekID string, key []byte) (*Envelope, error) {
	e := &Envelope{aeads: make(map[string]cipher.AEAD, 2)}
	if err := e.AddKey(dekID, key); err != nil {
		return nil, err
	}
	e.current = dekID
	return e, nil
}

// AddKey 登记一把密钥（轮换过渡期用）。
//
// 后登记的成为当前密钥：新写入用新密钥，旧密文按 dek_id 找到旧密钥解。
func (e *Envelope) AddKey(dekID string, key []byte) error {
	if dekID == "" {
		return domain.New(domain.CodeInternal, "dek_id 不能为空")
	}
	if len(key) != KeySize {
		return domain.Newf(domain.CodeInternal,
			"主密钥长度必须为 %d 字节，当前 %d 字节", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return domain.New(domain.CodeInternal, "初始化 AES 失败").WithCause(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return domain.New(domain.CodeInternal, "初始化 GCM 失败").WithCause(err)
	}
	e.aeads[dekID] = aead
	e.current = dekID
	return nil
}

// CurrentDEKID 返回当前密钥版本，写库时落进 account_claims.dek_id。
func (e *Envelope) CurrentDEKID() string { return e.current }

// Seal 加密明文，返回密文。
func (e *Envelope) Seal(plaintext string) ([]byte, error) {
	aead := e.aeads[e.current]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, domain.New(domain.CodeInternal, "生成随机数失败").WithCause(err)
	}
	return aead.Seal(nonce, nonce, []byte(plaintext), []byte(aadPrefix+e.current)), nil
}

// Open 按 dek_id 选择密钥解密。
func (e *Envelope) Open(ciphertext []byte, dekID string) (string, error) {
	aead, ok := e.aeads[dekID]
	if !ok {
		// 明确报"密钥版本缺失"，而不是拿当前密钥硬解：
		// 后者会失败但错误信息指向"密文损坏"，排障方向完全错误。
		return "", domain.Newf(domain.CodeInternal, "缺少密钥版本 %q 对应的主密钥", dekID)
	}
	ns := aead.NonceSize()
	if len(ciphertext) < ns+aead.Overhead() {
		return "", domain.New(domain.CodeInternal, "凭证密文长度非法")
	}
	plain, err := aead.Open(nil, ciphertext[:ns], ciphertext[ns:], []byte(aadPrefix+dekID))
	if err != nil {
		return "", domain.New(domain.CodeInternal, "凭证解密失败（密钥不匹配或密文损坏）").WithCause(err)
	}
	return string(plain), nil
}

// GenerateKey 生成随机主密钥（仅供开发环境引导）。
//
// 生产的主密钥由密钥管理系统下发，不通过本函数——
// "启动时随机生成"在生产会造成每次重启后历史密文全部不可读。
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	return key, nil
}

// EncodeKey 把主密钥编码成可写入配置的 Base64。
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// DecodeKey 解析配置里的主密钥。
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, domain.New(domain.CodeInternal, "security.master_key 不是合法的 Base64").WithCause(err)
	}
	if len(key) != KeySize {
		return nil, domain.Newf(domain.CodeInternal,
			"security.master_key 长度必须为 %d 字节，当前 %d 字节", KeySize, len(key))
	}
	return key, nil
}
