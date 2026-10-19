package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"sort"
	"strings"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// loadPrivateKey 解析应用私钥（PEM 或裸 base64 的 PKCS#1/PKCS#8）。
//
// 支付宝开放平台同时提供两种形态：工具生成的多为 PKCS#8 PEM，
// 老控制台给的是不带 PEM 头的 base64。两种都接受，但报错要能区分——
// "私钥格式不对"和"私钥与 app_id 不匹配"是两类完全不同的排查方向。
func loadPrivateKey(raw string) (*rsa.PrivateKey, error) {
	der, err := decodeKeyMaterial(raw, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig,
			"支付宝应用私钥格式非法（需 PKCS#1 或 PKCS#8）")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "支付宝应用私钥不是 RSA 私钥")
	}
	return rk, nil
}

// loadPublicKey 解析支付宝公钥（用于响应验签）。
func loadPublicKey(raw string) (*rsa.PublicKey, error) {
	der, err := decodeKeyMaterial(raw, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			return rk, nil
		}
	}
	if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rk, nil
	}
	return nil, errs.New(errs.CodeAuthInvalidConfig, "支付宝公钥格式非法")
}

func decodeKeyMaterial(raw, blockType string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errs.Newf(errs.CodeAuthInvalidConfig, "缺少 %s", blockType)
	}
	if strings.Contains(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errs.Newf(errs.CodeAuthInvalidConfig, "%s 的 PEM 解析失败", blockType)
		}
		return block.Bytes, nil
	}
	// 裸 base64：去掉可能的空白与换行。
	s = strings.Join(strings.Fields(s), "")
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errs.Newf(errs.CodeAuthInvalidConfig, "%s 不是合法 base64 或 PEM", blockType).
			WithDetail("decode_error", err.Error())
	}
	return der, nil
}

// signContent 按支付宝规则拼接待签名串：
// 过滤空值与 sign 本身，其余按 key 的字节序升序，以 k=v 用 & 连接。
//
// 这里必须用【原始值】—— 不能再做一次 URL 编码。支付宝是先对参数排序签名、
// 再对整体做表单编码，顺序颠倒会导致"本地验签通过、平台判定签名错误"。
func signContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	return b.String()
}

// signParams 对参数做 RSA2（SHA256withRSA）签名。
func signParams(params map[string]string, key *rsa.PrivateKey) (string, error) {
	sig, err := signRawBytes([]byte(signContent(params)), key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// signRawBytes 对任意字节做 SHA256withRSA 签名（原始签名值）。
func signRawBytes(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	sum := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "支付宝请求签名失败", err)
	}
	return sig, nil
}

// verifyNode 校验响应节点的签名。
//
// rawNode 必须是响应 JSON 中该节点的【原始字节】。用 json.RawMessage 拿到的
// 就是原始片段（含空白），这正是支付宝验签所要求的——重新序列化会改变字节，
// 导致签名永远对不上。
func verifyNode(rawNode []byte, signB64 string, pub *rsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(signB64)
	if err != nil {
		return errs.Wrap(errs.CodeAuthInvalidConfig, "支付宝响应签名不是合法 base64", err)
	}
	return verifyRawBytes(rawNode, sig, pub)
}

// verifyRawBytes 校验任意字节的 SHA256withRSA 签名。
func verifyRawBytes(data, sig []byte, pub *rsa.PublicKey) error {
	sum := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return errs.New(errs.CodeProviderRejected,
			"支付宝响应验签失败（可能是公钥配置错误，或响应被篡改）").
			WithDetail("hint", "确认 extra.alipay_public_key 是【支付宝公钥】而不是应用公钥")
	}
	return nil
}

// verifyRaw 校验字符串内容的签名（测试与排障用）。
func verifyRaw(content string, sig []byte, pub *rsa.PublicKey) error {
	return verifyRawBytes([]byte(content), sig, pub)
}
