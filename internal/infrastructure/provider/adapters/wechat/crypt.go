package wechat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// encryptedPhone 是 getPhoneNumber 的加密数据结构（旧版，依赖 session_key）。
type encryptedPhone struct {
	PhoneNumber     string `json:"phoneNumber"`
	PurePhoneNumber string `json:"purePhoneNumber"`
	CountryCode     string `json:"countryCode"`
	Watermark       struct {
		AppID     string `json:"appid"`
		Timestamp int64  `json:"timestamp"`
	} `json:"watermark"`
}

// decryptPhone 解密微信小程序 getPhoneNumber 返回的加密数据。
//
// 算法：AES-128-CBC，key = base64(session_key)，iv = base64(iv)，
// 明文按 PKCS#7 填充。这是微信官方文档给出的固定算法，不要"优化"。
//
// 必须校验 watermark.appid：session_key 与 appid 绑定，但密文是前端回传的，
// 不校验就可以把另一个小程序的密文拿来充数（跨 appid 重放）。
func decryptPhone(sessionKeyB64, encryptedB64, ivB64, expectAppID string) (phoneNumber, purePhone string, err error) {
	if sessionKeyB64 == "" {
		return "", "", errs.New(errs.CodeAuthInvalidState,
			"缺少 session_key，无法解密手机号；请确认先完成 code2session 再提交加密数据").
			WithDetail("hint", "新接入建议改用 phone_code（getPhoneNumber 新版返回的 code）")
	}
	key, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "session_key 不是合法 base64", err)
	}
	if len(key) != 16 {
		// AES-128 要求 16 字节。长度不对通常意味着 session_key 来自另一个 appid
		// 或已被换成别的东西，不是"稍后重试"能解决的。
		return "", "", errs.New(errs.CodeAuthInvalidState, "session_key 长度非法（期望 AES-128 的 16 字节）").
			WithDetail("key_bytes", len(key))
	}
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil || len(iv) != aes.BlockSize {
		return "", "", errs.New(errs.CodeAuthInvalidState, "iv 非法（必须是 16 字节的 base64）")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "encrypted_data 不是合法 base64", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", "", errs.New(errs.CodeAuthInvalidState, "密文长度非法（必须是 16 的整数倍）")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "构造 AES 解密器失败", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)

	plain, err = pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		// 解填充失败几乎总是"key 不对"（session_key 过期或被换过）。
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "解密手机号失败（session_key 可能已过期）", err)
	}

	var out encryptedPhone
	if err := json.Unmarshal(plain, &out); err != nil {
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "解密结果不是预期的手机号结构", err)
	}
	if expectAppID != "" && out.Watermark.AppID != "" && out.Watermark.AppID != expectAppID {
		return "", "", errs.New(errs.CodeAuthInvalidState, "手机号密文的 watermark.appid 与当前应用不一致").
			WithDetail("watermark_appid", out.Watermark.AppID).
			WithDetail("expect", expectAppID)
	}
	if out.PurePhoneNumber == "" && out.PhoneNumber == "" {
		return "", "", errs.New(errs.CodeProviderRejected, "解密结果中没有手机号")
	}
	pure := out.PurePhoneNumber
	if pure == "" {
		pure = out.PhoneNumber
	}
	return out.PhoneNumber, pure, nil
}

// pkcs7Unpad 去掉 PKCS#7 填充，并校验填充字节的合法性。
func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errs.New(errs.CodeAuthInvalidState, "非法填充：密文长度不是块大小的整数倍")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > blockSize || pad > len(b) {
		return nil, errs.New(errs.CodeAuthInvalidState, "非法填充：填充字节越界")
	}
	if !bytes.Equal(b[len(b)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errs.New(errs.CodeAuthInvalidState, "非法填充：填充内容不一致")
	}
	return b[:len(b)-pad], nil
}
