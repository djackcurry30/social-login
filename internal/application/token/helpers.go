package token

import "encoding/base64"

// base64URL 用 URL 安全且无填充的 Base64 编码随机令牌。
//
// 用无填充变体（RawURLEncoding）是因为刷新令牌会出现在 URL 表单与日志中，
// '=' 填充字符在这些位置容易被截断或转义，是"偶发 401"的常见来源。
func base64URL(buf []byte) string {
	return base64.RawURLEncoding.EncodeToString(buf)
}
