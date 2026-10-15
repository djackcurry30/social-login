// Package adminx 提供管理端的横切工具（当前仅密码哈希）。
//
// 为什么不放在 domain/admin：
// 1. domain 不应该感知具体哈希算法（bcrypt/scrypt/argon2 切换是 infra 的事）；
// 2. domain 只暴露"能不能匹配"这个端口，把哈希/校验的具体实现下沉到 infra/crypto 同层；
// 3. 跟 auditx 保持一致风格（横切工具 = 独立小包）。
package adminx

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost 是 bcrypt 的 cost 值。
//
// 选 12 的原因：12 ≈ 250ms 单次哈希（CPU 单核），对正常登录是用户可感知但可接受；
// 对暴力枚举，每多一位 cost 大约慢 2 倍——12 在 2026 年的硬件上足够让 6 位纯数字密码
// 难被爆。低于 12 是被业内反复劝退的选择（OWASP 推荐 ≥12）。
const BcryptCost = 12

// ErrPasswordMismatch 是密码比对失败的对外错误。
//
// 与 domain/admin.ErrInvalidCredentials 区分：本包是"哈希对不上"，
// domain 是"用户不存在 / 密码错 / 账号停用"统一对外包装。中间层负责合并。
var ErrPasswordMismatch = errors.New("adminx: password mismatch")

// HashPassword 返回 bcrypt(cost=12) 哈希。
//
// 返回的字符串可以直接入库；不要做任何二次处理。
func HashPassword(plain string) (string, error) {
	if len(plain) < 8 {
		return "", fmt.Errorf("adminx: 密码长度不足 8 位")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("adminx: 生成密码哈希失败: %w", err)
	}
	return string(b), nil
}

// VerifyPassword 校验明文密码与哈希是否匹配。
//
// 不匹配返回 ErrPasswordMismatch；其它错误（如哈希格式错乱）也返回非 nil 包装错。
func VerifyPassword(hash, plain string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return fmt.Errorf("adminx: 校验密码失败: %w", err)
	}
	return nil
}
