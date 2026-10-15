// Package adminx 的密码工具测试。
package adminx

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	// bcrypt 哈希以 $2a$ 开头
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("哈希格式不像 bcrypt: %s", hash)
	}

	if err := VerifyPassword(hash, "correct-horse-battery"); err != nil {
		t.Errorf("正确密码应校验通过，实际返回: %v", err)
	}

	if err := VerifyPassword(hash, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("错误密码应返回 ErrPasswordMismatch，实际: %v", err)
	}
}

func TestHashShortPassword(t *testing.T) {
	_, err := HashPassword("short")
	if err == nil {
		t.Errorf("8 位以下密码应被拒绝")
	}
}

// 同一明文两次哈希必须不同（bcrypt 随机 salt）—— 防止"两账号同密码能扫到"。
func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same-password-1234")
	b, _ := HashPassword("same-password-1234")
	if a == b {
		t.Errorf("bcrypt 哈希应带随机 salt，两次不应相同")
	}
}
