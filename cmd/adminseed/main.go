// Package main 是 admin seed 命令——给本地开发环境写入一个 super_admin 账号。
//
// 用法：
//
//	go run ./cmd/adminseed -username admin -password admin123
//
// 仅用于本地开发与第一期集成测试。生产环境禁止使用此命令；
// 生产的管理员开通由运维侧走"邀请链接 + 首次登录改密码"流程。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
	"github.com/djackcurry30/social-login/internal/pkg/adminx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"

	"go.uber.org/zap"
)

func main() {
	username := flag.String("username", "admin", "管理员用户名")
	password := flag.String("password", "admin12345", "管理员密码（≥8 字符）")
	role := flag.String("role", "super_admin", "角色（super_admin / config_admin / operator / viewer）")
	displayName := flag.String("display-name", "本地开发账号", "显示名")
	dsn := flag.String("dsn", "postgres://postgres:postgres@127.0.0.1:5432/social_login?sslmode=disable", "PostgreSQL DSN")
	flag.Parse()

	if len(*password) < 8 {
		fmt.Fprintln(os.Stderr, "password 必须 ≥8 字符")
		os.Exit(2)
	}
	if !admin.Role(*role).IsValid() {
		fmt.Fprintln(os.Stderr, "非法的 role:", *role)
		os.Exit(2)
	}

	logger := zap.NewNop()
	db, err := postgres.Open(context.Background(), postgres.Config{
		DSN:             *dsn,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: 0,
	}, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接 PG 失败:", err)
		os.Exit(1)
	}

	repo := postgres.NewAdminUserRepository(db)
	hash, err := adminx.HashPassword(*password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "哈希密码失败:", err)
		os.Exit(1)
	}
	inserted, err := repo.Insert(context.Background(), &admin.User{
		Username:     *username,
		PasswordHash: hash,
		DisplayName:  *displayName,
		Role:         admin.Role(*role),
	})
	if err != nil {
		if e, ok := errs.As(err); ok && e.Code == errs.CodeAdminConflict {
			fmt.Fprintf(os.Stderr, "username=%q 已存在；如需重置请走 SQL 直接 UPDATE password_hash（bcrypt cost=12）。\n", *username)
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "插入失败:", err)
		os.Exit(1)
	}
	fmt.Printf("OK  id=%d username=%s role=%s\n", inserted.ID, inserted.Username, inserted.Role)
}