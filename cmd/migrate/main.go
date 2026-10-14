// Command migrate 单独执行数据库迁移。
//
// 为什么需要一个独立命令，而不是只靠服务启动时自动迁移：
// 生产环境（server.mode=release）强制关闭自动迁移（见 bootstrap 配置校验）。
// 让应用启动顺带改 schema 有三个具体风险：
//
//  1. 多副本滚动发布时会并发执行同一批迁移，DDL 竞争可能产生半完成状态
//  2. 迁移失败会让整个新版本无法启动，回滚只能靠人工介入
//  3. 慢 DDL（加索引、改类型）会阻塞启动健康检查，把发布超时误报成服务故障
//
// 正确做法是发布流程里先跑本命令，成功后再滚动更新应用实例。
//
// 用法：
//
//	go run ./cmd/migrate -config configs/config.yaml -dir up
//	go run ./cmd/migrate -config configs/config.yaml -dir down
//	go run ./cmd/migrate -config configs/config.yaml -dir status
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"

	"github.com/pressly/goose/v3"

	"github.com/alex/social-login/internal/bootstrap"
	"github.com/alex/social-login/internal/infrastructure/persistence/postgres"
	"github.com/alex/social-login/migrations"
)

func main() {
	var (
		configPath = flag.String("config", "configs/config.yaml", "配置文件路径")
		dir        = flag.String("dir", "status", "up | down | status | version")
		steps      = flag.Int("steps", 1, "down 时的回退步数（默认 1 步；回退全部请传很大的值）")
		dsn        = flag.String("dsn", "", "直接指定数据库 DSN（优先于配置文件）")
	)
	flag.Parse()

	ctx := context.Background()

	cfg, err := bootstrap.Load(*configPath)
	if err != nil {
		fail("加载配置失败", err)
	}
	// 迁移命令刻意绕过"生产禁止自动迁移"的校验：它就是被禁掉的那个自动迁移的替代品。
	if *dsn == "" {
		*dsn = cfg.Database.DSN
	}
	if *dsn == "" {
		fail("数据库 DSN 未配置", nil)
	}

	db, err := postgres.Open(ctx, postgres.Config{
		DSN:          *dsn,
		MaxOpenConns: 2,
		MaxIdleConns: 2,
	}, nil)
	if err != nil {
		fail("连接数据库失败", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		fail("获取数据库连接失败", err)
	}
	defer func() { _ = sqlDB.Close() }()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		fail("设置迁移方言失败", err)
	}
	goose.SetLogger(stdoutLogger{})

	if err := run(sqlDB, *dir, *steps); err != nil {
		fail("迁移执行失败", err)
	}
	fmt.Println("完成。")
}

func run(db *sql.DB, dir string, steps int) error {
	switch dir {
	case "up":
		return goose.Up(db, ".")
	case "down":
		// 回退是高风险操作：默认只回退一步，需要全量回退必须显式指定 -steps。
		if steps > 0 {
			current, err := goose.GetDBVersion(db)
			if err != nil {
				return err
			}
			target := current - int64(steps)
			if target < 0 {
				target = 0
			}
			fmt.Printf("回退 schema 版本 %d → %d\n", current, target)
			return goose.DownTo(db, ".", target)
		}
		return goose.Down(db, ".")
	case "status":
		return goose.Status(db, ".")
	case "version":
		v, err := goose.GetDBVersion(db)
		if err != nil {
			return err
		}
		fmt.Printf("当前 schema 版本: %d\n", v)
		return nil
	default:
		return fmt.Errorf("未知的 -dir 取值: %s（可选 up | down | status | version）", dir)
	}
}

// stdoutLogger 把 goose 日志打到 stdout。
type stdoutLogger struct{}

func (stdoutLogger) Printf(format string, v ...any) { fmt.Printf(format+"\n", v...) }
func (stdoutLogger) Fatalf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
	os.Exit(1)
}

func fail(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(1)
}
