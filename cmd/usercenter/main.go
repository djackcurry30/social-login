// Command usercenter 是用户中心（账号主数据服务）的入口。
//
// 它的职责边界很小，刻意的（docs/user-center-mvp-design.md §1）：
// 只持有账号主数据与凭证唯一性，不做登录、不做令牌、不做权限。
// 因此它没有 Redis、没有会话、没有三方渠道，只依赖 PostgreSQL。
//
// 用法：
//
//	usercenter -config configs/usercenter.yaml                # 启动服务
//	usercenter -config configs/usercenter.yaml -migrate up     # 只执行迁移
//	usercenter -migrate status -dsn "postgres://..."           # 不读配置文件看迁移状态
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/djackcurry30/social-login/internal/usercenter/app"
	"github.com/djackcurry30/social-login/internal/usercenter/config"
	"github.com/djackcurry30/social-login/internal/usercenter/observe"
)

func main() {
	var (
		configPath  = flag.String("config", "configs/usercenter.yaml", "配置文件路径")
		migrate     = flag.String("migrate", "", "只执行迁移后退出：up / down / status")
		dsn         = flag.String("dsn", "", "覆盖配置文件里的 database.dsn（供 -migrate 使用）")
		showVersion = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(app.Version)
		return
	}

	// 迁移是独立进程语义：跑完就退出，不启动 HTTP。
	// 生产发布流程显式调用它，配置里必须关掉 migrate.enabled——
	// 让应用启动顺带改 schema，在多副本滚动发布时会并发迁移。
	if *migrate != "" {
		if err := runMigrate(*configPath, *dsn, *migrate); err != nil {
			fmt.Fprintf(os.Stderr, "迁移失败: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	a, err := app.New(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}

	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "运行失败: %v\n", err)
		os.Exit(1)
	}
}

// runMigrate 组装一个只够跑迁移的最小环境。
//
// 只读配置文件里的 database.dsn，不校验 service_token 之类的运行期必填项：
// 迁移通常在服务还没配好凭证的部署窗口执行，那时因为"缺 token"而拒绝迁移
// 只会逼人去临时改配置。
func runMigrate(configPath, dsnOverride, direction string) error {
	dsn := dsnOverride
	if dsn == "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		dsn = cfg.Database.DSN
	}

	log, err := observe.NewLogger("info", "console", "")
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	return app.Migrate(context.Background(), dsn, direction, log)
}
