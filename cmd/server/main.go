// Command server 是三方登录统一接入服务的入口。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alex/social-login/internal/bootstrap"
)

func main() {
	var (
		configPath  = flag.String("config", "configs/config.yaml", "配置文件路径")
		showVersion = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(bootstrap.Version)
		return
	}

	// 用 signal.NotifyContext：ctx 取消即触发优雅退出，
	// 不需要在业务代码里到处判断信号。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := bootstrap.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	app, err := bootstrap.New(ctx, bootstrap.Options{Config: cfg})
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}

	if err := app.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "运行失败: %v\n", err)
		os.Exit(1)
	}
}
