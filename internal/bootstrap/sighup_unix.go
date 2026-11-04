//go:build !windows

package bootstrap

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

// watchReloadSignal 监听 SIGHUP 并触发配置热更新。
//
// 为什么保留 SIGHUP 而不是只做管理端接口：
//
//	容器外（systemd / 传统虚机）运维的习惯就是 `kill -HUP <pid>`，
//	它不需要管理端账号，也不会因为管理端不可用而失效。
//	但容器里 SIGHUP 经常收不到（PID 1 的默认信号语义），所以接口是主路径，
//	这里只是补一条顺手的旁路。
func (a *App) watchReloadSignal(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if _, err := a.reloader.Reload(); err != nil {
				// 日志级别调整失败不能拖垮进程：旧配置继续生效。
				a.log.Warn("SIGHUP 触发的配置热更新失败，保持原配置", zap.Error(err))
			}
		}
	}
}
