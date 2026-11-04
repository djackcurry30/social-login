//go:build windows

package bootstrap

import "context"

// watchReloadSignal 在 Windows 上是空实现。
//
// Windows 没有 SIGHUP，信号驱动的热更新无从谈起；热更新走管理端
// POST /admin/v1/config/reload。保留同名方法是为了让 App.Run 不必写平台判断。
func (a *App) watchReloadSignal(ctx context.Context) {
	<-ctx.Done()
}
