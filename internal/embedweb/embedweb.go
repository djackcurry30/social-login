// Package embedweb 把前端构建产物（web/dist）以 go:embed 的形式打进二进制。
//
// 设计依据：架构 §15.6 第 1 项"管理端 SPA 与后端单 binary 部署"。
//
// 工作流（详见 Makefile → web-sync）：
//   1. web/ 下 npm run build → web/dist/
//   2. cp -r web/dist internal/embedweb/dist
//   3. 重新构建 Go 二进制（go:embed 嵌入 dist）
//
// 与 migrations/embed.go 的差异：
//   - migrations 是【必要】资源；
//   - 这里 web/dist 是【可选】：开发模式（无 dist）也能启动，由 vite dev 自服务。
//
// 用 build tag 控制：当 web/dist 不存在时让编译继续，避免"前端没构建就先无法启动后端"。
// 默认（无 build tag）：HasBuild() 返回 false；装配层走"开发模式（vite dev）"。
// 生产构建时直接 go build（无需 build tag）：HasBuild() 自动判 true。
package embedweb

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// FS 返回 fs.Sub(dist) 的结果（去掉顶层 dist 目录）。
//
// 即使 dist 不存在，go:embed 也会编译通过——只是 fs.Sub 会返回空 fs。
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil
	}
	return sub
}

// HasBuild 探测 dist 是否真的有产物（index.html）。
//
// 用法：装配层 if !embedweb.HasBuild() { 走 vite dev proxy } else { embed }。
func HasBuild() bool {
	if embedded == (embed.FS{}) {
		return false
	}
	sub := FS()
	if sub == nil {
		return false
	}
	_, err := fs.Stat(sub, "index.html")
	return err == nil
}