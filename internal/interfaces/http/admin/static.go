// Package admin 中的 static.go：把前端 dist 用 go:embed 提供给浏览器，
// 并实现 SPA fallback：任何不匹配 /admin/v1/* 的 GET 都返回 index.html。
//
// 设计依据：架构 §15.6 第 1 项"管理端 SPA + 单 binary 部署"。
//
// 与 MountAdmin 的差异：
//   - MountAdmin 只挂 /admin/v1/* 的 API 路由
//   - 这里挂 /admin/* 的 static（SPA index.html + assets/）
//
// 顺序很重要：
//   - 先 /assets/*（静态资源，hash 文件名，不会变）
//   - 再 /其它路径（SPA fallback 到 index.html）
//
// 为什么不用 gin 的 NoRoute：那是 404 行为；我们要的是"始终返回 index.html"。
// （React Router 在客户端解析 hash/pushState 后再决定渲染什么组件。）
package admin

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// MountStatic 把前端 dist 挂到 parent 的 /admin 前缀下。
//
// 参数 webFS 是 fs.Sub(dist) 的结果；如果为 nil 则不挂（开发模式）。
// 这样 dev 流程（vite 5173 代理）与生产流程（embed）走同一个装配入口。
func MountStatic(parent *gin.Engine, webFS fs.FS) {
	if webFS == nil {
		return
	}

	// 1. /admin/assets/*：纯静态资源，hash 文件名，长缓存
	parent.StaticFS("/admin/assets", mustSub(webFS, "assets"))

	// 2. /admin/*：SPA fallback
	//    除了 /admin/v1/* 与 /admin/assets/* 外，任何路径都返回 index.html。
	//    React Router 接管前端路由解析。
	indexBytes := readIndex(webFS)

	parent.GET("/admin", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexBytes)
	})
	parent.GET("/admin/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexBytes)
	})

	// 用 NoRoute 是兜底：对于 /admin/login、/admin/apps 等 React Router 路径。
	parent.NoRoute(func(c *gin.Context) {
		// 只对 /admin/* 的 GET 兜底；业务端 NoRoute 在 router.go 已设。
		if !strings.HasPrefix(c.Request.URL.Path, "/admin/") {
			// 不属于管理端的路径（业务端 NoRoute 会接手）。
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		// /admin/v1/* 是 API，不应该返回 HTML。
		if strings.HasPrefix(c.Request.URL.Path, "/admin/v1/") {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexBytes)
	})
}

func mustSub(f fs.FS, dir string) http.FileSystem {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic("admin static: fs.Sub(" + dir + ") 失败: " + err.Error())
	}
	return http.FS(sub)
}

func readIndex(f fs.FS) []byte {
	b, err := fs.ReadFile(f, "index.html")
	if err != nil {
		panic("admin static: 读不到 index.html: " + err.Error())
	}
	return b
}

// 抑制 unused：path 仅在调试时偶尔用；保留 import 防 lint 警告。
var _ = path.Join
