// Package admin 是管理端（/admin/v1/*）的 HTTP 接入层入口。
//
// 设计依据：架构 §15.2 与 §15.6。
//
// 路由组（按 §15.4 第一期交付范围）：
//   - A 组（应用与策略）        internal/interfaces/http/admin/handler/apps.go
//   - B 组（渠道配置 + verify）  internal/interfaces/http/admin/handler/provider_configs.go
//   - I 组（观测）              internal/interfaces/http/admin/handler/observability.go
//   - 鉴权（auth/login/me）    internal/interfaces/http/admin/handler/auth.go
//
// 路由装配结构（见 mount.go）：
//
//	r := gin.New()
//	r.Use(middleware.RequestID(), middleware.Recovery(), middleware.AccessLog())
//	admin.MountAdmin(r, admin.Deps{...})
//
// 这种"主引擎挂 main 中间件 + admin 挂 admin 中间件"的写法避免每条路由都重复写
// adminmw.Require 与 adminmw.Authenticate。
package admin

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminapp"
	"github.com/djackcurry30/social-login/internal/application/adminaudit"
	"github.com/djackcurry30/social-login/internal/application/adminchan"
	"github.com/djackcurry30/social-login/internal/application/adminevent"
	"github.com/djackcurry30/social-login/internal/application/adminobs"
	"github.com/djackcurry30/social-login/internal/interfaces/http/admin/handler"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
)

// Deps 是装配 admin 路由所需的所有依赖。
type Deps struct {
	Logger       *zap.Logger
	AuthSessions adminmw.SessionLookup
	AuthUsers    adminmw.UserLookup
	AuthLogin    *handler.LoginService
	AdminApp     *adminapp.Service
	AdminChan    *adminchan.Service
	AdminObs     *adminobs.Service
	// AdminEvent 是 G 组（事件与死信）用例。为 nil 时不注册该组路由，
	// 便于只关心 A/B 组的测试。
	AdminEvent *adminevent.Service
	// AdminAudit 是 H 组（审计查询与异步导出）用例。同样为 nil 时跳过注册。
	AdminAudit *adminaudit.Service
}

// NewRouter 构造独立的 admin 子引擎。
//
// 与 MountAdmin 的差异：
//
//   - NewRouter 返回独立 *gin.Engine，自带 Recovery / AccessLog 等中间件，
//     便于单元测试独立跑（不必装配业务路由）。
//   - MountAdmin 把路由注册到【已装配好的】父引擎，复用父路由的中间件。
//
// 生产路径走 MountAdmin；NewRouter 只给单元测试。
func NewRouter(deps Deps) *gin.Engine {
	r := gin.New()
	// 测试专用中间件：单元测试需要日志但不希望依赖 zap 全局状态。
	r.Use(gin.Recovery())
	registerRoutes(r, deps)
	return r
}
