// Package admin 中的 mount.go：把 admin 子路由挂到传入的 gin 引擎。
//
// Gin 没有 http.ServeMux 那样的 Mount 方法——子引擎的中间件链不共享。
// 因此 MountAdmin 选择最简单的形态：把 admin 路由全部注册到 parent 上，
// 让 admin 内部不再持有自己的 gin.Engine。
//
// 与原版 NewRouter 的差异：
//
//   - NewRouter 会返回一个新的 gin.Engine（自带 Recovery，便于单元测试独立跑）
//   - MountAdmin 直接在 parent 上注册路由——复用 parent 的 RequestID / Recovery /
//     AccessLog 中间件；admin 自己的 Authenticate + RBAC 走 Route Group。
//
// 因此路由组织结构从"主 /admin v1 → 子 /admin/v1/*"变成"主 /admin/v1/*"，
// 等价但少一层中间件注入，更直接。
package admin

import (
	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/interfaces/http/admin/handler"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
)

// MountAdmin 把 admin 路由（/admin/v1/*）注册到 parent。
//
// parent 应已挂 RequestID / Recovery / AccessLog。
// admin 自己的 Authenticate + RBAC 走 adminmw。
func MountAdmin(parent *gin.Engine, deps Deps) {
	registerRoutes(parent, deps)
}

// registerRoutes 是 MountAdmin 的内部实现；保留 NewRouter 是为了单元测试
// 能在隔离的 gin.Engine 上跑同一组路由。
func registerRoutes(r *gin.Engine, deps Deps) {
	// 鉴权入口
	authn := &adminmw.Authenticator{
		Sessions: deps.AuthSessions,
		Users:    deps.AuthUsers,
		Logger:   deps.Logger,
	}

	authHandler := handler.NewAuthHandler(deps.AuthLogin, deps.Logger)

	// /admin/v1/auth/login 不需要鉴权，单独放
	r.POST("/admin/v1/auth/login", authHandler.Login)

	// /admin/v1/* 其它路径全部走 Authenticate
	api := r.Group("/admin/v1", authn.Authenticate())
	{
		// /auth/me 与 /auth/logout 走 viewer（即任何已认证用户）
		api.GET("/auth/me", adminmw.Require("app:read"), authHandler.Me)
		api.POST("/auth/logout", adminmw.Require("app:read"), authHandler.Logout)

		// A 组：应用与策略
		//
		// 注意：gin 不支持路径段里用 ":"（如 /apps/:id/secret:rotate），
		// 只能解析为"secret" + ":rotate"两段，会与"secret:finalize"冲突。
		// 因此统一用斜杠分隔子操作（语义同 RPC-style）。
		appH := handler.NewAppsHandler(deps.AdminApp, deps.Logger)
		api.GET("/apps", adminmw.Require("app:read"), appH.List)
		api.POST("/apps", adminmw.Require("app:write"), appH.Create)
		api.GET("/apps/:appId", adminmw.Require("app:read"), appH.Get)
		api.PATCH("/apps/:appId", adminmw.Require("app:write"), appH.Update)
		api.POST("/apps/:appId/secret/rotate", adminmw.Require("app:write"), appH.RotateSecret)
		api.GET("/apps/:appId/policy", adminmw.Require("app:read"), appH.GetPolicy)
		api.PUT("/apps/:appId/policy", adminmw.Require("app:write"), appH.SavePolicy)
		api.POST("/apps/:appId/policy/validate", adminmw.Require("app:read"), appH.ValidatePolicy)
		// A 组补充：事件投递目标（§5.4）。webhook 密钥是明文可解的密钥材料，
		// 与 name/status 的敏感级别不同，因此单独端点。
		api.PUT("/apps/:appId/webhook", adminmw.Require("app:write"), appH.UpdateWebhook)

		// B 组：渠道配置
		chanH := handler.NewProviderConfigsHandler(deps.AdminChan, deps.Logger)
		api.GET("/apps/:appId/provider-configs", adminmw.Require("config:read"), chanH.List)
		api.POST("/apps/:appId/provider-configs", adminmw.Require("config:write"), chanH.Create)
		api.GET("/apps/:appId/provider-configs/:id", adminmw.Require("config:read"), chanH.Get)
		api.PATCH("/apps/:appId/provider-configs/:id", adminmw.Require("config:write"), chanH.Update)
		api.POST("/apps/:appId/provider-configs/:id/secret/rotate", adminmw.Require("config:write"), chanH.RotateSecret)
		api.POST("/apps/:appId/provider-configs/:id/secret/finalize", adminmw.Require("config:write"), chanH.FinalizeSecret)
		api.POST("/apps/:appId/provider-configs/:id/secret/verify", adminmw.Require("config:write"), chanH.Verify)
		api.POST("/apps/:appId/provider-configs/:id/enable", adminmw.Require("config:write"), chanH.Enable)
		api.POST("/apps/:appId/provider-configs/:id/disable", adminmw.Require("config:write"), chanH.Disable)
		api.DELETE("/apps/:appId/provider-configs/:id", adminmw.Require("config:write"), chanH.Delete)

		// I 组：观测
		obsH := handler.NewObservabilityHandler(deps.AdminObs, deps.Logger)
		api.GET("/providers", adminmw.Require("config:read"), obsH.ListProviders)
		api.GET("/providers/health", adminmw.Require("config:read"), obsH.PingProviders)
		api.GET("/health/overview", adminmw.Require("app:read"), obsH.Overview)
		// 熔断复位（§5.6.9）。高危写操作：config:write + reason 必填 + 审计。
		//
		// 路径用 /providers/:platform/circuit-reset 而不是文档里的
		// /providers/{platform}:circuit-reset：gin 的 :param 占满整段，
		// 无法与后缀共用一段。项目内 secret:rotate 等也已统一为 /secret/rotate。
		api.POST("/providers/:platform/circuit-reset", adminmw.Require("config:write"), obsH.ResetCircuit)

		// G 组：事件与死信（§15.4）
		//
		// 只读与重投分开授权：读是 viewer 也有的能力，
		// 重投/丢弃会改变外发事实，必须 event:write。
		if deps.AdminEvent != nil {
			evH := handler.NewEventsHandler(deps.AdminEvent, deps.Logger)
			api.GET("/events/outbox", adminmw.Require("event:read"), evH.List)
			api.GET("/events/outbox/:id", adminmw.Require("event:read"), evH.Get)
			api.POST("/events/outbox/:id/retry", adminmw.Require("event:write"), evH.Retry)
			api.POST("/events/outbox/:id/discard", adminmw.Require("event:write"), evH.Discard)
		}

		// H 组：审计日志（§15.4）
		//
		// 全部走 audit:read：查询与导出都只读，导出虽会落盘但不改变业务事实，
		// 单列一个 audit:export 权限只会让"谁能导出"变成第二个要维护的矩阵。
		if deps.AdminAudit != nil {
			auditH := handler.NewAuditLogsHandler(deps.AdminAudit, deps.Logger)
			api.GET("/audit-logs", adminmw.Require("audit:read"), auditH.List)
			// ⚠️ 路由顺序：/audit-logs/admin 必须在 /audit-logs/:xxx 之前注册，
			// 否则 gin 会把 "admin" 当成参数吃进通配段（当前没有通配段，
			// 但一旦将来加 /audit-logs/:id 就会踩）。这里保持"静态优先"的顺序。
			api.GET("/audit-logs/admin", adminmw.Require("audit:read"), auditH.ListAdmin)
			api.GET("/audit-logs/exports", adminmw.Require("audit:read"), auditH.ListExports)
			api.POST("/audit-logs/export", adminmw.Require("audit:read"), auditH.SubmitExport)
			api.GET("/audit-logs/export/:taskId", adminmw.Require("audit:read"), auditH.GetExport)
			api.GET("/audit-logs/export/:taskId/download", adminmw.Require("audit:read"), auditH.Download)
		}
	}
}
