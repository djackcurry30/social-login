// Package handler 中的 apps.go：A 组（应用与策略）路由薄壳。
//
// 端点清单（架构 §15.4 A 组第一期 8 个）：
//
//	GET    /admin/v1/apps                          ListApps
//	POST   /admin/v1/apps                          CreateApp
//	GET    /admin/v1/apps/:id                      GetApp
//	PATCH  /admin/v1/apps/:id                      UpdateApp
//	POST   /admin/v1/apps/:id/secret:rotate        RotateAppSecret
//	GET    /admin/v1/apps/:id/policy               GetPolicy
//	PUT    /admin/v1/apps/:id/policy               SavePolicy
//	POST   /admin/v1/apps/:id/policy:validate      ValidatePolicy
//
// 高危操作（CreateApp / UpdateApp / RotateAppSecret / SavePolicy）由 application 层
// 校验 reason ≥4 字符；handler 这里只透传 Reason 与 Principal。
package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminapp"
	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AppsHandler 是 A 组 handler。
type AppsHandler struct {
	svc    *adminapp.Service
	logger *zap.Logger
}

// NewAppsHandler 构造 A 组 handler。
func NewAppsHandler(svc *adminapp.Service, logger *zap.Logger) *AppsHandler {
	return &AppsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/apps?status=&name=&page=&page_size=
func (h *AppsHandler) List(c *gin.Context) {
	in := adminapp.ListAppsInput{
		Page:     atoiDefault(c.Query("page"), 1),
		PageSize: atoiDefault(c.Query("page_size"), 20),
		Status:   atoiDefault(c.Query("status"), -1),
		Name:     c.Query("name"),
	}
	out, err := h.svc.ListApps(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Create POST /admin/v1/apps
func (h *AppsHandler) Create(c *gin.Context) {
	var in adminapp.CreateAppInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	out, err := h.svc.CreateApp(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusCreated, out)
}

// Get GET /admin/v1/apps/:id
func (h *AppsHandler) Get(c *gin.Context) {
	id, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	app, err := h.svc.GetApp(c.Request.Context(), id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"app": app})
}

// Update PATCH /admin/v1/apps/:id
func (h *AppsHandler) Update(c *gin.Context) {
	id, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	var in adminapp.UpdateAppInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	app, err := h.svc.UpdateApp(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"app": app})
}

// RotateSecret POST /admin/v1/apps/:id/secret:rotate
//
// 响应里包含【明文新密钥】，调用方应立即提示用户复制保存——
// 此后再无法重新获得明文，只能再 rotate 一次。
func (h *AppsHandler) RotateSecret(c *gin.Context) {
	id, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	var in adminapp.RotateAppSecretInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	out, err := h.svc.RotateAppSecret(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// UpdateWebhook PUT /admin/v1/apps/:appId/webhook
//
// 配置事件投递目标（架构 §5.4）。url 传空串表示关闭外发；
// secret 留空表示保留原密钥（只改地址不必重传密钥）。
func (h *AppsHandler) UpdateWebhook(c *gin.Context) {
	id, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	var in adminapp.UpdateWebhookInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	if err := h.svc.UpdateWebhook(c.Request.Context(), id, in); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// GetPolicy GET /admin/v1/apps/:id/policy
func (h *AppsHandler) GetPolicy(c *gin.Context) {
	id, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	policy, err := h.svc.GetPolicy(c.Request.Context(), id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"policy": policy})
}

// SavePolicy PUT /admin/v1/apps/:id/policy
func (h *AppsHandler) SavePolicy(c *gin.Context) {
	id, ok := parseIDParam(c, "appId")
	if !ok {
		return
	}
	var in adminapp.SavePolicyInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	policy, err := h.svc.SavePolicy(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"policy": policy})
}

// ValidatePolicy POST /admin/v1/apps/:id/policy:validate
//
// 这是 dry-run：不写库，只返回"是否能通过校验 + 标准化后的策略"。
// 前端实时校验建议在用户改任意字段后触发。
func (h *AppsHandler) ValidatePolicy(c *gin.Context) {
	var in adminapp.ValidatePolicyInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	out, err := h.svc.ValidatePolicy(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// --- helpers ---

// parseIDParam 解析路径里的整型 ID；失败时已经写入 400 并返回 ok=false。
//
// 用 ok=false 让 handler 可以直接 return 而不用写 if-else。
func parseIDParam(c *gin.Context, name string) (int64, bool) {
	raw := c.Param(name)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		// 这里直接走 errs.CodeInvalidRequest 而不是 path id——不是 unknown。
		_ = adminLogger(c)
		httputil.Fail(c, nil,
			errs.Newf(errs.CodeInvalidRequest, "%s 必须为正整数: %s", name, raw).
				WithDetail("field", name))
		return 0, false
	}
	return id, true
}

// atoiDefault 是查询参数解析工具：空串/非法 → def。
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// adminLogger 抑制 unused：parseIDParam 失败时 logger 是 nil（中间件层 Fail 已经写日志）。
// 这里保留类型断言位置，便于以后在 parseIDParam 里要 logger 时直接拿。
func adminLogger(c *gin.Context) *zap.Logger { return nil } //nolint:unused

// 抑制 unused（admin.Role 在 apps handler 不直接用；保留 import 便于未来 SavePolicy/Update 引用）
var _ = (*admin.Role)(nil)
