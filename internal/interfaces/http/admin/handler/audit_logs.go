// Package handler 中的 audit_logs.go：H 组（审计日志）路由薄壳。
//
// 端点清单（架构 §15.4 H 组 + 一处必要补齐）：
//
//	GET  /admin/v1/audit-logs                      List         业务审计
//	GET  /admin/v1/audit-logs/admin                ListAdmin    管理端审计
//	POST /admin/v1/audit-logs/export               SubmitExport 异步导出（返回 task_id）
//	GET  /admin/v1/audit-logs/export/:taskId       GetExport    查状态
//	GET  /admin/v1/audit-logs/export/:taskId/download  Download 取文件
//	GET  /admin/v1/audit-logs/exports              ListExports  "我的导出任务"
//
// 路径写法说明：文档里是 `/audit-logs:export`，但 gin 无法在路径段内使用冒号
// （会被解析成参数前缀）。项目内（A 组 secret:rotate、B 组 secret/verify）
// 已统一改成斜杠分段，这里沿用同一约定。
package handler

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminaudit"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AuditLogsHandler 是 H 组 handler。
type AuditLogsHandler struct {
	svc    *adminaudit.Service
	logger *zap.Logger
}

// NewAuditLogsHandler 构造 H 组 handler。
func NewAuditLogsHandler(svc *adminaudit.Service, logger *zap.Logger) *AuditLogsHandler {
	return &AuditLogsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/audit-logs
//
// 注意 app_id 是可选的：不传表示跨全部应用查询（管理端天然跨应用）。
// 这与业务端"必须带 app_id"的强制隔离不冲突——隔离约束的是业务请求，
// 管理端的跨应用访问是显式声明的。
func (h *AuditLogsHandler) List(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.List(c.Request.Context(), adminaudit.ListInput{
		AppID:          appID,
		Action:         c.Query("action"),
		Result:         c.Query("result"),
		ExternalUserID: c.Query("external_user_id"),
		TraceID:        c.Query("trace_id"),
		Platform:       c.Query("platform"),
		Client:         c.Query("client"),
		From:           c.Query("from"),
		To:             c.Query("to"),
		Page:           atoiDefault(c.Query("page"), 1),
		PageSize:       atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// ListAdmin GET /admin/v1/audit-logs/admin
func (h *AuditLogsHandler) ListAdmin(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.ListAdmin(c.Request.Context(), adminaudit.AdminListInput{
		SubjectID:  c.Query("subject_id"),
		Action:     c.Query("action"),
		TargetType: c.Query("target_type"),
		TargetID:   c.Query("target_id"),
		AppID:      appID,
		Result:     c.Query("result"),
		From:       c.Query("from"),
		To:         c.Query("to"),
		Page:       atoiDefault(c.Query("page"), 1),
		PageSize:   atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// SubmitExport POST /admin/v1/audit-logs/export
//
// 返回 202：任务只是【被接受】了，不代表已经跑完。
// 用 200 会让调用方以为可以立刻下载。
func (h *AuditLogsHandler) SubmitExport(c *gin.Context) {
	var in adminaudit.ExportInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	out, err := h.svc.SubmitExport(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusAccepted, out)
}

// GetExport GET /admin/v1/audit-logs/export/:taskId
func (h *AuditLogsHandler) GetExport(c *gin.Context) {
	out, err := h.svc.GetExport(c.Request.Context(), c.Param("taskId"), adminmw.Principal(c))
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// ListExports GET /admin/v1/audit-logs/exports
//
// 补充端点：只返回当前管理员提交的任务。没有它，前端刷新一次就再也
// 找不回 task_id（提交响应只出现一次），任务列表页无从实现。
func (h *AuditLogsHandler) ListExports(c *gin.Context) {
	items, err := h.svc.ListExports(c.Request.Context(), adminmw.Principal(c),
		atoiDefault(c.Query("limit"), 20))
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"items": items})
}

// Download GET /admin/v1/audit-logs/export/:taskId/download
//
// 走鉴权接口而不是直链：审计数据含 openid、IP、UA 与错误详情，
// 直链一旦外泄就等于永久公开（本地文件存储也给不了预签名 URL）。
func (h *AuditLogsHandler) Download(c *gin.Context) {
	target, err := h.svc.PrepareDownload(c.Request.Context(), c.Param("taskId"), adminmw.Principal(c))
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	if _, statErr := os.Stat(target.Path); statErr != nil {
		// 元数据说成功了但文件不在：通常是目录被挂载覆盖或被人手工清理。
		// 这种情况必须报明确错误，而不是把空文件当成导出结果交出去。
		h.logger.Error("导出文件缺失",
			zap.String("task_id", c.Param("taskId")),
			zap.String("path", target.Path), zap.Error(statErr))
		httputil.Fail(c, h.logger,
			errs.New(errs.CodeNotFound, "导出文件已不可用，请重新导出"))
		return
	}
	c.FileAttachment(target.Path, target.FileName)
}
