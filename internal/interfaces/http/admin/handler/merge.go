// Package handler 中的 merge.go：D 组（账号合并运维）路由薄壳。
//
// 端点清单（架构 §15.4 D 组）：
//
//	GET  /admin/v1/merge-operations                 List
//	GET  /admin/v1/merge-operations/:id             Get
//	POST /admin/v1/merge-operations/:id/retry       Retry
//	POST /admin/v1/merge-operations/:id/resolve     Resolve
//	GET  /admin/v1/merge-operations/:id/impact      Impact
//
// 路径里的 :retry / :resolve 用斜杠分段，与 A 组 secret/rotate 一致
// （gin 不允许路径段内出现冒号）。
package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminmerge"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// MergeHandler 是 D 组 handler。
type MergeHandler struct {
	svc    *adminmerge.Service
	logger *zap.Logger
}

// NewMergeHandler 构造 D 组 handler。
func NewMergeHandler(svc *adminmerge.Service, logger *zap.Logger) *MergeHandler {
	return &MergeHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/merge-operations
func (h *MergeHandler) List(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.List(c.Request.Context(), adminmerge.ListInput{
		AppID:    appID,
		Status:   c.Query("status"),
		UserID:   c.Query("user_id"),
		From:     c.Query("from"),
		To:       c.Query("to"),
		Page:     atoiDefault(c.Query("page"), 1),
		PageSize: atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Get GET /admin/v1/merge-operations/:id
func (h *MergeHandler) Get(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	item, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"merge_operation": item})
}

// Retry POST /admin/v1/merge-operations/:id/retry
func (h *MergeHandler) Retry(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminmerge.RetryInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	if err := h.svc.Retry(c.Request.Context(), id, in); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// Resolve POST /admin/v1/merge-operations/:id/resolve
func (h *MergeHandler) Resolve(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminmerge.ResolveInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	if err := h.svc.Resolve(c.Request.Context(), id, in); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// Impact GET /admin/v1/merge-operations/:id/impact
//
// 供二次确认弹窗展示"将改绑 N 个身份、撤销 M 个令牌"。
func (h *MergeHandler) Impact(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	impact, err := h.svc.Impact(c.Request.Context(), id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"impact": impact})
}
