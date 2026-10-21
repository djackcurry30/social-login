// Package handler 中的 admin_grants.go：K 组（管理员授权）路由薄壳。
//
// 端点清单（架构 §15.4 K 组）：
//
//	GET    /admin/v1/admin-grants       List
//	POST   /admin/v1/admin-grants       Grant
//	DELETE /admin/v1/admin-grants/:id   Revoke
//
// 全部要求 admin:grant —— 该权限只有 super_admin 拥有（Role.Has 对
// super_admin 恒真）。这一点很关键：能改"谁能进管理端"的人必须是最小集合。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/admingrant"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// AdminGrantsHandler 是 K 组 handler。
type AdminGrantsHandler struct {
	svc    *admingrant.Service
	logger *zap.Logger
}

// NewAdminGrantsHandler 构造 K 组 handler。
func NewAdminGrantsHandler(svc *admingrant.Service, logger *zap.Logger) *AdminGrantsHandler {
	return &AdminGrantsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/admin-grants
func (h *AdminGrantsHandler) List(c *gin.Context) {
	out, err := h.svc.List(c.Request.Context(), admingrant.ListInput{
		SubjectID:      c.Query("subject_id"),
		IncludeRevoked: c.Query("include_revoked") == "true",
		Page:           atoiDefault(c.Query("page"), 1),
		PageSize:       atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Grant POST /admin/v1/admin-grants
func (h *AdminGrantsHandler) Grant(c *gin.Context) {
	var in admingrant.GrantInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	item, err := h.svc.Grant(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusCreated, gin.H{"grant": item})
}

// Revoke DELETE /admin/v1/admin-grants/:id
//
// reason 与其它 DELETE 端点同口径：body 优先，query 兜底
// （部分客户端/网关会丢弃 DELETE 的 body）。
func (h *AdminGrantsHandler) Revoke(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.Reason == "" {
		in.Reason = c.Query("reason")
	}
	if err := h.svc.Revoke(c.Request.Context(), id, in.Reason, adminmw.Principal(c)); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}
