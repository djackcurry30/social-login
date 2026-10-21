// Package handler 中的 sessions.go：E 组（会话与令牌）路由薄壳。
//
// 端点清单（架构 §15.4 E 组）：
//
//	GET  /admin/v1/tokens           List
//	POST /admin/v1/tokens/revoke    Revoke（强制下线）
//	GET  /admin/v1/revoked-jti      GetRevocation
//
// 文档写作 /tokens:revoke，gin 不允许路径段内出现冒号，统一改斜杠分段。
package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminsession"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// SessionsHandler 是 E 组 handler。
type SessionsHandler struct {
	svc    *adminsession.Service
	logger *zap.Logger
}

// NewSessionsHandler 构造 E 组 handler。
func NewSessionsHandler(svc *adminsession.Service, logger *zap.Logger) *SessionsHandler {
	return &SessionsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/tokens
func (h *SessionsHandler) List(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.List(c.Request.Context(), adminsession.ListInput{
		AppID:          appID,
		ExternalUserID: c.Query("external_user_id"),
		DeviceID:       c.Query("device_id"),
		Active:         c.Query("active"),
		Page:           atoiDefault(c.Query("page"), 1),
		PageSize:       atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Revoke POST /admin/v1/tokens/revoke
//
// 返回 effective_window_seconds：未开启 check_revocation 的调用方仍可能
// 接受旧 access_token 的剩余时间。必须如实告知——运营对用户说"已下线"时
// 需要知道这句话的准确含义。
func (h *SessionsHandler) Revoke(c *gin.Context) {
	var in adminsession.RevokeInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	out, err := h.svc.Revoke(c.Request.Context(), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// GetRevocation GET /admin/v1/revoked-jti?app_id=&external_user_id=&jti=
func (h *SessionsHandler) GetRevocation(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.GetRevocation(c.Request.Context(), adminsession.RevocationInput{
		AppID:          appID,
		ExternalUserID: c.Query("external_user_id"),
		JTI:            c.Query("jti"),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}
