// Package handler 中的 signing_keys.go：F 组（签名密钥）路由薄壳。
//
// 端点清单（架构 §15.4 F 组）：
//
//	GET  /admin/v1/signing-keys                List
//	GET  /admin/v1/signing-keys/jwks-preview   JWKSPreview
//	POST /admin/v1/signing-keys/rotate         Rotate
//	POST /admin/v1/signing-keys/:kid/retire    Retire
//
// 文档写作 /signing-keys:rotate，gin 不允许路径段内出现冒号，改斜杠分段。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminkey"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// SigningKeysHandler 是 F 组 handler。
type SigningKeysHandler struct {
	svc    *adminkey.Service
	logger *zap.Logger
}

// NewSigningKeysHandler 构造 F 组 handler。
func NewSigningKeysHandler(svc *adminkey.Service, logger *zap.Logger) *SigningKeysHandler {
	return &SigningKeysHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/signing-keys
func (h *SigningKeysHandler) List(c *gin.Context) {
	items, err := h.svc.List(c.Request.Context())
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"items": items})
}

// JWKSPreview GET /admin/v1/signing-keys/jwks-preview
func (h *SigningKeysHandler) JWKSPreview(c *gin.Context) {
	raw, err := h.svc.JWKSPreview(c.Request.Context())
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	// 直接返回原始 JWKS：与 /v1/jwks 完全一致，便于运维对照。
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

// rotateRequest 是轮换入参。
type rotateRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// Rotate POST /admin/v1/signing-keys/rotate
func (h *SigningKeysHandler) Rotate(c *gin.Context) {
	var in rotateRequest
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	out, err := h.svc.Rotate(c.Request.Context(), in.Reason, adminmw.Principal(c))
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// retireRequest 是下线入参。
type retireRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// Retire POST /admin/v1/signing-keys/:kid/retire
func (h *SigningKeysHandler) Retire(c *gin.Context) {
	var in retireRequest
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	if err := h.svc.Retire(c.Request.Context(), c.Param("kid"), in.Reason, adminmw.Principal(c)); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}
