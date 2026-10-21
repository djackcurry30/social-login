// Package handler 中的 identities.go：C 组（身份与绑定）路由薄壳。
//
// 端点清单（架构 §15.4 C 组）：
//
//	GET    /admin/v1/identities                           ListIdentities
//	GET    /admin/v1/identities/:id                       GetIdentity
//	GET    /admin/v1/bindings                             ListBindings
//	GET    /admin/v1/accounts/:externalUserId/bindings    ListAccountBindings
//	DELETE /admin/v1/bindings/:id                         ForceUnbind
//	POST   /admin/v1/bindings/:id/transfer                Transfer
//
// 强制解绑与 transfer 都会改变"谁能用这个渠道登录"，因此必须 reason +
// 写审计 + 同事务写 outbox 事件（业务方靠 binding.removed 同步自己的数据）。
package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminidentity"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// IdentitiesHandler 是 C 组 handler。
type IdentitiesHandler struct {
	svc    *adminidentity.Service
	logger *zap.Logger
}

// NewIdentitiesHandler 构造 C 组 handler。
func NewIdentitiesHandler(svc *adminidentity.Service, logger *zap.Logger) *IdentitiesHandler {
	return &IdentitiesHandler{svc: svc, logger: logger}
}

// ListIdentities GET /admin/v1/identities
func (h *IdentitiesHandler) ListIdentities(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.ListIdentities(c.Request.Context(), adminidentity.IdentityListInput{
		AppID:          appID,
		Platform:       c.Query("platform"),
		OpenID:         c.Query("open_id"),
		IdentityKey:    c.Query("identity_key"),
		ExternalUserID: c.Query("external_user_id"),
		Page:           atoiDefault(c.Query("page"), 1),
		PageSize:       atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// GetIdentity GET /admin/v1/identities/:id?app_id=
//
// app_id 必填：身份按应用隔离（约束 C1），同一个 id 在不同应用下
// 属于不同数据；由调用方显式声明比"从路径里猜"安全。
func (h *IdentitiesHandler) GetIdentity(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	detail, err := h.svc.GetIdentity(c.Request.Context(), appID, id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, detail)
}

// ListBindings GET /admin/v1/bindings
func (h *IdentitiesHandler) ListBindings(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	identityID, _ := strconv.ParseInt(c.Query("identity_id"), 10, 64)
	out, err := h.svc.ListBindings(c.Request.Context(), adminidentity.BindingListInput{
		AppID:          appID,
		ExternalUserID: c.Query("external_user_id"),
		Status:         c.Query("status"),
		IdentityID:     identityID,
		Page:           atoiDefault(c.Query("page"), 1),
		PageSize:       atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// ListAccountBindings GET /admin/v1/accounts/:externalUserId/bindings
func (h *IdentitiesHandler) ListAccountBindings(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	out, err := h.svc.ListAccountBindings(c.Request.Context(), appID, c.Param("externalUserId"))
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// ForceUnbind DELETE /admin/v1/bindings/:id
//
// reason 支持 body 或 query 两种传法：DELETE 带 body 在部分客户端/网关
// 会被丢弃（这是 HTTP 的历史包袱），query 是更保险的通道。
func (h *IdentitiesHandler) ForceUnbind(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminidentity.UnbindInput
	_ = c.ShouldBindJSON(&in)
	if in.Reason == "" {
		in.Reason = c.Query("reason")
	}
	if in.AppID == 0 {
		in.AppID, _ = strconv.ParseInt(c.Query("app_id"), 10, 64)
	}
	in.Principal = adminmw.Principal(c)

	item, err := h.svc.ForceUnbind(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"binding": item})
}

// Transfer POST /admin/v1/bindings/:id/transfer
func (h *IdentitiesHandler) Transfer(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminidentity.TransferInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	item, err := h.svc.Transfer(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"binding": item})
}
