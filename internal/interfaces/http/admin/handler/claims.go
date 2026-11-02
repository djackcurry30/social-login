// claims.go（handler）是 J 组（凭证一致性运维）路由薄壳。
//
// 端点清单（架构 §15.4 J 组）：
//
//	GET  /admin/v1/claims                     ListClaims
//	GET  /admin/v1/claims/mismatches          ListMismatches
//	POST /admin/v1/claims/:id/revoke          RevokeClaim
//
// 路径用 /claims/:id/revoke 而不是文档里的 /claims/{id}:revoke：
// gin 的 :param 占满整段，无法与后缀共用（项目内 secret:rotate 等
// 已统一改为 /secret/rotate 的斜杠形式）。
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

// ClaimsHandler 是 J 组 handler。
type ClaimsHandler struct {
	svc    *adminidentity.Service
	logger *zap.Logger
}

// NewClaimsHandler 构造 J 组 handler。
func NewClaimsHandler(svc *adminidentity.Service, logger *zap.Logger) *ClaimsHandler {
	return &ClaimsHandler{svc: svc, logger: logger}
}

// ListClaims GET /admin/v1/claims?app_id=&claim_type=&identity_id=&status=
func (h *ClaimsHandler) ListClaims(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	identityID, _ := strconv.ParseInt(c.Query("identity_id"), 10, 64)
	out, err := h.svc.ListClaims(c.Request.Context(), adminidentity.ClaimListInput{
		AppID:      appID,
		ClaimType:  c.Query("claim_type"),
		IdentityID: identityID,
		Status:     c.Query("status"),
		Page:       atoiDefault(c.Query("page"), 1),
		PageSize:   atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// ListMismatches GET /admin/v1/claims/mismatches?app_id=&status=&kind=&identity_id=
func (h *ClaimsHandler) ListMismatches(c *gin.Context) {
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)
	identityID, _ := strconv.ParseInt(c.Query("identity_id"), 10, 64)
	out, err := h.svc.ListMismatches(c.Request.Context(), adminidentity.MismatchListInput{
		AppID:      appID,
		Status:     c.Query("status"),
		Kind:       c.Query("kind"),
		ClaimType:  c.Query("claim_type"),
		IdentityID: identityID,
		Page:       atoiDefault(c.Query("page"), 1),
		PageSize:   atoiDefault(c.Query("page_size"), 20),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// RevokeClaim POST /admin/v1/claims/:id/revoke
//
// body 必填 app_id + reason：app_id 决定"这个 id 属于哪个应用的数据"
// （凭证按应用隔离），reason 进管理审计。
func (h *ClaimsHandler) RevokeClaim(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminidentity.RevokeClaimInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)

	out, err := h.svc.RevokeClaim(c.Request.Context(), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}
