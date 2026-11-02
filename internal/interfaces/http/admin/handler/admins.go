package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminuser"
	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AdminsHandler 是管理员账号管理（/admin/v1/admins）。
type AdminsHandler struct {
	svc    *adminuser.Service
	logger *zap.Logger
}

// NewAdminsHandler 构造 handler。
func NewAdminsHandler(svc *adminuser.Service, logger *zap.Logger) *AdminsHandler {
	return &AdminsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/admins
func (h *AdminsHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	items, err := h.svc.List(c.Request.Context(), limit)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"items": items})
}

// Create POST /admin/v1/admins
func (h *AdminsHandler) Create(c *gin.Context) {
	var in adminuser.CreateInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	out, err := h.svc.Create(c.Request.Context(), h.actor(c), in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusCreated, out)
}

// Update PATCH /admin/v1/admins/:id
func (h *AdminsHandler) Update(c *gin.Context) {
	id, ok := h.parseID(c)
	if !ok {
		return
	}
	var in adminuser.UpdateInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	out, err := h.svc.Update(c.Request.Context(), h.actor(c), id, in)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

type resetPasswordInput struct {
	Password string `json:"password"`
	Reason   string `json:"reason"`
}

// ResetPassword POST /admin/v1/admins/:id/password
//
// 不复用 Update：改密码的安全属性与改显示名完全不同（它要撤会话），
// 并且它对"改自己"是允许的（自助改密），而 Update 的规则里明确禁止
// 改自己的角色/状态。混在一个端点里，规则会互相打架。
func (h *AdminsHandler) ResetPassword(c *gin.Context) {
	id, ok := h.parseID(c)
	if !ok {
		return
	}
	var in resetPasswordInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), h.actor(c), id, in.Password, in.Reason); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"reset": true})
}

// actor 取当前操作者。
//
// 中间件已经保证认证通过，这里再返回 nil 是防御性写法：service 层对
// nil actor 会拒绝，宁可 401 也不要写出"subject_id 为空"的审计记录。
func (h *AdminsHandler) actor(c *gin.Context) *admin.User {
	p := adminmw.Principal(c)
	if p == nil {
		return nil
	}
	return p.User
}

func (h *AdminsHandler) parseID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		httputil.Fail(c, h.logger,
			errs.New(errs.CodeInvalidRequest, "id 非法").WithDetail("field", "id"))
		return 0, false
	}
	return id, true
}
