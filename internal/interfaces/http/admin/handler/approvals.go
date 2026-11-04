package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminapproval"
	"github.com/djackcurry30/social-login/internal/domain/approval"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// ApprovalsHandler 是双人复核的 HTTP 入口。
type ApprovalsHandler struct {
	svc    *adminapproval.Service
	logger *zap.Logger
}

// NewApprovalsHandler 构造处理器。
func NewApprovalsHandler(svc *adminapproval.Service, logger *zap.Logger) *ApprovalsHandler {
	return &ApprovalsHandler{svc: svc, logger: logger}
}

type createApprovalRequest struct {
	Action string `json:"action" binding:"required"`
	// AppID 可空：签名密钥轮换是全局动作。
	AppID       *int64 `json:"app_id"`
	Reason      string `json:"reason" binding:"required"`
	PayloadHash string `json:"payload_hash"`
}

// Create POST /admin/v1/approvals
func (h *ApprovalsHandler) Create(c *gin.Context) {
	var req createApprovalRequest
	if !httputil.BindJSON(c, &req, h.logger) {
		return
	}
	p := adminmw.Principal(c)
	if p == nil || p.User == nil {
		httputil.Fail(c, h.logger, errs.New(errs.CodeUnauthorized, "未认证"))
		return
	}
	a, err := h.svc.Create(c.Request.Context(), adminapproval.CreateInput{
		Action:      req.Action,
		AppID:       req.AppID,
		Reason:      req.Reason,
		PayloadHash: req.PayloadHash,
		RequesterID: p.User.ID,
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusCreated, approvalView(a))
}

// List GET /admin/v1/approvals?status=&limit=
func (h *ApprovalsHandler) List(c *gin.Context) {
	p := adminmw.Principal(c)
	if p == nil || p.User == nil {
		httputil.Fail(c, h.logger, errs.New(errs.CodeUnauthorized, "未认证"))
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	items, err := h.svc.List(c.Request.Context(), adminapproval.ListInput{
		Status:   approval.Status(c.Query("status")),
		Limit:    limit,
		CallerID: p.User.ID,
		// 只有超管能看全部：审批单暴露"谁想动哪个应用"，
		// 普通管理员没有互相查看的必要。
		All: adminapproval.IsSuperAdmin(p.User),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, a := range items {
		out = append(out, approvalView(a))
	}
	httputil.OK(c, http.StatusOK, gin.H{"items": out})
}

// Approve POST /admin/v1/approvals/:id/approve
func (h *ApprovalsHandler) Approve(c *gin.Context) { h.decide(c, true) }

// Reject POST /admin/v1/approvals/:id/reject
func (h *ApprovalsHandler) Reject(c *gin.Context) { h.decide(c, false) }

func (h *ApprovalsHandler) decide(c *gin.Context, approve bool) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	p := adminmw.Principal(c)
	if p == nil || p.User == nil {
		httputil.Fail(c, h.logger, errs.New(errs.CodeUnauthorized, "未认证"))
		return
	}
	var (
		a   *approval.Approval
		err error
	)
	if approve {
		a, err = h.svc.Approve(c.Request.Context(), id, p.User.ID)
	} else {
		a, err = h.svc.Reject(c.Request.Context(), id, p.User.ID)
	}
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, approvalView(a))
}

// approvalView 是审批单的对外视图。
//
// 刻意不回 requested_by 的姓名：审批是账号间的事，前端按 id 关联即可，
// 把人员信息铺进每个审批响应只会扩大暴露面。
func approvalView(a *approval.Approval) gin.H {
	if a == nil {
		return gin.H{}
	}
	return gin.H{
		"id":           a.ID,
		"action":       a.Action,
		"app_id":       a.AppID,
		"status":       a.Status,
		"reason":       a.Reason,
		"requested_by": a.RequestedBy,
		"requested_at": a.RequestedAt,
		"approved_by":  a.ApprovedBy,
		"approved_at":  a.ApprovedAt,
		"consumed_at":  a.ConsumedAt,
		"expires_at":   a.ExpiresAt,
	}
}
