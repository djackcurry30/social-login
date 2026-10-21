package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/interfaces/http/middleware"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// resolveRequest 是 POST /v1/bind/resolve 的请求体。
//
// 接口只接受两件事：票据 + 动作。**不接受 target/source 账号**——
// 那两个值在签发票据时就已固定，让前端重传等于把"合并谁到谁"的决定权
// 交给客户端，验证码会变成一个万能通行证。
type resolveRequest struct {
	MergeTicket string `json:"merge_ticket" binding:"required"`
	// Action 是 send_code | verify。
	Action string `json:"action" binding:"required"`
	Code   string `json:"code"`
	// ExternalUserID 仅服务端到服务端调用时提供（与 /v1/bind 同口径）。
	ExternalUserID string `json:"external_user_id"`
}

// Resolve 处理 POST /v1/bind/resolve：confirm 模式下"冲突 → 验证 → 合并"。
//
// 两段式：
//
//	{"action":"send_code"}               → 向【被占用账号】的手机号发码
//	{"action":"verify","code":"123456"} → 校验并执行合并
//
// 为什么验证码发到 source 账号：要合并的是它，用户必须证明自己控制它。
// 发到 target 等于"自己证明自己"，confirm 模式就退化成了 auto。
func (h *Handler) Resolve(c *gin.Context) {
	var req resolveRequest
	if !httputil.BindJSON(c, &req, h.logger()) {
		return
	}
	if h.deps.Merge == nil {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "合并能力未装配"))
		return
	}

	app := middleware.App(c)
	if app == nil {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "缺少已认证的应用上下文"))
		return
	}

	// 调用者身份：Bearer 优先，其次请求体断言（与 /v1/bind 同一套规则）。
	callerUserID, err := h.resolveBindTarget(c, app.AppCode, req.ExternalUserID)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}

	switch req.Action {
	case "send_code":
		out, err := h.deps.Merge.StartSMSVerification(c.Request.Context(), appmerge.StartVerificationInput{
			TicketID:     req.MergeTicket,
			CallerUserID: callerUserID,
		})
		if err != nil {
			httputil.Fail(c, h.logger(), err)
			return
		}
		httputil.OK(c, http.StatusOK, gin.H{
			"phone_masked":         out.PhoneMasked,
			"expires_at":           out.ExpiresAt,
			"resend_after_seconds": out.ResendAfterSeconds,
		})

	case "verify":
		if req.Code == "" {
			httputil.Fail(c, h.logger(),
				errs.New(errs.CodeInvalidRequest, "缺少验证码 code"))
			return
		}
		res, err := h.deps.Merge.CompleteSMSVerification(c.Request.Context(), appmerge.CompleteVerificationInput{
			TicketID:     req.MergeTicket,
			Code:         req.Code,
			CallerUserID: callerUserID,
		})
		if err != nil {
			httputil.Fail(c, h.logger(), err)
			return
		}
		// 返回 merged_into（架构 §7.3「合并的返回与前端配合」）：
		// 前端据此提示"已并入当前账号"，并知道 source 的会话已失效。
		httputil.OK(c, http.StatusOK, gin.H{
			"merged_into":  callerUserID,
			"operation_id": res.OperationID,
			"already":      res.AlreadyMerged,
		})

	default:
		httputil.Fail(c, h.logger(),
			errs.Newf(errs.CodeInvalidRequest, "未知的 action: %s（应为 send_code 或 verify）", req.Action))
	}
}
