package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/application/claimsync"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// claimInvalidatedRequest 是用户中心投递的事件（外层信封）。
//
// 信封与 payload 分开解析而不是摊平：投递层字段（event_id / event_type）
// 与业务字段（app_key / user_id）的生命周期不同，加第二个事件类型时
// 只需扩 payload，不用改信封。
type claimInvalidatedRequest struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Payload   struct {
		AppKey    string `json:"app_key"`
		UserID    string `json:"user_id"`
		ClaimType string `json:"claim_type"`
		Reason    string `json:"reason"`
	} `json:"payload"`
}

// ClaimInvalidated 处理 POST /internal/v1/usercenter/claim-invalidated。
//
// 这是【用户中心 → 本服务】的推送入口，不是业务方接口：
//   - 鉴权走 X-Service-Token（挂在该路由的中间件上）；
//   - 成功返回 200 + 处理计数；重复投递同样 200（撤销是幂等的），
//     让投递方能把事件标记为已投递，而不是无限重试。
//
// 失败语义要对齐投递方的重试策略：
//
//	400 报文/类型不认识   永久失败（重试无解，进死信）
//	401 令牌不对          永久失败（需要人改配置）
//	404 应用不存在        永久失败（应用应由对账修复，不是靠重投）
//	5xx 数据库错误        可重试
func (h *Handler) ClaimInvalidated(c *gin.Context) {
	var req claimInvalidatedRequest
	if !httputil.BindJSON(c, &req, h.logger()) {
		return
	}
	if req.EventType != "" && req.EventType != "claim.invalidated" {
		httputil.Fail(c, h.logger(), errs.Newf(errs.CodeInvalidRequest,
			"未知事件类型: %s", req.EventType))
		return
	}

	res, err := h.deps.ClaimsSync.Invalidate(c.Request.Context(), claimsync.Input{
		EventID:   req.EventID,
		AppKey:    req.Payload.AppKey,
		UserID:    req.Payload.UserID,
		ClaimType: req.Payload.ClaimType,
		Reason:    req.Payload.Reason,
		TraceID:   reqmeta.TraceID(c.Request.Context()),
		ClientIP:  c.ClientIP(),
	})
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"event_id":   req.EventID,
		"identities": res.Identities,
		"revoked":    res.Revoked,
	})
}
