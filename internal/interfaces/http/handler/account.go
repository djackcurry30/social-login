// account.go 是账号注销的用户端点。
//
// 为什么放在用户端点组（AppAuth + UserAuth）而不是内部接口：
// 注销的主体是【用户本人】，而证明"我是我"的唯一依据就是他自己持有的
// access_token。内部接口需要另一套服务间凭据，而目前用户中心并没有
// 反向调用本服务的能力（它不持有我们的服务令牌），做了也没有调用方。
//
// 代价是"用户中心主动注销"这条反向链路仍未打通：若账号在用户中心侧被
// 以别的入口关闭，本地绑定会残留到下一次登录时才被状态闸门拦下。
// 这一点记在 docs/implementation-status.md §34。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/interfaces/http/middleware"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// closeAccountInput 是注销请求体。
type closeAccountInput struct {
	// Confirm 必填且必须为 true。
	//
	// 注销不可逆，而它最可能的误触发方式是"业务方把某个按钮接错了接口"——
	// 那种调用不会带这个字段。要求一个显式布尔值，成本几乎为零，却能把
	// "误调用"与"用户真的想注销"区分开。
	Confirm bool `json:"confirm"`
	// Reason 是用户给出的注销原因，可选。写了就进审计，便于产品侧
	// 了解流失原因；不强制是因为强制填写的理由基本都是"无"。
	Reason string `json:"reason"`
}

// CloseAccount 处理 POST /v1/account/close。
func (h *Handler) CloseAccount(c *gin.Context) {
	app := middleware.App(c)
	userID := middleware.ExternalUserID(c)
	if app == nil || userID == "" {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeUnauthorized, "需要已登录的账号"))
		return
	}

	var in closeAccountInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httputil.FailBadRequest(c, h.logger(), "请求体格式错误", "body")
		return
	}
	if !in.Confirm {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInvalidRequest,
			"注销不可逆，需要在请求体中显式确认（confirm=true）").
			WithDetail("field", "confirm"))
		return
	}

	res, err := h.deps.AccountClose.Close(c.Request.Context(), app.AppCode, userID, in.Reason)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	httputil.OK(c, http.StatusOK, res)
}
