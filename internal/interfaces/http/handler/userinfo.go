package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/alex/social-login/internal/interfaces/http/httputil"
	"github.com/alex/social-login/internal/interfaces/http/middleware"
	"github.com/alex/social-login/internal/pkg/errs"
)

// UserInfo 处理 GET /v1/userinfo：返回归一化的当前用户身份与已绑渠道。
//
// 它刻意只返回【本服务的归一化结果】，不返回三方原始资料：
// 三方资料的权威源在渠道侧，本服务只保留展示用的最小快照，
// 业务方需要更多资料应直接调平台接口或由业务侧自行落地。
func (h *Handler) UserInfo(c *gin.Context) {
	app := middleware.App(c)
	userID := middleware.ExternalUserID(c)
	if app == nil || userID == "" {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeUnauthorized, "需要已登录的账号"))
		return
	}

	rows, err := h.deps.Bindings.ListBindings(c.Request.Context(), app.AppCode, userID)
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{
		// sub 直接用业务方账号标识（约束 C4：本服务不持有账号，不生成第二层别名）。
		"sub":      userID,
		"app_id":   app.AppCode,
		"bindings": rows,
	})
}
