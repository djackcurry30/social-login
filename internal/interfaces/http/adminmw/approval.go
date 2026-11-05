package adminmw

import (
	"context"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// HeaderApprovalID 是携带审批单号的请求头。
//
// 用头而不是请求体：高危操作里有 PUT/PATCH 且请求体结构各不相同，
// 塞进 body 需要每个接口都改 DTO，而审批是横切逻辑。
// 放头里还有一个好处：代理/网关日志会带上它，"谁用哪张单执行了什么"可追溯。
const HeaderApprovalID = "X-Approval-Id"

// ApprovalConsumer 是"校验并消费审批单"的端口（实现见 adminapproval.Service）。
//
// 定义在中间件包而不是 application 层：中间件不该依赖用例层的具体类型，
// 而 application 层实现这个接口不需要 import 本包（Go 的隐式接口）。
type ApprovalConsumer interface {
	// actorID 是"用掉这张单的人"：审批单要能回答"谁批的、谁执行的"。
	// 两者必须都能查——只有批准人而不知道谁执行，出事后无法定责。
	Consume(ctx context.Context, id int64, action string, appID *int64, actorID int64) error
}

// RequireApproval 要求请求携带一张已批准、未使用、动作与目标匹配的审批单。
//
// 三个失败分支刻意区分：
//
//	没有头 / 格式错 → 400，提示"该怎么带"
//	单子不可用（未批准/已用/过期/不匹配）→ 由 Consume 返回具体错误码
//
// 注意：审批单在这里【即被消费】，即使后续业务失败也不退还。
// 这是有意的取舍——"失败了要重新审批"比"能重复使用一张已批准的授权"
// 安全得多，而前者只是麻烦。
func RequireApproval(consumer ApprovalConsumer, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimSpace(c.GetHeader(HeaderApprovalID))
		if raw == "" {
			httputil.Fail(c, nil, errs.New(errs.CodeAdminApprovalRequired,
				"该操作需要双人复核：请先提交审批，并把审批单号放入 "+HeaderApprovalID+" 请求头").
				WithDetail("action", action))
			return
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			httputil.Fail(c, nil, errs.New(errs.CodeInvalidRequest,
				HeaderApprovalID+" 必须是审批单编号（正整数）"))
			return
		}

		// 目标应用取路径里的 appId：审批单绑定应用，避免"批了 A 应用的单子
		// 拿去轮换 B 应用的密钥"。全局动作（如签名密钥轮换）没有 appId，
		// 对应审批单的 app_id 必须为 NULL。
		var appID *int64
		if v := c.Param("appId"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				httputil.Fail(c, nil, errs.New(errs.CodeInvalidRequest, "appId 不合法"))
				return
			}
			appID = &n
		}

		actorID := int64(0)
		if p := Principal(c); p != nil && p.User != nil {
			actorID = p.User.ID
		}
		if err := consumer.Consume(c.Request.Context(), id, action, appID, actorID); err != nil {
			httputil.Fail(c, nil, err)
			return
		}
		c.Next()
	}
}
