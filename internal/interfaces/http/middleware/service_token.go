package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// ServiceTokenHeader 是服务间调用的令牌头。
//
// 用它而不是复用 Authorization: Bearer：
//
//	登录侧的公网接口已经用 Authorization 表达"业务方凭据 / 用户令牌"，
//	同一个头承载第三种身份会让鉴权中间件必须猜"这次是哪一种"。
//	独立的头让"内部接口"在日志与网关上都能被单独识别与拦截。
const ServiceTokenHeader = "X-Service-Token"

// ServiceToken 校验内部接口的服务令牌。
//
// 未配置令牌时一律 503，而不是"放行"：
//
//	漏配一个环境变量就变成公网可写的内部接口，是这类端点最常见的事故。
//	启动时配置校验会拦住生产环境，这里兜住开发/测试环境的误用。
func ServiceToken(token string) gin.HandlerFunc {
	want := []byte(strings.TrimSpace(token))
	return func(c *gin.Context) {
		if len(want) == 0 {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": gin.H{
					"code":    "INTERNAL.NOT_CONFIGURED",
					"message": "内部接口未配置服务令牌，拒绝处理",
				},
			})
			return
		}
		got := []byte(strings.TrimSpace(c.GetHeader(ServiceTokenHeader)))
		// 定长比较：普通 == 会在第一个不同字节处返回，理论上可被计时侧信道利用。
		if subtle.ConstantTimeCompare(got, want) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":      string(errs.CodeUnauthorized),
					"message":   "服务令牌无效",
					"retryable": false,
				},
			})
			return
		}
		c.Next()
	}
}
