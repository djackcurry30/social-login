package handler

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/application/oauthnotify"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// maxNotifyBodyBytes 限制通知报文体积。
//
// 取 64 KiB：Apple 通知是一两千字节的 JWT，支付宝异步通知更小；
// 留 30 倍余量足以应付平台加字段，同时把"用超大 body 打爆内存"挡在外面
// （本接口是公开端点，没有应用凭据保护）。
const maxNotifyBodyBytes = 64 << 10

// notifyQuery 是 /v1/oauth/notify/{platform} 的查询参数。
//
// 三个参数都是【渠道配置的定位键】，不是业务数据：
// 通知报文里没有 app_id（平台不知道我们的多租户结构），因此必须由
// 在平台侧注册的通知地址带上它。
type notifyQuery struct {
	AppID     string `form:"app_id" binding:"required"`
	Scene     string `form:"scene"`
	ConfigKey string `form:"config_key"`
}

// Notify 处理 POST /v1/oauth/notify/{platform}。
//
// 这是【平台服务端到服务端】的通知入口，与浏览器无关：
//
//   - 不挂 AppAuth：调用方是 Apple / 支付宝的服务器，它们不会带我们的 app_secret；
//   - 不挂 UserAuth：通知里没有终端用户会话；
//   - 信任完全建立在报文签名上（由适配器验签），因此验签失败必须整体拒绝。
//
// 返回语义（对平台的重试策略有直接影响）：
//
//	2xx  报文合法，无论是否产生了状态变更。平台收到 2xx 即停止重投。
//	4xx  报文不合法（验签失败 / 缺参数）。平台通常不重投同一条签名错误的报文，
//	     即使重投也是我们希望它记一次失败。
//	5xx  我们自己的问题（DB 不可用）。必须让平台重投，否则通知就永久丢了。
func (h *Handler) Notify(c *gin.Context) {
	platform := c.Param("platform")

	var q notifyQuery
	if !httputil.BindQuery(c, &q, h.logger()) {
		return
	}
	if !provider.IsValidPlatform(platform) {
		httputil.Fail(c, h.logger(), errs.Newf(errs.CodeNotFound, "未知平台: %s", platform).
			WithDetail("platform", platform))
		return
	}

	scene := q.Scene
	if scene == "" {
		scene = defaultNotifyScene(platform)
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxNotifyBodyBytes))
	if err != nil {
		httputil.Fail(c, h.logger(), errs.Wrap(errs.CodeInvalidRequest, "读取通知报文失败", err))
		return
	}
	if len(body) == 0 {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInvalidRequest, "通知报文为空"))
		return
	}

	out, err := h.deps.Notify.Handle(c.Request.Context(), oauthnotify.Input{
		AppCode:   q.AppID,
		Platform:  platform,
		Scene:     scene,
		ConfigKey: q.ConfigKey,
		Raw: &provider.CallbackPayload{
			Platform: platform,
			Scene:    scene,
			Query:    c.Request.URL.Query(),
			Body:     body,
			Header:   c.Request.Header,
		},
	})
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}

	// 用 200 而非 204：平台侧的回执排查要靠响应体里的 event / handled，
	// 空响应会让"到底处理了没"变成只能翻日志的问题。
	httputil.OK(c, http.StatusOK, gin.H{
		"event":            out.Event,
		"handled":          out.Handled,
		"identity_id":      out.IdentityID,
		"external_user_id": out.ExternalUserID,
		"reason":           out.Reason,
	})
}

// defaultNotifyScene 给出各平台服务端通知默认使用的登录场景。
//
// 为什么复用登录场景而不是用 provider.SceneNotify：通知报文要用登录场景的
// 【凭据】来验签（Apple 的 client_id / 支付宝的 app_id + 公钥都在那份配置里），
// 而 provider_configs 表里不存在 scene=notify 的配置行——
// 用 notify 当 scene 会在查配置时直接 ProviderNotFound。
func defaultNotifyScene(platform string) string {
	switch platform {
	case provider.PlatformApple:
		return provider.SceneApp
	case provider.PlatformAlipay:
		return provider.SceneWeb
	default:
		return provider.SceneApp
	}
}
