// Package handler 中的 observability.go：I 组（观测与健康）路由薄壳。
//
// 端点清单（架构 §15.4 I 组第一期 3 个；本期去掉 circuit-reset，留给第四期）：
//
//	GET /admin/v1/providers               ListProviders
//	GET /admin/v1/providers/health        PingProviders
//	GET /admin/v1/health/overview         Overview
//
// I 组没有写操作，没有 reason 强制。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminobs"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// ObservabilityHandler 是 I 组 handler。
type ObservabilityHandler struct {
	svc    *adminobs.Service
	logger *zap.Logger
}

// NewObservabilityHandler 构造 I 组 handler。
func NewObservabilityHandler(svc *adminobs.Service, logger *zap.Logger) *ObservabilityHandler {
	return &ObservabilityHandler{svc: svc, logger: logger}
}

// ListProviders GET /admin/v1/providers
//
// 返回已注册渠道清单（仅元数据：platform/scene/display_name/api_version/...）。
// 不返回渠道的运行时配置（凭证），凭证在 provider-configs Group 端点里管。
func (h *ObservabilityHandler) ListProviders(c *gin.Context) {
	items := h.svc.ListProviders()
	httputil.OK(c, http.StatusOK, gin.H{"items": items})
}

// PingProviders GET /admin/v1/providers/health
//
// 并发 ping 全部渠道的可达性。3s/渠道超时，全部完成后返回每条渠道的状态。
//
// 注意：本期 defaultPingHTTP 是占位实现（详见 adminobs.defaultPingHTTP）；
// 真正的 token_url 健康探测会在"渠道清单按 config 实时获取"时上线。
func (h *ObservabilityHandler) PingProviders(c *gin.Context) {
	out, err := h.svc.PingProviders(c.Request.Context())
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Overview GET /admin/v1/health/overview
//
// 摘要：provider_count / apps_count / healthy_providers / unhealthy_providers / by_platform。
//
// Overview 默认会 ping 一次各渠道（耗时 3s 兜底）—— 这是这个端点独有的延迟。
// 把它设计成"读 + ping 联动"是因为 §15.4 把它定位为看板"开屏要看的第一屏"。
func (h *ObservabilityHandler) Overview(c *gin.Context) {
	out, err := h.svc.Overview(c.Request.Context())
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// resetCircuitRequest 是 circuit-reset 的请求体。
type resetCircuitRequest struct {
	// Reason 必填：熔断复位会立刻恢复对该平台的流量，
	// 若平台实际仍在故障中，这是一次有风险的操作，必须留下动机。
	Reason string `json:"reason" binding:"required"`
}

// ResetCircuit POST /admin/v1/providers/:platform/circuit-reset
//
// 架构 §15.4 I 组。属于高危写操作：需要 config:write 权限、reason 必填、写管理审计。
func (h *ObservabilityHandler) ResetCircuit(c *gin.Context) {
	var req resetCircuitRequest
	if !httputil.BindJSON(c, &req, h.logger) {
		return
	}
	err := h.svc.ResetCircuit(c.Request.Context(), adminobs.ResetCircuitInput{
		Platform:  c.Param("platform"),
		Reason:    req.Reason,
		Principal: adminmw.Principal(c),
		ClientIP:  c.ClientIP(),
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{
		"platform":      c.Param("platform"),
		"circuit_state": "closed",
		"reset":         true,
	})
}