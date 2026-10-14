package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/alex/social-login/internal/interfaces/http/httputil"
)

// HealthDeps 是健康检查需要探测的下游依赖。
//
// 用函数而非具体客户端，是为了让 handler 包不依赖基础设施实现——
// 同一个 Handler 在集成测试里可以注入桩，无需起真实数据库。
type HealthDeps struct {
	// PingDatabase 探测数据库连通性。
	PingDatabase func(ctx context.Context) error
	// PingCache 探测 Redis 连通性。
	PingCache func(ctx context.Context) error
}

// Live 处理 GET /healthz：存活探针。
//
// 存活探针【只回答"进程是否还活着"】，不探测下游。
// 这一点很关键：如果存活探针依赖数据库，数据库抖动会导致编排系统
// 把所有实例重启一遍，而重启并不能修好数据库——只会让故障面扩大。
func (h *Handler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": h.deps.Version})
}

// Ready 处理 GET /readyz：就绪探针，探测下游依赖。
//
// 与存活探针相反，就绪探针【应该】探测下游：它回答的是"现在能不能接流量"。
// 就绪失败只会把实例摘出负载均衡，不会引发重启风暴。
func (h *Handler) Ready(c *gin.Context) {
	// 探针必须有独立且短的超时，不能被一个卡住的下游拖住整个探测。
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{}
	ready := true
	for name, ping := range map[string]func(context.Context) error{
		"database": h.deps.Health.PingDatabase,
		"cache":    h.deps.Health.PingCache,
	} {
		if ping == nil {
			continue
		}
		if err := ping(ctx); err != nil {
			checks[name] = "down"
			ready = false
			continue
		}
		checks[name] = "up"
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	httputil.OK(c, status, gin.H{
		"status": map[bool]string{true: "ready", false: "not_ready"}[ready],
		"checks": checks,
	})
}
