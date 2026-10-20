// Package handler 中的 events.go：G 组（事件与死信）路由薄壳。
//
// 端点清单（架构 §15.4 G 组）：
//
//	GET  /admin/v1/events/outbox               List
//	GET  /admin/v1/events/outbox/:id           Get
//	POST /admin/v1/events/outbox/:id/retry     Retry
//	POST /admin/v1/events/outbox/:id/discard   Discard
//
// 路径里不用 ":retry" 后缀：gin 不支持路径段内的冒号，会被拆成
// "id" 与 ":retry" 两段并与其它子操作冲突（A 组已经踩过这个坑）。
package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminevent"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
)

// EventsHandler 是 G 组 handler。
type EventsHandler struct {
	svc    *adminevent.Service
	logger *zap.Logger
}

// NewEventsHandler 构造 G 组 handler。
func NewEventsHandler(svc *adminevent.Service, logger *zap.Logger) *EventsHandler {
	return &EventsHandler{svc: svc, logger: logger}
}

// List GET /admin/v1/events/outbox
func (h *EventsHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	appID, _ := strconv.ParseInt(c.Query("app_id"), 10, 64)

	out, err := h.svc.List(c.Request.Context(), adminevent.ListInput{
		AppID:    appID,
		Status:   c.Query("status"),
		Type:     c.Query("event_type"),
		From:     c.Query("from"),
		To:       c.Query("to"),
		Page:     page,
		PageSize: size,
	})
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Get GET /admin/v1/events/outbox/:id
func (h *EventsHandler) Get(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	item, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"event": item})
}

// Retry POST /admin/v1/events/outbox/:id/retry
//
// 重置 attempts 并立即重新排队。event_id 保持不变——业务方按它去重。
func (h *EventsHandler) Retry(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	// reason 对重投不是必须的（死信重投是常规运维动作），
	// 但给了就记进审计，便于回溯"谁在什么时候把哪条死信捞出来了"。
	_ = c.ShouldBindJSON(&body)

	if err := h.svc.Retry(c.Request.Context(), id, adminmw.Principal(c), body.Reason); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// Discard POST /admin/v1/events/outbox/:id/discard
func (h *EventsHandler) Discard(c *gin.Context) {
	id, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	var in adminevent.DiscardInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	in.Principal = adminmw.Principal(c)
	if err := h.svc.Discard(c.Request.Context(), id, in); err != nil {
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}
