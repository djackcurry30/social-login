// Package adminevent 是管理端"事件与死信（G 组）"用例。
//
// 为什么这一组必须随二期一起交付（架构 §13）：渠道一接入，线上排障就只能靠
// "事件到底投出去了没有"。没有查询与重投，业务方一句"我没收到合并通知"
// 就只能翻库。
package adminevent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Deps 是用例依赖。
type Deps struct {
	Events     event.Store
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
	Now        func() time.Time
}

// Service 是 G 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: d}
}

// ListInput 是 GET /admin/v1/events/outbox 的入参。
type ListInput struct {
	AppID    int64
	Status   string
	Type     string
	From     string
	To       string
	Page     int
	PageSize int
}

// Item 是事件的对外视图。
//
// 字段命名与 §5.4 的事件体保持一致（event_id / event_type / schema_version），
// 避免运维在读日志与读接口之间做心智转换。
type Item struct {
	ID            int64          `json:"id"`
	AppID         int64          `json:"app_id"`
	EventID       string         `json:"event_id"`
	EventType     string         `json:"event_type"`
	SchemaVersion int            `json:"schema_version"`
	Status        string         `json:"status"`
	Attempts      int            `json:"attempts"`
	NextRetryAt   *time.Time     `json:"next_retry_at,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	SentAt        *time.Time     `json:"sent_at,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
}

// ListOutput 是列表出参。
type ListOutput struct {
	Items    []Item `json:"items"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// List 查询事件。
func (s *Service) List(ctx context.Context, in ListInput) (*ListOutput, error) {
	f := event.Filter{
		AppID:    in.AppID,
		Type:     in.Type,
		Page:     in.Page,
		PageSize: in.PageSize,
	}
	if in.Status != "" {
		st := event.Status(in.Status)
		if !st.Valid() {
			return nil, errs.Newf(errs.CodeInvalidRequest, "status 不合法: %s", in.Status)
		}
		f.Status = st
	}
	if in.From != "" {
		t, err := parseTime(in.From)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "from 时间格式非法，应为 RFC3339")
		}
		f.From = &t
	}
	if in.To != "" {
		t, err := parseTime(in.To)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "to 时间格式非法，应为 RFC3339")
		}
		f.To = &t
	}

	rows, total, err := s.deps.Events.List(ctx, f)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(rows))
	for _, e := range rows {
		// 列表不返回 payload：单条事件体可能很大，列表页只需要定位。
		items = append(items, toItem(e, false))
	}
	return &ListOutput{Items: items, Total: total, Page: max(in.Page, 1), PageSize: in.PageSize}, nil
}

// Get 返回事件详情（含 payload）。
func (s *Service) Get(ctx context.Context, id int64) (*Item, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	e, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	it := toItem(e, true)
	return &it, nil
}

// Retry 死信重投。
//
// 只允许对 dead / skipped / discarded 重投：对 pending 重投没有意义
// （它本来就会被投递），对 sent 重投会违反"同一 event_id 不重复投递成功"
// 的承诺——那会让业务方收到重复事件。
func (s *Service) Retry(ctx context.Context, id int64, principal *admin.Principal, reason string) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	e, err := s.load(ctx, id)
	if err != nil {
		return err
	}
	switch e.Status {
	case event.StatusDead, event.StatusSkipped, event.StatusDiscarded:
	case event.StatusSent:
		return errs.New(errs.CodeInvalidRequest, "已投递成功的事件不能重投").
			WithDetail("status", string(e.Status))
	default:
		return errs.Newf(errs.CodeInvalidRequest, "状态为 %s 的事件不能重投", e.Status)
	}

	if err := s.deps.Events.Restore(ctx, id); err != nil {
		s.writeAudit(ctx, principal, "event.retry", id, reason,
			map[string]any{"status": string(e.Status), "attempts": e.Attempts}, nil, "error", err)
		return err
	}
	// 重投保持原 event_id：业务方按它去重，换新 ID 会被当成新事件处理两次。
	s.writeAudit(ctx, principal, "event.retry", id, reason,
		map[string]any{"status": string(e.Status), "attempts": e.Attempts},
		map[string]any{"status": string(event.StatusPending), "attempts": 0, "event_id": e.EventID},
		"success", nil)
	return nil
}

// DiscardInput 是丢弃入参。
type DiscardInput struct {
	Reason    string `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// Discard 人工丢弃（需 reason）。
func (s *Service) Discard(ctx context.Context, id int64, in DiscardInput) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	if len([]rune(in.Reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired,
			"丢弃事件必须填写 reason（≥4 字符）")
	}
	e, err := s.load(ctx, id)
	if err != nil {
		return err
	}
	if e.Status == event.StatusSent {
		return errs.New(errs.CodeInvalidRequest, "已投递成功的事件不能丢弃")
	}
	if err := s.deps.Events.Discard(ctx, id, in.Reason); err != nil {
		return err
	}
	s.writeAudit(ctx, in.Principal, "event.discard", id, in.Reason,
		map[string]any{"status": string(e.Status)}, map[string]any{"status": string(event.StatusDiscarded)},
		"success", nil)
	return nil
}

// load 读取事件，并把"不存在"翻译成 404。
//
// 仓储返回的是哨兵错误 event.ErrNotFound——基础设施层不该依赖 HTTP 语义，
// 这个翻译必须发生在用例层。漏了这一步，httputil 会把它归一化成 500：
// 运维看到 500 以为服务崩了，而不是"这条事件不在了"（可能被清理任务删了、
// 或者是手工拼的 id）。
func (s *Service) load(ctx context.Context, id int64) (*event.Event, error) {
	e, err := s.deps.Events.Get(ctx, id)
	if err != nil {
		if errors.Is(err, event.ErrNotFound) {
			return nil, errs.New(errs.CodeNotFound, "事件不存在").WithDetail("id", id)
		}
		return nil, err
	}
	return e, nil
}

func toItem(e *event.Event, withPayload bool) Item {
	it := Item{
		ID:            e.ID,
		AppID:         e.AppID,
		EventID:       e.EventID,
		EventType:     e.Type,
		SchemaVersion: e.SchemaVersion,
		Status:        string(e.Status),
		Attempts:      e.Attempts,
		NextRetryAt:   e.NextRetryAt,
		LastError:     e.LastError,
		CreatedAt:     e.CreatedAt,
		SentAt:        e.SentAt,
	}
	if withPayload {
		it.Payload = e.Payload
	}
	return it
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action string, id int64,
	reason string, before, after map[string]any, result string, err error) {
	if s.deps.AdminAudit == nil {
		return
	}
	e := &admin.AuditEvent{
		Action:      action,
		TargetType:  "event_outbox",
		TargetID:    fmt.Sprintf("%d", id),
		Reason:      reason,
		BeforeState: before,
		AfterState:  after,
		Result:      result,
	}
	if p != nil && p.User != nil {
		e.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	} else {
		e.SubjectID = "admin:anonymous"
	}
	if err != nil {
		if ee, ok := errs.As(err); ok {
			e.ErrorCode = string(ee.Code)
		} else {
			e.ErrorCode = string(errs.CodeInternal)
		}
	}
	_ = s.deps.AdminAudit.Write(ctx, e)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
