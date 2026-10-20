package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// EventRepository 是 event_outbox 的仓储。
type EventRepository struct {
	db *gorm.DB
}

// NewEventRepository 构造仓储。
func NewEventRepository(db *gorm.DB) *EventRepository {
	return &EventRepository{db: db}
}

var _ event.Store = (*EventRepository)(nil)

// Append 追加一条事件。
//
// 调用约束：必须传业务事务的 ctx（本服务用 appctx 传作用域），才能与业务变更
// 落进同一个事务。仓储本身不开事务——开了就变成了"事件先提交、业务后回滚"。
func (r *EventRepository) Append(ctx context.Context, e *event.Event) error {
	if e == nil {
		return errs.New(errs.CodeInternal, "事件为空")
	}
	if e.EventID == "" || e.Type == "" {
		return errs.New(errs.CodeInternal, "事件缺少 event_id 或 event_type")
	}
	m := &eventOutboxModel{
		AppID:         e.AppID,
		EventID:       e.EventID,
		EventType:     e.Type,
		SchemaVersion: e.SchemaVersion,
		Payload:       jsonNotNull(e.Payload),
		Status:        string(event.StatusPending),
		Attempts:      0,
		CreatedAt:     time.Now().UTC(),
	}
	if m.SchemaVersion <= 0 {
		m.SchemaVersion = 1
	}
	// next_retry_at 留 NULL：立刻可投递（NULLS FIRST 让它们排在最前）。
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return errs.Wrap(errs.CodeInternal, "写入 outbox 失败", err)
	}
	e.ID = m.ID
	e.Status = event.StatusPending
	e.CreatedAt = m.CreatedAt
	return nil
}

// claimSQL 用一条语句完成"挑出来 + 占住"。
//
// 为什么不是 SELECT 再 UPDATE 两条语句：中间存在窗口，多副本会领到同一批事件，
// 业务方就会收到重复投递（虽然契约是至少一次，但重复放大到 2 倍会显著增加
// 对方的去重压力）。FOR UPDATE SKIP LOCKED 让并发副本直接跳过彼此的行。
//
// 占住的方式是把 next_retry_at 推到租约到期时间，而不是引入 sending 状态：
// 进程崩溃时租约自然过期，事件自动回到待投递，不需要额外的超时回收任务。
const claimSQL = `
WITH due AS (
    SELECT id FROM event_outbox
    WHERE status = 'pending'
      AND (next_retry_at IS NULL OR next_retry_at <= now())
    ORDER BY next_retry_at NULLS FIRST, id
    LIMIT ?
    FOR UPDATE SKIP LOCKED
)
UPDATE event_outbox o
SET next_retry_at = now() + ?::interval
FROM due
WHERE o.id = due.id
RETURNING o.id, o.app_id, o.event_id, o.event_type, o.schema_version,
          o.payload, o.status, o.attempts, o.last_error, o.created_at
`

// ClaimDue 领取到期事件。租约到期未完成的事件会被其它副本重新领取。
func (r *EventRepository) ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]*event.Event, error) {
	if limit <= 0 {
		limit = 20
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	// worker 天然跨应用，必须显式声明（否则隔离回调会 panic）。
	ctx = appctx.WithCrossAppScope(ctx)

	var rows []eventOutboxModel
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Raw(claimSQL, limit, lease.String()).Scan(&rows).Error
	})
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "领取 outbox 事件失败", err)
	}

	out := make([]*event.Event, 0, len(rows))
	for i := range rows {
		out = append(out, toEvent(&rows[i]))
	}
	return out, nil
}

// MarkSent 标记投递成功。
func (r *EventRepository) MarkSent(ctx context.Context, id int64) error {
	ctx = appctx.WithCrossAppScope(ctx)
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&eventOutboxModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":        string(event.StatusSent),
			"sent_at":       now,
			"next_retry_at": nil,
			"last_error":    nil,
		})
	return wrapUpdate(res, "标记事件已投递失败")
}

// MarkRetry 记录一次失败并安排下次重试。
func (r *EventRepository) MarkRetry(ctx context.Context, id int64, attempts int, next time.Time, lastErr string) error {
	ctx = appctx.WithCrossAppScope(ctx)
	res := r.db.WithContext(ctx).Model(&eventOutboxModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"attempts":      attempts,
			"next_retry_at": next.UTC(),
			"last_error":    truncateErr(lastErr),
		})
	return wrapUpdate(res, "更新事件重试状态失败")
}

// MarkDead 转入死信。
func (r *EventRepository) MarkDead(ctx context.Context, id int64, attempts int, lastErr string) error {
	ctx = appctx.WithCrossAppScope(ctx)
	res := r.db.WithContext(ctx).Model(&eventOutboxModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":        string(event.StatusDead),
			"attempts":      attempts,
			"next_retry_at": nil,
			"last_error":    truncateErr(lastErr),
		})
	return wrapUpdate(res, "标记事件为死信失败")
}

// MarkSkipped 标记"未配置投递地址"。
func (r *EventRepository) MarkSkipped(ctx context.Context, id int64, reason string) error {
	ctx = appctx.WithCrossAppScope(ctx)
	res := r.db.WithContext(ctx).Model(&eventOutboxModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":        string(event.StatusSkipped),
			"next_retry_at": nil,
			"last_error":    truncateErr(reason),
		})
	return wrapUpdate(res, "标记事件跳过失败")
}

// Get 按主键取事件。
func (r *EventRepository) Get(ctx context.Context, id int64) (*event.Event, error) {
	ctx = appctx.WithCrossAppScope(ctx)
	var m eventOutboxModel
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, event.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询事件失败", err)
	}
	return toEvent(&m), nil
}

// List 按条件分页查询。
func (r *EventRepository) List(ctx context.Context, f event.Filter) ([]*event.Event, int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)
	q := r.db.WithContext(ctx).Model(&eventOutboxModel{})
	if f.AppID > 0 {
		q = q.Where("app_id = ?", f.AppID)
	}
	if f.Status != "" {
		q = q.Where("status = ?", string(f.Status))
	}
	if f.Type != "" {
		q = q.Where("event_type = ?", f.Type)
	}
	if f.From != nil {
		q = q.Where("created_at >= ?", f.From.UTC())
	}
	if f.To != nil {
		q = q.Where("created_at < ?", f.To.UTC())
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计事件失败", err)
	}

	page, size := f.Page, f.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}

	var rows []eventOutboxModel
	if err := q.Order("id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询事件列表失败", err)
	}

	out := make([]*event.Event, 0, len(rows))
	for i := range rows {
		out = append(out, toEvent(&rows[i]))
	}
	return out, total, nil
}

// Restore 死信重投：重置 attempts 与状态，event_id 保持不变。
//
// 保持 event_id 是契约要求（§5.4）：业务方按 event_id 去重，换新 ID 会让
// 同一条业务事件被处理两次。
func (r *EventRepository) Restore(ctx context.Context, id int64) error {
	ctx = appctx.WithCrossAppScope(ctx)
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&eventOutboxModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":        string(event.StatusPending),
			"attempts":      0,
			"next_retry_at": now,
			"last_error":    nil,
			"sent_at":       nil,
		})
	return wrapUpdate(res, "重置事件失败")
}

// Discard 人工丢弃。
func (r *EventRepository) Discard(ctx context.Context, id int64, reason string) error {
	ctx = appctx.WithCrossAppScope(ctx)
	// 刻意不覆盖 last_error：那里存的是最近一次【投递失败】的原因，
	// 排障时恰恰最需要它。丢弃理由记在管理审计里（谁、何时、为什么），
	// 事件本身只翻转状态——否则查询详情会看到"错误"写着一段中文理由。
	res := r.db.WithContext(ctx).Model(&eventOutboxModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":        string(event.StatusDiscarded),
			"next_retry_at": nil,
		})
	return wrapUpdate(res, "丢弃事件失败")
}

func wrapUpdate(res *gorm.DB, msg string) error {
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, msg, res.Error)
	}
	if res.RowsAffected == 0 {
		return event.ErrNotFound
	}
	return nil
}

// truncateErr 截断错误信息，避免上游返回整页 HTML 把 last_error 撑爆。
func truncateErr(s string) string {
	const max = 1000
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

func toEvent(m *eventOutboxModel) *event.Event {
	e := &event.Event{
		ID:            m.ID,
		AppID:         m.AppID,
		EventID:       m.EventID,
		Type:          m.EventType,
		SchemaVersion: m.SchemaVersion,
		Payload:       map[string]any(m.Payload),
		Status:        event.Status(m.Status),
		Attempts:      m.Attempts,
		NextRetryAt:   m.NextRetryAt,
		CreatedAt:     m.CreatedAt,
		SentAt:        m.SentAt,
	}
	if m.LastError != nil {
		e.LastError = *m.LastError
	}
	return e
}
