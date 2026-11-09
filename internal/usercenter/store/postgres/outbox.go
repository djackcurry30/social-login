package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// 出站事件类型。取值集合由 uc_outbox 的 ck_outbox_type 约束兜住。
const (
	OutboxClaimInvalidated = "claim.invalidated"
)

// OutboxInput 是一条待投递的出站事件。
//
// payload 由调用方构造（含 app_key / user_id / claim_type / reason），
// 本层只负责序列化与落库，不解释内容——事件语义属于 service。
type OutboxInput struct {
	AppID     int64
	EventType string
	Payload   map[string]any
}

// OutboxRecord 是投递器领到的一条事件。
type OutboxRecord struct {
	ID        int64
	AppID     int64
	EventType string
	Payload   []byte
	Attempts  int
	CreatedAt time.Time
}

// insertOutbox 在同一事务里写一条出站事件。
//
// 与业务写在同一个事务，是这套机制唯一的正确性来源：
// 换绑成功但事件没落库 = 登录侧永远不知道；事件落了库但换绑失败 = 登录侧
// 会撤销一条其实没变的 claim（无害但会多一次回源）。前者丢通知，后者多做事，
// 显然前者更糟——所以宁可让两者同生共死。
func insertOutbox(ctx context.Context, tx pgx.Tx, in *OutboxInput) error {
	if in == nil {
		return nil
	}
	payload, err := json.Marshal(in.Payload)
	if err != nil {
		return domain.New(domain.CodeInternal, "出站事件序列化失败").WithCause(err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO uc_outbox (app_id, event_type, payload)
		VALUES ($1, $2, $3::jsonb)`,
		in.AppID, in.EventType, string(payload))
	if err != nil {
		return translateDBError("insert_outbox", err)
	}
	return nil
}

// ClaimDueOutbox 领取最多 limit 条到期事件。
//
// 用 "UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING"
// 一条语句完成领取：
//
//  1. SKIP LOCKED 让多实例并发投递时各拿各的，不会互相阻塞，也不会重复投递；
//  2. 领取时把 next_attempt_at 推到 now+lease（秒），等于一个粗粒度租约——
//     进程在投递途中崩溃时，这条事件在租约到期后会重新变成"到期"，
//     不会永久卡在"已领取"状态（这正是不做"processing"状态的原因：
//     多一个状态就多一处可能永远出不来的地方）。
func (s *Store) ClaimDueOutbox(ctx context.Context, limit int, lease time.Duration) ([]OutboxRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	if lease <= 0 {
		lease = time.Minute
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE uc_outbox
		   SET next_attempt_at = now() + make_interval(secs => $2),
		       attempts = attempts + 1
		 WHERE id IN (
		       SELECT id FROM uc_outbox
		        WHERE status = 'pending' AND next_attempt_at <= now()
		        ORDER BY id
		        FOR UPDATE SKIP LOCKED
		        LIMIT $1
		 )
		RETURNING id, app_id, event_type, payload, attempts, created_at`,
		limit, int(lease.Seconds()))
	if err != nil {
		return nil, translateDBError("claim_outbox", err)
	}
	defer rows.Close()

	out := make([]OutboxRecord, 0, limit)
	for rows.Next() {
		var r OutboxRecord
		if err := rows.Scan(&r.ID, &r.AppID, &r.EventType, &r.Payload, &r.Attempts, &r.CreatedAt); err != nil {
			return nil, translateDBError("scan_outbox", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, translateDBError("iterate_outbox", err)
	}
	return out, nil
}

// MarkOutboxSent 标记投递成功。
func (s *Store) MarkOutboxSent(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE uc_outbox
		   SET status = 'sent', sent_at = now(), last_error = ''
		 WHERE id = $1`, id)
	if err != nil {
		return translateDBError("mark_outbox_sent", err)
	}
	return nil
}

// MarkOutboxFailed 记录一次失败，并决定是重试还是进死信。
//
// dead 由调用方（投递器）按最大次数判定：判定逻辑放应用层，
// 因为"重试几次算足够"是运维策略，不是存储的职责。
func (s *Store) MarkOutboxFailed(ctx context.Context, id int64, reason string, next time.Time, dead bool) error {
	status := "pending"
	if dead {
		status = "dead"
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE uc_outbox
		   SET status = $2, last_error = $3, next_attempt_at = $4
		 WHERE id = $1`, id, status, clip(reason, 500), next)
	if err != nil {
		return translateDBError("mark_outbox_failed", err)
	}
	return nil
}

// CountPendingOutbox 返回待投递事件数（运维指标用）。
//
// 只数 pending：dead 单独一条指标才有人去处理——把两者混在一起，
// "5 条待投递"看起来正常，而实际可能是 5 条永远发不出去的。
func (s *Store) CountPendingOutbox(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM uc_outbox WHERE status = 'pending'`).Scan(&n); err != nil {
		return 0, translateDBError("count_outbox", err)
	}
	return n, nil
}

// CountDeadOutbox 返回死信数。
func (s *Store) CountDeadOutbox(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM uc_outbox WHERE status = 'dead'`).Scan(&n); err != nil {
		return 0, translateDBError("count_outbox_dead", err)
	}
	return n, nil
}
