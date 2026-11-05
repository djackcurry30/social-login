package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// 审计动作。取值集合由 account_audit_logs 的 ck_audit_action 约束兜住——
// 拼错一个字母会在插入时直接失败（事务回滚），而不是静默写进一条没人认得的记录。
const (
	AuditAccountCreated  = "account.created"
	AuditAccountMerged   = "account.merged"
	AuditClaimBound      = "claim.bound"
	AuditClaimReplaced   = "claim.replaced"
	AuditAccountClosed   = "account.closed"
	auditDefaultActor    = "service"
	auditMaxActorRunes   = 64
	auditMaxTraceRunes   = 64
	auditMaxUserAgent    = 512
	auditMaxClientIPRune = 64
)

// AuditInput 是一条待写入的审计记录。
//
// 它是"由 store 在业务事务里顺手写下去"的，因此不带时间戳：
// created_at 用数据库的 now()，与业务行的 updated_at 落在同一个事务时钟上，
// 排序不会出现"审计比业务晚 3ms 但看起来像两次操作"。
type AuditInput struct {
	AppID     int64
	AccountID int64
	UserID    string
	Action    string
	Actor     string
	TraceID   string
	ClientIP  string
	UserAgent string
	Detail    map[string]any
}

// insertAudit 在给定事务里写一条审计。
//
// 失败直接返回错误，让调用方的事务回滚：没有审计记录的写操作等于
// "数据变了但没人知道是谁改的"，那比操作失败更糟。
func insertAudit(ctx context.Context, tx pgx.Tx, in *AuditInput) error {
	if in == nil {
		return nil
	}
	detail, err := json.Marshal(in.Detail)
	if err != nil {
		// detail 只由本包的调用点构造（map[string]any 里放字符串与数字），
		// 序列化失败说明传了不可表达的值，属于编码问题，不该静默丢成 '{}'。
		return domain.New(domain.CodeInternal, "审计 detail 序列化失败").WithCause(err)
	}
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		actor = auditDefaultActor
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO account_audit_logs
			(app_id, account_id, user_id, action, actor, trace_id, client_ip, user_agent, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
		in.AppID, nullableID(in.AccountID), in.UserID, in.Action,
		clip(actor, auditMaxActorRunes),
		clip(in.TraceID, auditMaxTraceRunes),
		clip(in.ClientIP, auditMaxClientIPRune),
		clip(in.UserAgent, auditMaxUserAgent),
		string(detail))
	if err != nil {
		return translateDBError("insert_audit", err)
	}
	return nil
}

// nullableID 把 0 转成 NULL。
//
// 0 在库里会指向不存在的账号 id，而 NULL 明确表达"这次操作没有对应账号行"。
// 两者在后续统计（count distinct account_id）里的行为完全不同。
func nullableID(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}

// clip 截断过长的自由文本（调用方可控，必须限长）。
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// AuditFilter 是审计查询条件。
//
// 只支持"按账号"与"按应用"两个维度 + 游标翻页：
// 审计表的行数随时间线性增长，任何 offset 翻页在几百万行后都会变成全表扫描。
type AuditFilter struct {
	AppID  int64
	UserID string
	Action string
	// BeforeID 是游标（上一页最后一条的 id），0 表示第一页。
	BeforeID int64
	Limit    int
}

// AuditRecord 是查询出来的审计行。
type AuditRecord struct {
	ID        int64           `json:"id"`
	AppID     int64           `json:"app_id"`
	AccountID *int64          `json:"account_id,omitempty"`
	UserID    string          `json:"user_id"`
	Action    string          `json:"action"`
	Actor     string          `json:"actor"`
	TraceID   string          `json:"trace_id"`
	ClientIP  string          `json:"client_ip"`
	UserAgent string          `json:"user_agent"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"created_at"`
}

// ListAudit 查询审计记录（新的在前）。
//
// 排序键用 id 而不是 created_at：同一毫秒内可能有多条（建号 + 换绑），
// 按时间排序的结果不稳定，翻页时会漏行或重复。
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, app_id, account_id, user_id, action, actor, trace_id, client_ip, user_agent, detail, created_at
		  FROM account_audit_logs
		 WHERE app_id = $1
		   AND ($2 = '' OR user_id = $2)
		   AND ($3 = '' OR action = $3)
		   AND ($4 = 0 OR id < $4)
		 ORDER BY id DESC
		 LIMIT $5`,
		f.AppID, f.UserID, f.Action, f.BeforeID, limit)
	if err != nil {
		return nil, translateDBError("list_audit", err)
	}
	defer rows.Close()

	out := make([]AuditRecord, 0, limit)
	for rows.Next() {
		var r AuditRecord
		if err := rows.Scan(&r.ID, &r.AppID, &r.AccountID, &r.UserID, &r.Action, &r.Actor,
			&r.TraceID, &r.ClientIP, &r.UserAgent, &r.Detail, &r.CreatedAt); err != nil {
			return nil, translateDBError("scan_audit", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, translateDBError("iterate_audit", err)
	}
	return out, nil
}
