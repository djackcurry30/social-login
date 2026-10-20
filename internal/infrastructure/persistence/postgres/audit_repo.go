package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AuditRepository 是 auth_audit_logs 表的仓储。
type AuditRepository struct {
	db *gorm.DB
}

// NewAuditRepository 构造仓储。
func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

var _ audit.Writer = (*AuditRepository)(nil)

// 查询侧列清单。
//
// 为什么带 COALESCE：表定义里 external_user_id / user_agent / trace_id 等列
// 允许为 NULL（历史数据与"系统级事件"），而 GORM 把 NULL 扫进 string 会直接
// 返回 converting NULL to string is unsupported。与其把模型全改成指针（会让
// 写入侧也得跟着判空），不如在查询列上收敛成空串——对外语义本来就是"没有"。
const auditSelectCols = `id, app_id,
	COALESCE(external_user_id, '') AS external_user_id,
	COALESCE(platform, '')         AS platform,
	COALESCE(scene, '')            AS scene,
	COALESCE(client, '')           AS client,
	action, result,
	COALESCE(error_code, '')       AS error_code,
	client_ip,
	COALESCE(user_agent, '')       AS user_agent,
	COALESCE(trace_id, '')         AS trace_id,
	COALESCE(detail, '{}'::jsonb)  AS detail,
	created_at`

var _ audit.Query = (*AuditRepository)(nil)

// auditFilter 把查询条件叠加到 q 上（与关系）。
//
// 单独成函数是为了让 List 与 Stream 共用同一套条件——导出与页面筛选
// 若走两份过滤逻辑，迟早会出现"页面上看到 3 条，导出的 CSV 里有 5 条"。
func auditFilter(q *gorm.DB, f audit.Filter) *gorm.DB {
	if f.AppID > 0 {
		q = q.Where("app_id = ?", f.AppID)
	}
	if f.Action != "" {
		q = q.Where("action = ?", f.Action)
	}
	if f.Result != "" {
		q = q.Where("result = ?", f.Result)
	}
	if f.ExternalUserID != "" {
		q = q.Where("external_user_id = ?", f.ExternalUserID)
	}
	if f.TraceID != "" {
		q = q.Where("trace_id = ?", f.TraceID)
	}
	if f.Platform != "" {
		q = q.Where("platform = ?", f.Platform)
	}
	if f.Client != "" {
		q = q.Where("client = ?", f.Client)
	}
	if f.From != nil {
		q = q.Where("created_at >= ?", f.From.UTC())
	}
	if f.To != nil {
		// 与 event_repo 一致：上界取开区间，避免 from==to 时把整秒的记录都排掉。
		q = q.Where("created_at < ?", f.To.UTC())
	}
	return q
}

// List 分页查询业务审计。
func (r *AuditRepository) List(ctx context.Context, f audit.Filter) ([]audit.Record, int64, error) {
	// 管理端天然跨应用：这里是一次显式的跨应用声明（§9.1），
	// 应用维度的过滤由 f.AppID 在 SQL 条件里表达，而不是靠作用域。
	ctx = appctx.WithCrossAppScope(ctx)

	var total int64
	if err := auditFilter(r.db.WithContext(ctx).Model(&auditLogModel{}), f).
		Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计审计日志失败", err)
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

	var rows []auditLogModel
	if err := auditFilter(r.db.WithContext(ctx).Model(&auditLogModel{}), f).
		Select(auditSelectCols).
		Order("created_at DESC, id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询审计日志失败", err)
	}

	out := make([]audit.Record, 0, len(rows))
	for i := range rows {
		out = append(out, toAuditRecord(&rows[i]))
	}
	return out, total, nil
}

// Stream 按批次回调业务审计（导出用）。
//
// 游标分页而不是 OFFSET：审计表单表可达千万行，OFFSET 深翻页会让 PG
// 逐行丢弃前面的结果，越导越慢。用 (created_at DESC, id DESC) 的键集游标
// 则每批都走索引。
//
// 游标字段用 id 就够：id 是 BIGSERIAL，与 created_at 同向递增，
// 且 (created_at, id) 的组合排序在"同一秒内多条"时仍保持全序。
func (r *AuditRepository) Stream(ctx context.Context, f audit.Filter, batch int, fn func([]audit.Record) error) error {
	if fn == nil {
		return nil
	}
	ctx = appctx.WithCrossAppScope(ctx)
	if batch <= 0 || batch > 5000 {
		batch = 500
	}

	lastAt := time.Time{}
	var lastID int64
	for {
		q := auditFilter(r.db.WithContext(ctx).Model(&auditLogModel{}), f).
			Select(auditSelectCols)
		if lastID > 0 {
			// (created_at, id) 严格小于上一批的最后一条。
			q = q.Where("(created_at, id) < (?, ?)", lastAt, lastID)
		}
		var rows []auditLogModel
		if err := q.Order("created_at DESC, id DESC").Limit(batch).Find(&rows).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "流式读取审计日志失败", err)
		}
		if len(rows) == 0 {
			return nil
		}
		recs := make([]audit.Record, 0, len(rows))
		for i := range rows {
			recs = append(recs, toAuditRecord(&rows[i]))
		}
		if err := fn(recs); err != nil {
			return err
		}
		last := rows[len(rows)-1]
		lastAt, lastID = last.CreatedAt, last.ID
		if len(rows) < batch {
			return nil
		}
	}
}

// ListAdmin 分页查询管理端审计。
//
// admin_audit_logs 不在 scopedTables 里——管理端审计天然跨应用，
// 它的 app_id 只是"这次操作针对哪个应用"，不是隔离边界。
func (r *AuditRepository) ListAdmin(ctx context.Context, f audit.AdminFilter) ([]audit.AdminRecord, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.SubjectID != "" {
			q = q.Where("subject_id = ?", f.SubjectID)
		}
		if f.Action != "" {
			q = q.Where("action = ?", f.Action)
		}
		if f.TargetType != "" {
			q = q.Where("target_type = ?", f.TargetType)
		}
		if f.TargetID != "" {
			q = q.Where("target_id = ?", f.TargetID)
		}
		if f.AppID > 0 {
			q = q.Where("app_id = ?", f.AppID)
		}
		if f.Result != "" {
			q = q.Where("result = ?", f.Result)
		}
		if f.From != nil {
			q = q.Where("created_at >= ?", f.From.UTC())
		}
		if f.To != nil {
			q = q.Where("created_at < ?", f.To.UTC())
		}
		return q
	}

	var total int64
	if err := apply(r.db.WithContext(ctx).Model(&adminAuditLogModel{})).
		Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计管理端审计失败", err)
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

	var rows []adminAuditLogModel
	if err := apply(r.db.WithContext(ctx).Model(&adminAuditLogModel{})).
		Order("created_at DESC, id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询管理端审计失败", err)
	}

	out := make([]audit.AdminRecord, 0, len(rows))
	for i := range rows {
		m := &rows[i]
		rec := audit.AdminRecord{
			ID:          m.ID,
			SubjectID:   m.SubjectID,
			Action:      m.Action,
			TargetType:  m.TargetType,
			TargetID:    m.TargetID,
			AppID:       m.AppID,
			Reason:      m.Reason,
			BeforeState: m.BeforeState,
			AfterState:  m.AfterState,
			TraceID:     m.TraceID,
			Result:      m.Result,
			ErrorCode:   m.ErrorCode,
			CreatedAt:   m.CreatedAt,
		}
		if m.ClientIP != nil {
			rec.ClientIP = *m.ClientIP
		}
		out = append(out, rec)
	}
	return out, total, nil
}

func toAuditRecord(m *auditLogModel) audit.Record {
	rec := audit.Record{
		ID:             m.ID,
		AppID:          m.AppID,
		ExternalUserID: m.ExternalUserID,
		Platform:       m.Platform,
		Scene:          m.Scene,
		Client:         m.Client,
		Action:         m.Action,
		Result:         m.Result,
		ErrorCode:      m.ErrorCode,
		UserAgent:      m.UserAgent,
		TraceID:        m.TraceID,
		Detail:         m.Detail,
		CreatedAt:      m.CreatedAt,
	}
	if m.ClientIP != nil {
		rec.ClientIP = *m.ClientIP
	}
	return rec
}

// Write 写入一条审计记录。
//
// 关于失败处理：本方法如实返回错误，但【调用方必须忽略它】——审计是旁路，
// 不能因为审计写不进去就让用户登录失败。应用层用 SafeWriter 包装后使用。
func (r *AuditRepository) Write(ctx context.Context, e *audit.Event) error {
	if e == nil {
		return nil
	}
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// 审计日志按应用隔离。系统级事件（app_id 为 0，如管理端操作、
	// 渠道回调异常）走显式跨应用作用域——这是代码里可见的一次声明。
	if e.AppID > 0 {
		ctx = appctx.WithAppScope(ctx, e.AppID)
	} else {
		ctx = appctx.WithCrossAppScope(ctx)
	}

	m := auditLogModel{
		AppID:          e.AppID,
		ExternalUserID: e.ExternalUserID,
		Platform:       e.Platform,
		Scene:          e.Scene,
		Client:         e.Client,
		Action:         e.Action,
		Result:         e.Result,
		ErrorCode:      e.ErrorCode,
		UserAgent:      e.UserAgent,
		TraceID:        e.TraceID,
		// NOT NULL 列：不是每条审计都有 detail。
		Detail:         jsonNotNull(e.Detail),
		CreatedAt:      at,
	}
	if e.ClientIP != "" {
		ip := e.ClientIP
		m.ClientIP = &ip
	}

	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return errs.Wrap(errs.CodeInternal, "写入审计日志失败", err)
	}
	return nil
}
