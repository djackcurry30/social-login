package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AuditExportRepository 是 audit_export_tasks 表的仓储。
type AuditExportRepository struct {
	db *gorm.DB
}

// NewAuditExportRepository 构造仓储。
func NewAuditExportRepository(db *gorm.DB) *AuditExportRepository {
	return &AuditExportRepository{db: db}
}

var _ audit.ExportStore = (*AuditExportRepository)(nil)

// Create 新建任务。
func (r *AuditExportRepository) Create(ctx context.Context, t *audit.ExportTask) error {
	m, err := toExportModel(t)
	if err != nil {
		return err
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return errs.Wrap(errs.CodeInternal, "创建导出任务失败", err)
	}
	return nil
}

// Get 按 id 查任务。
func (r *AuditExportRepository) Get(ctx context.Context, id string) (*audit.ExportTask, error) {
	var m auditExportTaskModel
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, audit.ErrExportNotFound
		}
		return nil, errs.Wrap(errs.CodeInternal, "查询导出任务失败", err)
	}
	return fromExportModel(&m)
}

// ListBySubject 列出某管理员最近的导出任务。
func (r *AuditExportRepository) ListBySubject(ctx context.Context, subjectID string, limit int) ([]*audit.ExportTask, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var rows []auditExportTaskModel
	if err := r.db.WithContext(ctx).
		Where("subject_id = ?", subjectID).
		Order("created_at DESC").
		Limit(limit).Find(&rows).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询导出任务列表失败", err)
	}
	out := make([]*audit.ExportTask, 0, len(rows))
	for i := range rows {
		t, err := fromExportModel(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// claimRow 是原子领取的返回行。
type claimRow struct {
	ID        string    `gorm:"column:id"`
	SubjectID string    `gorm:"column:subject_id"`
	Filter    JSONMap   `gorm:"column:filter"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

// ClaimPending 原子领取一条待执行的导出任务。
//
// 单条 UPDATE + 子查询，靠 FOR UPDATE SKIP LOCKED 保证多副本 worker
// 各自领到不同任务：这是 PG 上"队列语义"的标准写法，不需要额外的
// 分布式锁，也不需要引入 Redis 队列。
//
// 为什么没有租约（与 event_outbox 不同）：导出是幂等的——重复导出最多
// 多写一个文件，不会造成对外可见的副作用（事件外发会）。因此进程崩溃后
// 把 running 任务重置为 pending 由启动时的一次性修复完成（见 RequeueStale），
// 而不是每轮扫描。
func (r *AuditExportRepository) ClaimPending(ctx context.Context) (*audit.ExportTask, error) {
	const q = `
UPDATE audit_export_tasks
   SET status = 'running', started_at = now()
 WHERE id = (
       SELECT id FROM audit_export_tasks
        WHERE status = 'pending'
        ORDER BY created_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED
 )
RETURNING id, subject_id, filter, created_at`

	var row claimRow
	if err := r.db.WithContext(ctx).Raw(q).Scan(&row).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "领取导出任务失败", err)
	}
	if row.ID == "" {
		return nil, nil
	}
	crit, err := decodeCriteria(row.Filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &audit.ExportTask{
		ID:        row.ID,
		SubjectID: row.SubjectID,
		Criteria:  crit,
		Status:    audit.ExportRunning,
		CreatedAt: row.CreatedAt,
		StartedAt: &now,
	}, nil
}

// MarkSucceeded 标记成功并落盘信息。
func (r *AuditExportRepository) MarkSucceeded(ctx context.Context, id string, rows, size int64, path string, expiresAt time.Time) error {
	res := r.db.WithContext(ctx).Model(&auditExportTaskModel{}).
		Where("id = ? AND status = ?", id, audit.ExportRunning).
		Updates(map[string]any{
			"status":      audit.ExportSucceeded,
			"row_count":   rows,
			"file_size":   size,
			"file_path":   path,
			"expires_at":  expiresAt,
			"finished_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "回写导出任务失败", res.Error)
	}
	// 影响行数为 0 只在"任务被并发清理"时出现，不是错误——文件由调用方删。
	return nil
}

// MarkFailed 标记失败。
//
// 失败也写 finished_at：否则监控图里"卡在 running"的任务会一直挂着，
// 排查时无法区分"还在跑"与"崩了没回写"。
func (r *AuditExportRepository) MarkFailed(ctx context.Context, id string, code, message string) error {
	res := r.db.WithContext(ctx).Model(&auditExportTaskModel{}).
		Where("id = ? AND status = ?", id, audit.ExportRunning).
		Updates(map[string]any{
			"status":        audit.ExportFailed,
			"error_code":    code,
			"error_message": message,
			"finished_at":   time.Now().UTC(),
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "回写导出任务失败", res.Error)
	}
	return nil
}

// PurgeExpired 清理到期任务的元数据，返回被清理的任务（供调用方删文件）。
func (r *AuditExportRepository) PurgeExpired(ctx context.Context, now time.Time, limit int) ([]*audit.ExportTask, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows []auditExportTaskModel
	if err := r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ? AND status IN ?",
			now.UTC(), []string{audit.ExportSucceeded, audit.ExportFailed}).
		Order("expires_at").
		Limit(limit).Find(&rows).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询到期导出任务失败", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(rows))
	out := make([]*audit.ExportTask, 0, len(rows))
	for i := range rows {
		t, err := fromExportModel(&rows[i])
		if err != nil {
			return nil, err
		}
		ids = append(ids, t.ID)
		out = append(out, t)
	}
	if err := r.db.WithContext(ctx).Where("id IN ?", ids).
		Delete(&auditExportTaskModel{}).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "清理到期导出任务失败", err)
	}
	return out, nil
}

// RequeueStale 把进程重启后遗留的 running 任务退回 pending。
//
// 只在 worker 启动时调用一次：运行中不做周期性回收，因为导出任务的
// 执行时间有明确上界（单次 SELECT 流 + 写文件），长期 running 只可能是
// 崩溃遗留。
func (r *AuditExportRepository) RequeueStale(ctx context.Context) (int64, error) {
	res := r.db.WithContext(ctx).Model(&auditExportTaskModel{}).
		Where("status = ?", audit.ExportRunning).
		Updates(map[string]any{"status": audit.ExportPending, "started_at": nil})
	if res.Error != nil {
		return 0, errs.Wrap(errs.CodeInternal, "重置遗留导出任务失败", res.Error)
	}
	return res.RowsAffected, nil
}

func toExportModel(t *audit.ExportTask) (*auditExportTaskModel, error) {
	crit, err := encodeCriteria(t.Criteria)
	if err != nil {
		return nil, err
	}
	m := &auditExportTaskModel{
		ID:         t.ID,
		SubjectID:  t.SubjectID,
		Filter:     crit,
		Status:     t.Status,
		RowCount:   t.RowCount,
		FileSize:   t.FileSize,
		CreatedAt:  t.CreatedAt,
		StartedAt:  t.StartedAt,
		FinishedAt: t.FinishedAt,
		ExpiresAt:  t.ExpiresAt,
	}
	if t.FilePath != "" {
		p := t.FilePath
		m.FilePath = &p
	}
	if t.ErrorCode != "" {
		c := t.ErrorCode
		m.ErrorCode = &c
	}
	if t.ErrorMessage != "" {
		e := t.ErrorMessage
		m.ErrorMessage = &e
	}
	return m, nil
}

func fromExportModel(m *auditExportTaskModel) (*audit.ExportTask, error) {
	crit, err := decodeCriteria(m.Filter)
	if err != nil {
		return nil, err
	}
	t := &audit.ExportTask{
		ID:         m.ID,
		SubjectID:  m.SubjectID,
		Criteria:   crit,
		Status:     m.Status,
		RowCount:   m.RowCount,
		FileSize:   m.FileSize,
		CreatedAt:  m.CreatedAt,
		StartedAt:  m.StartedAt,
		FinishedAt: m.FinishedAt,
		ExpiresAt:  m.ExpiresAt,
	}
	if m.FilePath != nil {
		t.FilePath = *m.FilePath
	}
	if m.ErrorCode != nil {
		t.ErrorCode = *m.ErrorCode
	}
	if m.ErrorMessage != nil {
		t.ErrorMessage = *m.ErrorMessage
	}
	return t, nil
}

func encodeCriteria(c audit.ExportCriteria) (JSONMap, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "序列化导出条件失败", err)
	}
	out := JSONMap{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "序列化导出条件失败", err)
	}
	return out, nil
}

func decodeCriteria(m JSONMap) (audit.ExportCriteria, error) {
	var c audit.ExportCriteria
	if len(m) == 0 {
		return c, nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return c, errs.Wrap(errs.CodeInternal, "反序列化导出条件失败", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, errs.Wrap(errs.CodeInternal, "反序列化导出条件失败", err)
	}
	return c, nil
}
