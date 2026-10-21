package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// MergeRepository 是 merge_operations 表的仓储。
type MergeRepository struct {
	db *gorm.DB
}

// NewMergeRepository 构造仓储。
func NewMergeRepository(db *gorm.DB) *MergeRepository {
	return &MergeRepository{db: db}
}

var _ merge.Store = (*MergeRepository)(nil)

// Create 写入一条 pending 记录，幂等键冲突时返回已有记录。
//
// 用 ON CONFLICT DO NOTHING + 回查，而不是"先查再插"：
// 后者在并发下必然有窗口（两个请求同时查到"不存在"，然后一个失败），
// 而这里的并发是常态——用户连点、前端重试都会打到同一个键。
func (r *MergeRepository) Create(ctx context.Context, op *merge.Operation) (*merge.Operation, bool, error) {
	ctx = appctx.WithAppScope(ctx, op.AppID)

	m := &mergeOperationModel{
		AppID:          op.AppID,
		IdempotencyKey: op.IdempotencyKey,
		TargetUserID:   op.TargetUserID,
		SourceUserID:   op.SourceUserID,
		Status:         merge.StatusPending,
		Attempts:       1,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if op.IdentityID > 0 {
		id := op.IdentityID
		m.IdentityID = &id
	}
	if op.Reason != "" {
		reason := op.Reason
		m.Reason = &reason
	}

	res := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "app_id"}, {Name: "idempotency_key"}},
		DoNothing: true,
	}).Create(m)

	if res.Error != nil {
		return nil, false, errs.Wrap(errs.CodeInternal, "写入合并操作失败", res.Error)
	}
	if res.RowsAffected == 1 {
		saved, err := r.Get(ctx, m.ID)
		return saved, true, err
	}

	// 冲突：回查已有记录。
	var existing mergeOperationModel
	if err := r.db.WithContext(ctx).
		Where("app_id = ? AND idempotency_key = ?", op.AppID, op.IdempotencyKey).
		Take(&existing).Error; err != nil {
		return nil, false, errs.Wrap(errs.CodeInternal, "回查合并操作失败", err)
	}
	saved, err := fromMergeModel(&existing)
	return saved, false, err
}

// Get 按主键查询。
func (r *MergeRepository) Get(ctx context.Context, id int64) (*merge.Operation, error) {
	// merge_operations 在 scopedTables 里，必须给作用域。
	// 这里不知道 app_id，用显式跨应用声明 + 主键条件（主键唯一即可定位）。
	ctx = appctx.WithCrossAppScope(ctx)

	var m mergeOperationModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, merge.ErrNotFound
		}
		return nil, errs.Wrap(errs.CodeInternal, "查询合并操作失败", err)
	}
	return fromMergeModel(&m)
}

// List 分页查询（管理端 D 组）。
func (r *MergeRepository) List(ctx context.Context, f merge.Filter) ([]*merge.Operation, int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	apply := func(q *gorm.DB) *gorm.DB {
		if f.AppID > 0 {
			q = q.Where("app_id = ?", f.AppID)
		}
		if f.Status != "" {
			q = q.Where("status = ?", f.Status)
		}
		if f.UserID != "" {
			q = q.Where("(target_user_id = ? OR source_user_id = ?)", f.UserID, f.UserID)
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
	if err := apply(r.db.WithContext(ctx).Model(&mergeOperationModel{})).
		Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计合并操作失败", err)
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

	var rows []mergeOperationModel
	if err := apply(r.db.WithContext(ctx).Model(&mergeOperationModel{})).
		Order("created_at DESC, id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询合并操作失败", err)
	}

	out := make([]*merge.Operation, 0, len(rows))
	for i := range rows {
		op, err := fromMergeModel(&rows[i])
		if err != nil {
			return nil, 0, err
		}
		out = append(out, op)
	}
	return out, total, nil
}

// MarkDone 标记完成。
//
// 注意：这里【不】改 attempts。attempts 是"试了几次"的事实，
// 收敛过程把它清零会让排查记录失真（"明明重试过两次，为什么显示 1 次"）。
func (r *MergeRepository) MarkDone(ctx context.Context, id int64, remote map[string]any) error {
	updates := map[string]any{
		"status":     merge.StatusDone,
		"updated_at": time.Now().UTC(),
	}
	if remote != nil {
		updates["remote_result"] = JSONMap(remote)
	}
	return r.update(ctx, id, updates)
}

// MarkFailed 标记失败并累加 attempts。
func (r *MergeRepository) MarkFailed(ctx context.Context, id int64, remote map[string]any, lastErr string) error {
	updates := map[string]any{
		"status":     merge.StatusFailed,
		"last_error": lastErr,
		"updated_at": time.Now().UTC(),
		"attempts":   gorm.Expr("attempts + 1"),
	}
	if remote != nil {
		updates["remote_result"] = JSONMap(remote)
	}
	return r.update(ctx, id, updates)
}

// MarkDead 标记为不可自动恢复。
func (r *MergeRepository) MarkDead(ctx context.Context, id int64, lastErr string) error {
	return r.update(ctx, id, map[string]any{
		"status":     merge.StatusDead,
		"last_error": lastErr,
		"updated_at": time.Now().UTC(),
	})
}

// MarkRejected 标记为规则拒绝。
func (r *MergeRepository) MarkRejected(ctx context.Context, id int64, reason string) error {
	return r.update(ctx, id, map[string]any{
		"status":     merge.StatusRejected,
		"last_error": reason,
		"updated_at": time.Now().UTC(),
	})
}

// ListDue 返回需要补偿的操作。
//
// pending 也在里面：进程在"插入 pending"与"调用远端"之间崩溃时，
// 这条记录会永远停在 pending——它和 failed 一样需要被捞起来。
func (r *MergeRepository) ListDue(ctx context.Context, limit int) ([]*merge.Operation, error) {
	ctx = appctx.WithCrossAppScope(ctx)
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	var rows []mergeOperationModel
	if err := r.db.WithContext(ctx).
		Where("status IN ? AND attempts < ?", []string{merge.StatusPending, merge.StatusFailed}, merge.MaxAttempts).
		Order("updated_at").
		Limit(limit).Find(&rows).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询待补偿合并操作失败", err)
	}
	out := make([]*merge.Operation, 0, len(rows))
	for i := range rows {
		op, err := fromMergeModel(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, nil
}

func (r *MergeRepository) update(ctx context.Context, id int64, updates map[string]any) error {
	ctx = appctx.WithCrossAppScope(ctx)
	res := r.db.WithContext(ctx).Model(&mergeOperationModel{}).
		Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "回写合并操作失败", res.Error)
	}
	return nil
}

func fromMergeModel(m *mergeOperationModel) (*merge.Operation, error) {
	op := &merge.Operation{
		ID:             m.ID,
		AppID:          m.AppID,
		IdempotencyKey: m.IdempotencyKey,
		TargetUserID:   m.TargetUserID,
		SourceUserID:   m.SourceUserID,
		Status:         m.Status,
		Attempts:       m.Attempts,
		RemoteResult:   m.RemoteResult,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
	if m.IdentityID != nil {
		op.IdentityID = *m.IdentityID
	}
	if m.Reason != nil {
		op.Reason = *m.Reason
	}
	if m.LastError != nil {
		op.LastError = *m.LastError
	}
	return op, nil
}
