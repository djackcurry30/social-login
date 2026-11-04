package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/approval"
)

// AdminApprovalRepository 是 admin_approvals 的持久化实现。
//
// 所有状态变更都用一条 UPDATE ... WHERE 完成（原因见 domain/approval.Store），
// 这里不提供 "Update" 这种万能方法，避免调用方绕开状态机。
type AdminApprovalRepository struct {
	db *gorm.DB
}

// NewAdminApprovalRepository 构造仓储。
func NewAdminApprovalRepository(db *gorm.DB) *AdminApprovalRepository {
	return &AdminApprovalRepository{db: db}
}

var _ approval.Store = (*AdminApprovalRepository)(nil)

// Create 插入一张审批单。
func (r *AdminApprovalRepository) Create(ctx context.Context, a *approval.Approval) error {
	row := &adminApprovalModel{
		Action:      a.Action,
		AppID:       a.AppID,
		PayloadHash: a.PayloadHash,
		RequestedBy: a.RequestedBy,
		RequestedAt: a.RequestedAt,
		Reason:      a.Reason,
		Status:      string(approval.StatusPending),
		ExpiresAt:   a.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		return err
	}
	a.ID = row.ID
	return nil
}

// Get 按 id 读取。
func (r *AdminApprovalRepository) Get(ctx context.Context, id int64) (*approval.Approval, error) {
	var row adminApprovalModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, approval.ErrNotFound
		}
		return nil, err
	}
	return row.toDomain(), nil
}

// List 列出审批单（最近优先）。
func (r *AdminApprovalRepository) List(ctx context.Context, f approval.Filter) ([]*approval.Approval, error) {
	q := r.db.WithContext(ctx).Model(&adminApprovalModel{})
	if f.Status != "" {
		q = q.Where("status = ?", string(f.Status))
	}
	if f.RequestedBy != 0 {
		q = q.Where("requested_by = ?", f.RequestedBy)
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []adminApprovalModel
	if err := q.Order("requested_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*approval.Approval, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].toDomain())
	}
	return out, nil
}

// Approve 把待批准单置为已批准。
func (r *AdminApprovalRepository) Approve(ctx context.Context, id, approverID int64, at time.Time) error {
	return r.decide(ctx, id, approverID, at, approval.StatusApproved)
}

// Reject 驳回。
func (r *AdminApprovalRepository) Reject(ctx context.Context, id, approverID int64, at time.Time) error {
	return r.decide(ctx, id, approverID, at, approval.StatusRejected)
}

func (r *AdminApprovalRepository) decide(ctx context.Context, id, approverID int64, at time.Time, to approval.Status) error {
	// 条件更新：只有 pending 且未过期才能被决策。
	// 过期单不能"补批"——补批等于用一个已经过时的上下文授权现在的操作。
	// requested_by <> approver 也必须进 WHERE：只靠下面那段"0 行后判断"是不够的，
	// 因为自批的 UPDATE 在数据库层会被 CHECK 拒绝并返回一个原始 SQL 错误，
	// 最终被归一化成 INTERNAL.ERROR——语义对，但对调用方是误导（它会以为服务坏了）。
	res := r.db.WithContext(ctx).Model(&adminApprovalModel{}).
		Where("id = ? AND status = ? AND expires_at > ? AND requested_by <> ?",
			id, string(approval.StatusPending), at, approverID).
		Updates(map[string]any{
			"status":      string(to),
			"approved_by": approverID,
			"approved_at": at,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		// 分辨原因：不存在 / 已决策 / 已过期 / 自批。
		cur, err := r.Get(ctx, id)
		if err != nil {
			return err
		}
		switch {
		case cur.RequestedBy == approverID:
			return approval.ErrSelfApprove
		case !at.Before(cur.ExpiresAt):
			return approval.ErrExpired
		default:
			return approval.ErrNotPending
		}
	}
	return nil
}

// Consume 校验并消费审批单。
func (r *AdminApprovalRepository) Consume(ctx context.Context, id int64, action string, appID *int64, at time.Time) error {
	// 一条 UPDATE 同时完成四条判定：状态、未消费、未过期、动作与目标匹配。
	// 用一条语句而不是"读-判断-写"，是因为这里既是并发点（同一张单被两个
	// 请求同时用），也是安全边界（用 A 的批准执行 B 的动作）。
	q := r.db.WithContext(ctx).Model(&adminApprovalModel{}).
		Where("id = ? AND status = ? AND consumed_at IS NULL AND expires_at > ? AND action = ?",
			id, string(approval.StatusApproved), at, action)
	if appID != nil {
		q = q.Where("app_id = ?", *appID)
	} else {
		q = q.Where("app_id IS NULL")
	}
	res := q.Updates(map[string]any{
		"status":      string(approval.StatusConsumed),
		"consumed_at": at,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		cur, err := r.Get(ctx, id)
		if err != nil {
			return err
		}
		switch {
		case cur.Status != approval.StatusApproved || cur.ConsumedAt != nil:
			return approval.ErrNotApproved
		case !at.Before(cur.ExpiresAt):
			return approval.ErrExpired
		default:
			return approval.ErrMismatch
		}
	}
	return nil
}
