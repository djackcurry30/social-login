package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// ClaimMismatchRepository 是 claim_mismatches 表的仓储（J 组）。
type ClaimMismatchRepository struct {
	db *gorm.DB
}

// NewClaimMismatchRepository 构造仓储。
func NewClaimMismatchRepository(db *gorm.DB) *ClaimMismatchRepository {
	return &ClaimMismatchRepository{db: db}
}

var _ identity.MismatchRepository = (*ClaimMismatchRepository)(nil)

// recordMismatchSQL 是去重写入。
//
// 为什么用原生 SQL 而不是 gorm 的 OnConflict clause：
// 目标索引是【部分唯一索引】uk_claim_mismatch_open（带 WHERE status='open'），
// ON CONFLICT 必须把同一个谓词再写一遍，PostgreSQL 才会做索引推断；
// gorm 的 clause.OnConflict 表达不了这个条件，写成 ON CONFLICT 全集
// 会在 "已闭环记录存在" 时报冲突——而那种情况本应允许新增一行。
//
// DO UPDATE 只刷新"最近一次观察到的状态"（谁、什么时候、佐证信息），
// 不改 first_seen_at：首次出现时间是判断"这处漂移存在多久"的依据，
// 被后来的登录覆盖掉就失去意义了。
const recordMismatchSQL = `
INSERT INTO claim_mismatches
    (app_id, claim_id, identity_id, claim_type, claim_value_hash,
     platform, claim_source, kind, expected_user_id, actual_user_id,
     detail, status, occurrences, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?)
ON CONFLICT (app_id, claim_id, kind) WHERE status = 'open'
DO UPDATE SET
    occurrences      = claim_mismatches.occurrences + 1,
    last_seen_at     = EXCLUDED.last_seen_at,
    expected_user_id = EXCLUDED.expected_user_id,
    actual_user_id   = EXCLUDED.actual_user_id,
    detail           = EXCLUDED.detail
`

// Record 写入（或累加）一条漂移记录。
func (r *ClaimMismatchRepository) Record(ctx context.Context, in identity.MismatchRecordInput) error {
	if err := in.Validate(); err != nil {
		return err
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, in.AppID)

	err := r.db.WithContext(ctx).Exec(recordMismatchSQL,
		in.AppID, in.ClaimID, in.IdentityID, in.ClaimType, in.ValueHash,
		in.Platform, in.ClaimSource, in.Kind,
		nilIfEmpty(in.ExpectedUserID), nilIfEmpty(in.ActualUserID), nilIfEmpty(in.Detail),
		at, at,
	).Error
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "写入凭证漂移记录失败", err)
	}
	return nil
}

// ListAdmin 分页查询漂移记录。
//
// 排序刻意做成"未闭环优先，其次最近命中"而不是单纯按时间：
// 运维打开页面要立刻看到待处理的那几条，已闭环的历史只是备查。
func (r *ClaimMismatchRepository) ListAdmin(ctx context.Context, q identity.MismatchAdminQuery) ([]identity.Mismatch, int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	apply := func(db *gorm.DB) *gorm.DB {
		if q.AppID > 0 {
			db = db.Where("app_id = ?", q.AppID)
		}
		if q.Status != "" {
			db = db.Where("status = ?", q.Status)
		}
		if q.Kind != "" {
			db = db.Where("kind = ?", q.Kind)
		}
		if q.ClaimType != "" {
			db = db.Where("claim_type = ?", q.ClaimType)
		}
		if q.IdentityID > 0 {
			db = db.Where("identity_id = ?", q.IdentityID)
		}
		return db
	}

	base := func() *gorm.DB {
		return r.db.WithContext(ctx).Model(&claimMismatchModel{})
	}

	var total int64
	if err := apply(base()).Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计凭证漂移记录失败", err)
	}

	page, size := q.Page, q.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}

	var ms []claimMismatchModel
	if err := apply(base()).
		Order("CASE WHEN status = 'open' THEN 0 ELSE 1 END").
		Order("last_seen_at DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&ms).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询凭证漂移记录失败", err)
	}

	out := make([]identity.Mismatch, 0, len(ms))
	for i := range ms {
		out = append(out, *mismatchToDomain(&ms[i]))
	}
	return out, total, nil
}

// ResolveByClaim 把某条 claim 下所有未闭环的漂移标记为已闭环。
func (r *ClaimMismatchRepository) ResolveByClaim(ctx context.Context, in identity.ResolveInput) (int64, error) {
	if in.AppID <= 0 || in.ClaimID <= 0 {
		return 0, errs.New(errs.CodeInternal, "闭环漂移记录缺少 app_id 或 claim_id")
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, in.AppID)

	res := r.db.WithContext(ctx).Model(&claimMismatchModel{}).
		Where("app_id = ? AND claim_id = ? AND status = ?",
			in.AppID, in.ClaimID, identity.MismatchStatusOpen).
		Updates(map[string]any{
			"status":      identity.MismatchStatusResolved,
			"resolved_at": at,
			"resolved_by": nilIfEmpty(in.By),
			"resolution":  nilIfEmpty(in.Resolution),
		})
	if res.Error != nil {
		return 0, errs.Wrap(errs.CodeInternal, "闭环凭证漂移记录失败", res.Error)
	}
	return res.RowsAffected, nil
}

func mismatchToDomain(m *claimMismatchModel) *identity.Mismatch {
	out := &identity.Mismatch{
		ID:          m.ID,
		AppID:       m.AppID,
		ClaimID:     m.ClaimID,
		IdentityID:  m.IdentityID,
		ClaimType:   m.ClaimType,
		ValueHash:   m.ClaimValueHash,
		Platform:    m.Platform,
		ClaimSource: m.ClaimSource,
		Kind:        m.Kind,
		Detail:      derefStr(m.Detail),
		Status:      m.Status,
		Occurrences: m.Occurrences,
		FirstSeenAt: m.FirstSeenAt,
		LastSeenAt:  m.LastSeenAt,
		ResolvedAt:  m.ResolvedAt,
		ResolvedBy:  derefStr(m.ResolvedBy),
		Resolution:  derefStr(m.Resolution),
	}
	if m.ExpectedUserID != nil {
		out.ExpectedUserID = *m.ExpectedUserID
	}
	if m.ActualUserID != nil {
		out.ActualUserID = *m.ActualUserID
	}
	return out
}

// nilIfEmpty 把空字符串转成 NULL。
//
// 这里的空值有语义：expected/actual 为空表示"这一侧没有该信息"
// （身份已删 / 用户中心查无此人），存成空串会和"账号 id 恰好是空串"混淆。
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// CountOpen 返回未闭环的漂移总数（全平台）。
//
// 只服务 I 组的 /health/overview 摘要。刻意不放进 identity.MismatchRepository
// 接口：那个接口是管理端 J 组的契约（查询 + 闭环），一个"给看板用的计数"
// 混进去会让所有实现方都被迫实现它。
func (r *ClaimMismatchRepository) CountOpen(ctx context.Context) (int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)
	var n int64
	err := r.db.WithContext(ctx).Model(&claimMismatchModel{}).
		Where("status = ?", identity.MismatchStatusOpen).
		Count(&n).Error
	if err != nil {
		return 0, errs.Wrap(errs.CodeInternal, "统计未闭环凭证漂移失败", err)
	}
	return n, nil
}
