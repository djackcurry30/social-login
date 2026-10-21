package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AdminGrantRepository 是 admin_grants 表的仓储（K 组）。
type AdminGrantRepository struct {
	db *gorm.DB
}

// NewAdminGrantRepository 构造仓储。
func NewAdminGrantRepository(db *gorm.DB) *AdminGrantRepository {
	return &AdminGrantRepository{db: db}
}

var _ admin.GrantRepository = (*AdminGrantRepository)(nil)

// List 查询授权。
func (r *AdminGrantRepository) List(ctx context.Context, f admin.GrantFilter) ([]admin.Grant, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.SubjectID != "" {
			q = q.Where("subject_id = ?", f.SubjectID)
		}
		if !f.IncludeRevoked {
			q = q.Where("revoked_at IS NULL")
		}
		return q
	}

	var total int64
	if err := apply(r.db.WithContext(ctx).Model(&adminGrantModel{})).Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计授权失败", err)
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

	var rows []adminGrantModel
	if err := apply(r.db.WithContext(ctx).Model(&adminGrantModel{})).
		Order("granted_at DESC, id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询授权失败", err)
	}

	out := make([]admin.Grant, 0, len(rows))
	for i := range rows {
		out = append(out, toGrant(&rows[i]))
	}
	return out, total, nil
}

// Insert 授予角色。
//
// 唯一约束是 (subject_id, role, scope_app_id)，且 scope 为 NULL 时 Postgres
// 认为 NULL 互不相等——所以"全局授权"的幂等不能依赖唯一索引。
// 这里先查活跃授权再插入，并用事务包住，避免并发下建出两条全局授权。
func (r *AdminGrantRepository) Insert(ctx context.Context, g *admin.Grant) (*admin.Grant, error) {
	if g == nil || g.SubjectID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "授权缺少 subject_id")
	}
	if !g.Role.IsValid() {
		return nil, errs.Newf(errs.CodeInvalidRequest, "未知角色: %s", g.Role)
	}

	var out *admin.Grant
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing adminGrantModel
		q := tx.Where("subject_id = ? AND role = ? AND revoked_at IS NULL", g.SubjectID, string(g.Role))
		if g.ScopeAppID != nil {
			q = q.Where("scope_app_id = ?", *g.ScopeAppID)
		} else {
			q = q.Where("scope_app_id IS NULL")
		}
		err := q.Take(&existing).Error
		if err == nil {
			// 已存在同范围同角色的活跃授权：直接返回，不重复插入。
			gr := toGrant(&existing)
			out = &gr
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return errs.Wrap(errs.CodeInternal, "查询既有授权失败", err)
		}

		m := &adminGrantModel{
			SubjectID:  g.SubjectID,
			Role:       string(g.Role),
			ScopeAppID: g.ScopeAppID,
			GrantedBy:  g.GrantedBy,
			GrantedAt:  g.GrantedAt,
			ExpiresAt:  g.ExpiresAt,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(m).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "写入授权失败", err)
		}
		gr := toGrant(m)
		out = &gr
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke 撤销授权（软删，保留历史）。
func (r *AdminGrantRepository) Revoke(ctx context.Context, id int64, at time.Time) (*admin.Grant, error) {
	var m adminGrantModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, admin.ErrGrantNotFound
		}
		return nil, errs.Wrap(errs.CodeInternal, "查询授权失败", err)
	}
	if m.RevokedAt == nil {
		if err := r.db.WithContext(ctx).Model(&adminGrantModel{}).
			Where("id = ?", id).Update("revoked_at", at).Error; err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "撤销授权失败", err)
		}
		m.RevokedAt = &at
	}
	g := toGrant(&m)
	return &g, nil
}

// FindByID 按主键查。
func (r *AdminGrantRepository) FindByID(ctx context.Context, id int64) (*admin.Grant, error) {
	var m adminGrantModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, admin.ErrGrantNotFound
		}
		return nil, errs.Wrap(errs.CodeInternal, "查询授权失败", err)
	}
	g := toGrant(&m)
	return &g, nil
}

// ListEffectiveBySubject 返回某主体当前生效的授权。
//
// "生效"的判据放在 SQL 里而不是查询后再过滤：鉴权路径上不该把
// 已过期/已撤销的记录读进内存再丢掉。
func (r *AdminGrantRepository) ListEffectiveBySubject(ctx context.Context, subjectID string, now time.Time) ([]admin.Grant, error) {
	if subjectID == "" {
		return nil, nil
	}
	var rows []adminGrantModel
	if err := r.db.WithContext(ctx).
		Where("subject_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
			subjectID, now).
		Find(&rows).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询生效授权失败", err)
	}
	out := make([]admin.Grant, 0, len(rows))
	for i := range rows {
		out = append(out, toGrant(&rows[i]))
	}
	return out, nil
}

func toGrant(m *adminGrantModel) admin.Grant {
	return admin.Grant{
		ID:         m.ID,
		SubjectID:  m.SubjectID,
		Role:       admin.Role(m.Role),
		ScopeAppID: m.ScopeAppID,
		GrantedBy:  m.GrantedBy,
		GrantedAt:  m.GrantedAt,
		ExpiresAt:  m.ExpiresAt,
		RevokedAt:  m.RevokedAt,
	}
}

// attachGrants 为管理员补齐生效授权。
//
// 在仓储层做而不是用例层：FindByID / FindByUsername 有多个调用点
// （登录、鉴权中间件、管理端查询），漏掉任何一处都会让权限判定不一致。
func attachGrants(ctx context.Context, db *gorm.DB, now time.Time, u *admin.User) error {
	if u == nil {
		return nil
	}
	var rows []adminGrantModel
	if err := db.WithContext(ctx).
		Where("subject_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
			admin.SubjectOf(u.ID), now).
		Find(&rows).Error; err != nil {
		return errs.Wrap(errs.CodeInternal, "加载管理员授权失败", err)
	}
	if len(rows) == 0 {
		return nil
	}
	u.Grants = make([]admin.Grant, 0, len(rows))
	for i := range rows {
		u.Grants = append(u.Grants, toGrant(&rows[i]))
	}
	return nil
}
