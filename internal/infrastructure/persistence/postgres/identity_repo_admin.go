package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// IdentityAdminRepository 提供管理端 C 组的身份多维查询。
//
// 单独成类型而不是加到 IdentityRepository：授权链路只用到 Upsert / FindByXxx，
// 让核心仓储为运维查询背债会让每次改动授权链路都要重新审视管理端语义。
type IdentityAdminRepository struct {
	db *gorm.DB
}

// NewIdentityAdminRepository 构造仓储。
func NewIdentityAdminRepository(db *gorm.DB) *IdentityAdminRepository {
	return &IdentityAdminRepository{db: db}
}

var _ identity.AdminLister = (*IdentityAdminRepository)(nil)

// ListAdmin 按多维条件查询身份。
func (r *IdentityAdminRepository) ListAdmin(ctx context.Context, q identity.AdminQuery) ([]identity.Identity, int64, error) {
	// 管理端天然跨应用：显式声明，之后用 q.AppID 做业务过滤。
	ctx = appctx.WithCrossAppScope(ctx)

	apply := func(db *gorm.DB) *gorm.DB {
		if q.AppID > 0 {
			db = db.Where("i.app_id = ?", q.AppID)
		}
		if q.Platform != "" {
			db = db.Where("i.platform = ?", q.Platform)
		}
		if q.OpenID != "" {
			db = db.Where("i.open_id = ?", q.OpenID)
		}
		if q.IdentityKey != "" {
			db = db.Where("i.identity_key = ?", q.IdentityKey)
		}
		if q.ExternalUserID != "" {
			// 身份本身不存账号归属（约束 C4），必须经绑定表反查。
			// EXISTS 而不是 JOIN：一个账号可能有多个身份，JOIN 会产生重复行，
			// 让分页 total 与列表长度对不上。
			db = db.Where(`EXISTS (
				SELECT 1 FROM oauth_bindings b
				 WHERE b.identity_id = i.id
				   AND b.external_user_id = ?
				   AND b.status = 'active'
			)`, q.ExternalUserID)
		}
		return db
	}

	base := func() *gorm.DB {
		return r.db.WithContext(ctx).Table("oauth_identities AS i")
	}

	var total int64
	if err := apply(base()).Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计身份失败", err)
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

	var rows []identityModel
	if err := apply(base()).
		Select("i.*").
		Order("i.id DESC").
		Offset((page - 1) * size).Limit(size).
		Scan(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询身份失败", err)
	}

	out := make([]identity.Identity, 0, len(rows))
	for i := range rows {
		out = append(out, *identityToDomain(&rows[i]))
	}
	return out, total, nil
}
