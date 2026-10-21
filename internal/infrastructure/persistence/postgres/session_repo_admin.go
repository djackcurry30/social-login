package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// SessionAdminRepository 提供管理端 E 组的会话查询。
type SessionAdminRepository struct {
	db *gorm.DB
}

var _ session.AdminLister = (*SessionAdminRepository)(nil)

// NewSessionAdminRepository 构造仓储。
func NewSessionAdminRepository(db *gorm.DB) *SessionAdminRepository {
	return &SessionAdminRepository{db: db}
}

// ListAdmin 查询刷新令牌（会话）。
func (r *SessionAdminRepository) ListAdmin(ctx context.Context, f session.AdminFilter) ([]session.RefreshToken, int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	apply := func(q *gorm.DB) *gorm.DB {
		if f.AppID > 0 {
			q = q.Where("app_id = ?", f.AppID)
		}
		if f.ExternalUserID != "" {
			q = q.Where("external_user_id = ?", f.ExternalUserID)
		}
		if f.DeviceID != "" {
			q = q.Where("device_id = ?", f.DeviceID)
		}
		if f.Active != nil {
			if *f.Active {
				q = q.Where("revoked = ? AND expires_at > now()", false)
			} else {
				q = q.Where("revoked = ? OR expires_at <= now()", true)
			}
		}
		return q
	}

	var total int64
	if err := apply(r.db.WithContext(ctx).Model(&refreshTokenModel{})).
		Count(&total).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "统计会话失败", err)
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

	var rows []refreshTokenModel
	if err := apply(r.db.WithContext(ctx).Model(&refreshTokenModel{})).
		Order("created_at DESC, id DESC").
		Offset((page - 1) * size).Limit(size).
		Find(&rows).Error; err != nil {
		return nil, 0, errs.Wrap(errs.CodeInternal, "查询会话失败", err)
	}

	out := make([]session.RefreshToken, 0, len(rows))
	for i := range rows {
		m := &rows[i]
		out = append(out, session.RefreshToken{
			ID:             m.ID,
			AppID:          m.AppID,
			ExternalUserID: m.ExternalUserID,
			TokenHash:      m.TokenHash,
			DeviceID:       m.DeviceID,
			Scope:          m.Scope,
			ExpiresAt:      m.ExpiresAt,
			RotatedFrom:    m.RotatedFrom,
			Revoked:        m.Revoked,
			RevokedReason:  m.RevokedReason,
			CreatedAt:      m.CreatedAt,
		})
	}
	return out, total, nil
}
