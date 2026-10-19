package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// IdentityRepository 是 oauth_identities 表的仓储。
type IdentityRepository struct {
	db *gorm.DB
}

// NewIdentityRepository 构造仓储。
func NewIdentityRepository(db *gorm.DB) *IdentityRepository {
	return &IdentityRepository{db: db}
}

var _ identity.Repository = (*IdentityRepository)(nil)

// Upsert 按唯一键 (app_id, platform, provider_app_id, open_id) 插入或更新身份。
//
// 使用 INSERT ... ON CONFLICT DO UPDATE ... RETURNING id，一次往返完成"创建或刷新"，
// 避免"先查后写"在并发下插入重复记录（唯一索引会拦，但会变成异常路径）。
func (r *IdentityRepository) Upsert(ctx context.Context, in identity.UpsertInput) (*identity.Identity, error) {
	if in.AppID <= 0 {
		return nil, errs.New(errs.CodeInternal, "身份写入缺少 app_id")
	}
	if in.Platform == "" || in.ProviderAppID == "" || in.OpenID == "" {
		return nil, errs.New(errs.CodeInternal, "身份写入缺少唯一键字段")
	}
	if in.IdentityKey == "" {
		// 约束 C3 下 identity_key = open_id（unionid 不可用）。
		in.IdentityKey = in.OpenID
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, in.AppID)

	m := identityModel{
		AppID:           in.AppID,
		Platform:        in.Platform,
		ProviderAppID:   in.ProviderAppID,
		OpenID:          in.OpenID,
		UnionID:         in.UnionID,
		IdentityKey:     in.IdentityKey,
		// NOT NULL 列：平台什么都没返回时 Profile 为空，不能写 NULL。
		ProfileSnapshot: jsonNotNull(in.Profile),
		ProfileSyncedAt: &at,
		FirstSeenAt:     at,
		LastLoginAt:     &at,
	}

	err := r.db.WithContext(ctx).Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "app_id"}, {Name: "platform"},
				{Name: "provider_app_id"}, {Name: "open_id"},
			},
			// 只更新可变字段：first_seen_at 必须保持首次时间，
			// 它是对账与风控"该身份何时出现"的唯一依据。
			DoUpdates: clause.Assignments(map[string]any{
				"union_id":          m.UnionID,
				"identity_key":      m.IdentityKey,
				"profile_snapshot":  m.ProfileSnapshot,
				"profile_synced_at": m.ProfileSyncedAt,
				"last_login_at":     m.LastLoginAt,
			}),
		},
		clause.Returning{Columns: []clause.Column{{Name: "id"}}},
	).Create(&m).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "写入三方身份失败", err)
	}
	if m.ID == 0 {
		// 理论上不会发生：ON CONFLICT DO UPDATE 一定会命中一行。
		// 真发生了说明 RETURNING 没有生效，属于需修代码的问题，不能静默继续。
		return nil, errs.New(errs.CodeInternal, "身份 Upsert 未返回主键")
	}
	return identityToDomain(&m), nil
}

// FindByOpenID 按唯一键查找身份。
//
// 约束 C1：必须带 app_id 条件。这里既显式给出 app_id，隔离回调也会再补一次；
// 双重保证不是冗余——显式条件让 SQL 可读，回调保证"漏写也安全"。
func (r *IdentityRepository) FindByOpenID(ctx context.Context, q identity.FindQuery) (*identity.Identity, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	ctx = appctx.WithAppScope(ctx, q.AppID)

	var m identityModel
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND platform = ? AND provider_app_id = ? AND open_id = ?",
			q.AppID, q.Platform, q.ProviderAppID, q.OpenID).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, identity.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询三方身份失败", err)
	}
	return identityToDomain(&m), nil
}

// FindByID 按主键查找身份。
func (r *IdentityRepository) FindByID(ctx context.Context, appID, id int64) (*identity.Identity, error) {
	if appID <= 0 || id <= 0 {
		return nil, errs.New(errs.CodeInternal, "身份查询参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var m identityModel
	err := r.db.WithContext(ctx).Where("app_id = ? AND id = ?", appID, id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, identity.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询三方身份失败", err)
	}
	return identityToDomain(&m), nil
}

func identityToDomain(m *identityModel) *identity.Identity {
	return &identity.Identity{
		ID:              m.ID,
		AppID:           m.AppID,
		Platform:        m.Platform,
		ProviderAppID:   m.ProviderAppID,
		OpenID:          m.OpenID,
		UnionID:         m.UnionID,
		IdentityKey:     m.IdentityKey,
		ProfileSnapshot: m.ProfileSnapshot,
		ProfileSyncedAt: m.ProfileSyncedAt,
		FirstSeenAt:     m.FirstSeenAt,
		LastLoginAt:     m.LastLoginAt,
	}
}
