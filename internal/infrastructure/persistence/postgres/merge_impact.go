package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// MergeImpactor 计算合并影响面（管理端 D 组）。
type MergeImpactor struct {
	db *gorm.DB
}

// NewMergeImpactor 构造影响面计算器。
func NewMergeImpactor(db *gorm.DB) *MergeImpactor {
	return &MergeImpactor{db: db}
}

var _ merge.Impactor = (*MergeImpactor)(nil)

// Estimate 统计 source 账号下将被改挂的绑定与将被撤销的令牌。
//
// 用 COUNT 而不是把行全部读出来：影响面只用于二次确认弹窗，
// 一个账号可能有上千条令牌记录，全量读毫无意义。
func (m *MergeImpactor) Estimate(ctx context.Context, appID int64, sourceUserID string) (*merge.Impact, error) {
	ctx = appctx.WithAppScope(ctx, appID)

	out := &merge.Impact{}

	if err := m.db.WithContext(ctx).Model(&bindingModel{}).
		Where("app_id = ? AND external_user_id = ? AND status = ?", appID, sourceUserID, "active").
		Count(&out.Bindings).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "统计待改挂绑定失败", err)
	}

	if err := m.db.WithContext(ctx).Model(&refreshTokenModel{}).
		Where("app_id = ? AND external_user_id = ? AND revoked = ?", appID, sourceUserID, false).
		Count(&out.Tokens).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "统计待撤销令牌失败", err)
	}

	// 平台摘要，让运维在确认前能看出"要动的是哪几个渠道"。
	//
	// 只取 platform 不取 scene：oauth_identities 没有 scene 列——承载场景
	// 属于渠道配置维度（app_provider_configs），一个 identity 可能被多个
	// 场景共用，把它列在这里会给出错误的"一对一"印象。
	type row struct {
		Platform string
	}
	var rows []row
	if err := m.db.WithContext(ctx).Table("oauth_bindings AS b").
		Select("i.platform").
		Joins("JOIN oauth_identities AS i ON i.id = b.identity_id").
		Where("b.app_id = ? AND b.external_user_id = ? AND b.status = ?", appID, sourceUserID, "active").
		Scan(&rows).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "统计渠道分布失败", err)
	}
	for _, r := range rows {
		out.Identities = append(out.Identities, r.Platform)
	}
	if out.Identities == nil {
		out.Identities = []string{}
	}
	return out, nil
}
