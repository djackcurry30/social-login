// Package identity 是三方身份的领域模型（Identity 聚合）。
//
// 关键约束（架构 §1.4 C1 / C3）：
//   - identity 按【业务应用】隔离：所有查询必须带 app_id。这不是靠调用方自觉，
//     而是在持久层用 GORM 全局 Callback 强制注入，缺失即 panic（见 infrastructure/persistence）。
//   - identity 不含 scene 字段（与 DDL 一致）：身份由
//     (app_id, platform, provider_app_id, open_id) 唯一确定，而 provider_app_id
//     本身就属于某一份渠道配置，scene 可经配置反查。这是刻意的——同一个人用
//     微信 App 与小程序登录会得到两条身份记录（C3 下 openid 不同），正是这一
//     事实要求业务侧支持合并（需求 R1）。
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// ErrNotFound 表示身份不存在。仓储实现返回它，调用方用 errors.Is 判定。
var ErrNotFound = errors.New("identity: not found")

// Identity 是一条三方身份记录。
type Identity struct {
	ID            int64
	AppID         int64
	Platform      string
	ProviderAppID string
	OpenID        string
	// UnionID 是保留字段。约束 C3 下恒为空（unionid 不可用），
	// 但表结构预留，将来开通开放平台账号绑定后无需改表。
	UnionID string
	// IdentityKey 是归一化归并键。C3 下 = open_id。
	IdentityKey     string
	ProfileSnapshot map[string]any
	ProfileSyncedAt *time.Time
	FirstSeenAt     time.Time
	LastLoginAt     *time.Time
}

// FindQuery 是身份精确查找条件。
// 四个字段全部必填——漏掉任何一个都会命中错误的身份。
type FindQuery struct {
	AppID         int64
	Platform      string
	ProviderAppID string
	OpenID        string
}

// UpsertInput 是"授权成功后写入身份"的入参。
type UpsertInput struct {
	AppID         int64
	Platform      string
	ProviderAppID string
	OpenID        string
	UnionID       string
	IdentityKey   string
	Profile       map[string]any
	At            time.Time
}

// Repository 是身份的持久化端口。
type Repository interface {
	// Upsert 按唯一键插入或更新身份，并返回最终记录。
	// 授权成功时调用：首次登录创建，后续登录刷新资料与登录时间。
	Upsert(ctx context.Context, in UpsertInput) (*Identity, error)

	// FindByOpenID 按唯一键查找。未找到返回 ErrNotFound。
	FindByOpenID(ctx context.Context, q FindQuery) (*Identity, error)

	// FindByID 按主键查找。由于身份按应用隔离，app_id 是必需的校验条件。
	FindByID(ctx context.Context, appID, id int64) (*Identity, error)
}

// Validate 校验入参完整性，避免把空键写进唯一索引。
func (q FindQuery) Validate() error {
	if q.AppID <= 0 {
		return errs.New(errs.CodeInternal, "身份查询缺少 app_id（会破坏应用隔离）")
	}
	if q.Platform == "" || q.ProviderAppID == "" || q.OpenID == "" {
		return errs.New(errs.CodeInternal, "身份查询条件不完整")
	}
	return nil
}
