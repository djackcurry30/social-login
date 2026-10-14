// Package binding 是绑定关系的领域模型。
//
// 决策 D4：Binding 独立成聚合，而不是 Identity 上的一个 user_id 字段。原因是
// "这个微信已经绑了另一个账号"是这类服务最高频的线上问题；把它建模成独立对象，
// 才能用【部分唯一索引】在数据库层保证"一个身份同期只绑一个账号"，同时保留
// 解绑历史用于审计与合并回滚。
package binding

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound 表示没有找到活跃绑定。
var ErrNotFound = errors.New("binding: not found")

// 绑定状态。
const (
	StatusActive  = "active"
	StatusUnbound = "unbound"
)

// 绑定来源，用于审计与冲突排查。
const (
	// SourceLogin 是登录时自动建立。
	SourceLogin = "login"
	// SourceExplicit 是用户在"账号设置"里主动绑定。
	SourceExplicit = "explicit"
	// SourceMerge 是账号合并时改挂。
	SourceMerge = "merge"
	// SourceAdmin 是管理员干预。
	SourceAdmin = "admin"
)

// Binding 是一条绑定关系。
//
// external_user_id 是【外部引用】（约束 C4）：本服务不持有账号主数据，
// 该字段指向用户中心的账号，不加外键约束。
type Binding struct {
	ID             int64
	AppID          int64
	ExternalUserID string
	IdentityID     int64
	Status         string
	IsPrimary      bool
	BindSource     string
	BoundAt        time.Time
	UnboundAt      *time.Time
}

// ActivateInput 是建立绑定的入参。
type ActivateInput struct {
	AppID          int64
	ExternalUserID string
	IdentityID     int64
	IsPrimary      bool
	BindSource     string
	At             time.Time
}

// Repository 是绑定关系的持久化端口。
type Repository interface {
	// FindActiveByIdentity 查询某身份的活跃绑定。未找到返回 ErrNotFound。
	FindActiveByIdentity(ctx context.Context, appID, identityID int64) (*Binding, error)

	// ListActiveByExternalUser 列出某业务账号的全部活跃绑定（引导绑定页的数据源）。
	ListActiveByExternalUser(ctx context.Context, appID int64, externalUserID string) ([]Binding, error)

	// Activate 建立绑定。
	//
	// 返回 alreadyExists=true 表示该身份已被占用（命中了部分唯一索引
	// uk_bindings_active）。这是【设计预期内的正常路径】，不是错误：
	// 并发绑定靠数据库唯一索引兜底，比加分布式锁更轻也更可靠（架构 §5.2）。
	// 调用方据此走冲突策略。
	Activate(ctx context.Context, in ActivateInput) (b *Binding, alreadyExists bool, err error)

	// Unbind 解绑（置 status=unbound，保留历史行用于审计）。
	Unbind(ctx context.Context, appID, identityID int64, at time.Time) error

	// CountActive 统计某业务账号的活跃绑定数，用于判断"这是最后一个登录方式"。
	CountActive(ctx context.Context, appID int64, externalUserID string) (int, error)
}
