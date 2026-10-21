package admin

import (
	"context"
	"errors"
	"time"
)

// Grant 是一条管理员授权（admin_grants 表）。
//
// 为什么需要它：`admin_users.role` 只能表达"一个人一个角色"，
// 但现实里常见"某人平时是 viewer，这个月临时加 operator 处理一批客诉"，
// 以及"只允许他管这个应用"。grants 用 subject + role + scope_app_id +
// expires_at 四元组表达这三种需求。
//
// 与 admin_users.role 的关系：**并存，取并集**。role 是"基础角色"，
// grants 是"附加授权"。这样 K 组上线不需要一次性迁移所有现有管理员，
// 也不会因为漏迁而让人突然失去权限。
type Grant struct {
	ID int64
	// SubjectID 形如 "admin:1"（本地账号）或 IdP 的 sub（将来切 SSO）。
	// 与 admin_audit_logs.subject_id 同一套命名，便于把"谁被授权"与
	// "谁做了什么"直接对上。
	SubjectID string
	Role      Role
	// ScopeAppID 非空表示该授权只对这一个应用生效。
	//
	// ⚠️ 当前鉴权层【忽略】这个字段（见 User.Can 的注释）：
	// 现有 52 个管理端接口里没有"按应用"的权限边界，先按全局处理。
	// 真正的按应用隔离需要中间件拿到目标 app_id（路径参数或请求体），
	// 那是一次跨所有端点的改动，单独排期。
	ScopeAppID *int64
	GrantedBy  string
	GrantedAt  time.Time
	// ExpiresAt 为空表示长期有效（临时授权填未来时间）。
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// Effective 判断授权在 now 是否生效。
func (g *Grant) Effective(now time.Time) bool {
	if g == nil || g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return false
	}
	return true
}

// GrantFilter 是授权列表的查询条件。
type GrantFilter struct {
	SubjectID string
	// IncludeRevoked 为 true 时连已撤销的一起返回（排查"他为什么没权限"）。
	IncludeRevoked bool
	Page           int
	PageSize       int
}

// GrantRepository 是 admin_grants 的持久化端口。
type GrantRepository interface {
	// List 查询授权。
	List(ctx context.Context, f GrantFilter) ([]Grant, int64, error)
	// Insert 授予角色。已存在同 (subject, role, scope) 的活跃授权时返回该条（幂等）。
	Insert(ctx context.Context, g *Grant) (*Grant, error)
	// Revoke 撤销授权（置 revoked_at，保留历史）。
	Revoke(ctx context.Context, id int64, at time.Time) (*Grant, error)
	// FindByID 按主键查。
	FindByID(ctx context.Context, id int64) (*Grant, error)
	// ListEffectiveBySubject 返回某主体当前生效的授权（鉴权时加载）。
	ListEffectiveBySubject(ctx context.Context, subjectID string, now time.Time) ([]Grant, error)
}

// ErrGrantNotFound 表示授权不存在。
var ErrGrantNotFound = errors.New("admin: grant not found")

// SubjectOf 把管理员账号转成 subject_id。
func SubjectOf(userID int64) string {
	return "admin:" + itoa(userID)
}

// itoa 避免为一行格式化引入 strconv（保持本包依赖最小）。
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
