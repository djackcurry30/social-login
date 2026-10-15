// Package admin 是管理端（B 端）的领域模型。
//
// 设计依据：架构 §15.3 规定管理员身份复用用户中心账号，但当前阶段
// 用户中心尚未落地（参 docs/admin-quickstart.md），本包实现"本地账号密码起步"的
// 临时形态：身份在 admin_users 本地维护，subject_id 字段保留为兼容位
//（先填 admin_users.id 的字符串化，将来切 OIDC SSO 时只换中间件）。
//
// 演进路径：
//   - 接用户中心 / OIDC SSO：password_hash 列废弃不写，subject_id 填 IdP 标识
//   - 表结构、grants、audit_logs 全部不动
//   - K 组（管理员授权）落地时：admin_users.role 列废弃，改由 admin_grants
//     表达"多角色、按 app_id 限定范围、临时授权"
package admin

import (
	"errors"
	"time"
)

// Role 是管理员的内置角色（K 组未上线前 hardcode 4 个）。
//
// 命名 §15.3 表格：viewer / operator / config_admin / super_admin。
//
// ⚠️ 这是【内置枚举】，不是字符串白名单。修改这里要同步修改：
//   - migrations/00002_admin.sql 的 admin_users_role_check 约束
//   - application/adminapp 等用例中的鉴权判断
//   - 文档 docs/admin-quickstart.md
type Role string

const (
	RoleViewer      Role = "viewer"      // *:read
	RoleOperator    Role = "operator"    // viewer + binding:* token:revoke merge:retry
	RoleConfigAdmin Role = "config_admin" // viewer + app:* config:* key:* event:*
	RoleSuperAdmin  Role = "super_admin" // 全部 + admin:grant
)

// AllRoles 列出全部内置角色（校验与测试用）。
func AllRoles() []Role {
	return []Role{RoleViewer, RoleOperator, RoleConfigAdmin, RoleSuperAdmin}
}

// IsValid 判断 role 是否为内置合法值。
func (r Role) IsValid() bool {
	for _, v := range AllRoles() {
		if v == r {
			return true
		}
	}
	return false
}

// Permissions 是该角色拥有的全部权限。
//
// 权限采用 `resource:action` 粒度（§15.3），例如 `app:read` / `config:write`。
// 这里用闭包表：调用方查 Has(perm) 时按角色返回。
//
// 写成表而不是 if-else 链，是因为 §15.4 接下来会加 4 期共 52 个接口，
// 链式会让增删改的认知成本快速上升。
var Permissions = map[Role]map[string]struct{}{
	RoleViewer: {
		"app:read": {}, "config:read": {}, "token:read": {},
		"identity:read": {}, "binding:read": {}, "event:read": {},
		"audit:read": {}, "key:read": {},
	},
	RoleOperator: {},
	RoleConfigAdmin: {},
	RoleSuperAdmin:  {},
}

// has 内部辅助。
func has(set map[string]struct{}, perm string) bool {
	_, ok := set[perm]
	return ok
}

// Has 判断该角色是否拥有指定权限。
//
// SuperAdmin 走特例（admin:grant 不属于其他角色），其它角色只查自己的闭包表。
// Operator 的权限是 ConfigAdmin 的子集（不含 app:write / config:write / key:write）。
// 这里用「显式列举」而不是「config_admin 是 operator 的超集」，是因为：
//   - 显式列举每加一个角色都要明确写出它有什么、没什么，避免「继承 → 漏看」
//   - 临时变更某角色权限时，diff 只在它自己的闭包里
func (r Role) Has(perm string) bool {
	switch r {
	case RoleSuperAdmin:
		return true
	}
	return has(Permissions[r], perm)
}

// IsHighRisk 判断 action 是否属于高危操作（§15.5 要求 reason 必填）。
//
// 与 HTTP 路径无关——只要某个 action 落在这张表里，写审计时都强制校验 reason。
// 表里只列本期的：A 组（app:write / app:write_secret）和 B 组（config:write / config:verify）。
// 其它组（C/D/E/F/G/J）的高危操作随它们上线时再补。
var HighRiskActions = map[string]struct{}{
	"app.create":        {},
	"app.update":        {},
	"app.rotate_secret": {},
	"config.create":     {},
	"config.update":     {},
	"config.rotate":     {},
	"config.finalize":   {},
	"config.verify":     {},
	"config.delete":     {},
	"config.enable":     {},
	"config.disable":    {},
}

// IsHighRisk 报告 action 是否高危。
func IsHighRisk(action string) bool {
	_, ok := HighRiskActions[action]
	return ok
}

// ErrNotFound 表示管理员账号不存在。
var ErrNotFound = errors.New("admin: not found")

// ErrInvalidCredentials 表示登录失败（用户名不存在、密码错、账号停用统一此错）。
//
// 统一错误避免通过错误信息枚举 username（架构 §10.1 用户枚举的对偶问题）。
var ErrInvalidCredentials = errors.New("admin: invalid credentials")

// User 是管理员账号。
type User struct {
	ID           int64
	Username     string
	PasswordHash string // bcrypt(cost=12)——禁止写入日志与错误 details
	DisplayName  string
	Role         Role
	Status       int16 // 1=enabled, 0=disabled
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Enabled 判断账号是否可用。
func (u *User) Enabled() bool { return u.Status == 1 }

// Session 是管理员会话。
type Session struct {
	ID        int64
	UserID    int64
	TokenHash string // SHA-256 hex(64)
	ClientIP  string
	UserAgent string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// Expired 判断会话是否已过期。
func (s *Session) Expired(now time.Time) bool { return !s.ExpiresAt.After(now) }

// Revoked 判断会话是否被主动撤销。
func (s *Session) Revoked() bool { return s.RevokedAt != nil }

// Principal 是当前请求已认证的管理员上下文。
//
// 把 *User + *Session 合并而不是分两个 ctx 键，是因为
// admin 中间件解析一次就拿全，handler 写起来不啰嗦：
//
//	admin.Subject(c).User.Username
//	admin.Subject(c).Session.ExpiresAt
type Principal struct {
	User    *User
	Session *Session
}

// AuditEvent 是写管理审计的事件。
//
// 与 auth_audit_logs 的区别：业务审计按 app_id 隔离、面向"用户行为"；
// 管理审计按 subject_id 索引、面向"管理员行为"，保留期更长（3 年）。
type AuditEvent struct {
	SubjectID   string
	Action      string
	TargetType  string
	TargetID    string
	AppID       *int64
	Reason      string
	BeforeState map[string]any
	AfterState  map[string]any
	ClientIP    string
	TraceID     string
	Result      string // "success" | "denied" | "error"
	ErrorCode   string
}
