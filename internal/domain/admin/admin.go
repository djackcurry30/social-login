// Package admin 是管理端（B 端）的领域模型。
//
// 设计依据：架构 §15.3 规定管理员身份复用用户中心账号，但当前阶段
// 用户中心尚未落地（参 docs/admin-quickstart.md），本包实现"本地账号密码起步"的
// 临时形态：身份在 admin_users 本地维护，subject_id 字段保留为兼容位
// （先填 admin_users.id 的字符串化，将来切 OIDC SSO 时只换中间件）。
//
// 演进路径：
//   - 接用户中心 / OIDC SSO：password_hash 列废弃不写，subject_id 填 IdP 标识
//   - 表结构、grants、audit_logs 全部不动
//   - K 组（管理员授权）落地时：admin_users.role 列废弃，改由 admin_grants
//     表达"多角色、按 app_id 限定范围、临时授权"
package admin

import (
	"errors"
	"sort"
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
	RoleViewer      Role = "viewer"       // *:read
	RoleOperator    Role = "operator"     // viewer + binding:* token:revoke merge:retry
	RoleConfigAdmin Role = "config_admin" // viewer + app:* config:* key:* event:*
	RoleSuperAdmin  Role = "super_admin"  // 全部 + admin:grant
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
		"audit:read": {}, "key:read": {}, "merge:read": {},
	},
	// operator = viewer + 会话/绑定运维 + 合并重试。
	//
	// ⚠️ 这里必须把 viewer 的读权限【显式重列】一遍：Has() 不做角色继承
	// （见下方注释的取舍），早期版本把 operator 留空，结果 operator 登录后
	// 连 GET /admin/v1/apps 都是 403——一个"看不到任何东西"的角色。
	RoleOperator: {
		"app:read": {}, "config:read": {}, "token:read": {},
		"identity:read": {}, "binding:read": {}, "event:read": {},
		"audit:read": {}, "key:read": {}, "merge:read": {},
		"binding:write": {}, "binding:transfer": {}, "token:revoke": {}, "merge:retry": {},
		// identity:write 对应 J 组的"人工撤销凭证"（§15.4）。
		// 只给 operator：撤销一条 claim 会改变"下一次登录会被归并到哪个账号"，
		// 属于账号运营动作；config_admin 管的是接入配置，不该有这项。
		"identity:write": {},
	},
	// config_admin = viewer + 应用/渠道/密钥/事件写权限。
	RoleConfigAdmin: {
		"app:read": {}, "config:read": {}, "token:read": {},
		"identity:read": {}, "binding:read": {}, "event:read": {},
		"audit:read": {}, "key:read": {}, "merge:read": {},
		"app:write": {}, "config:write": {}, "key:write": {}, "event:write": {},
	},
	RoleSuperAdmin: {},
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
	// Grants 是该管理员当前生效的附加授权（K 组）。
	//
	// 由仓储在 FindByID / FindByUsername 时一并加载，而不是在鉴权中间件里
	// 再查一次——中间件在每一个管理端请求的热路径上。
	Grants []Grant
}

// Permissions 返回该管理员的全部有效权限（基础角色 ∪ 生效 grants）。
//
// super_admin 用通配 "\u002a" 表达"全部权限"，而不是把所有权限字符串列一遍：
// 权限表会随接口增加而增长，逐一枚举意味着每次加权限都要记得改这里。
// 前端 consumes 这个返回值来决定按钮是否可用（见 web/src/lib/auth.ts）。
func (u *User) Permissions() []string {
	if u == nil {
		return nil
	}
	if u.Role == RoleSuperAdmin {
		return []string{"*"}
	}
	set := make(map[string]struct{}, 16)
	for p := range Permissions[u.Role] {
		set[p] = struct{}{}
	}
	now := time.Now().UTC()
	for i := range u.Grants {
		g := &u.Grants[i]
		if !g.Effective(now) {
			continue
		}
		if g.Role == RoleSuperAdmin {
			return []string{"*"}
		}
		for p := range Permissions[g.Role] {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out) // 稳定输出：便于前端缓存与测试对比
	return out
}

// ScopeFor 返回某权限可作用于哪些应用。
//
// 返回值语义：
//
//	restricted=false        不受限（全局），appIDs 无意义
//	restricted=true, ids=[] 有该权限但只限若干应用；空列表表示"一个都不许"
//
// 判定看【权限的来源】而不是看"有没有 grant"：
//
//	基础角色 admin_users.role 是全局的      → 只要它有该权限，就不受限
//	附加授权 grant.scope_app_id = NULL      → 全局
//	附加授权 grant.scope_app_id = 7         → 只限 7
//
// 这样同一个人的不同权限可以有不同的范围（例如 base role=viewer 看全部，
// 临时授予的 operator 只限应用 7），不需要在表上再加一个"人级别"的范围字段。
// 只有一条全局来源就放开——收紧的方向必须是"少给权限"，而不是把已有的
// 全局角色突然降成单应用，否则上线当天会有一批人看不见数据。
func (u *User) ScopeFor(perm string) (appIDs []int64, restricted bool) {
	if u == nil {
		return nil, false
	}
	if u.Role == RoleSuperAdmin || u.Role.Has(perm) {
		// 基础角色是全局的：不能因为"他还被授了一个单应用角色"就把基础
		// 角色的可见范围缩小。
		return nil, false
	}
	now := time.Now().UTC()
	scoped := make([]int64, 0, len(u.Grants))
	for i := range u.Grants {
		g := &u.Grants[i]
		if !g.Effective(now) || !g.Role.Has(perm) {
			continue
		}
		if g.Role == RoleSuperAdmin || g.ScopeAppID == nil {
			return nil, false
		}
		scoped = append(scoped, *g.ScopeAppID)
	}
	return scoped, true
}

// CanInApp 判断管理员能否在指定应用上使用某权限。
func (u *User) CanInApp(perm string, appID int64) bool {
	if !u.Can(perm) {
		return false
	}
	ids, restricted := u.ScopeFor(perm)
	if !restricted {
		return true
	}
	for _, id := range ids {
		if id == appID {
			return true
		}
	}
	return false
}

// UserOf 从 Principal 取 User，nil 安全。
func UserOf(p *Principal) *User {
	if p == nil {
		return nil
	}
	return p.User
}

// AllowsApp 报告 user 能否在 appID 上使用 perm。
//
// u 为 nil 表示"没有主体上下文"（内部调用、补偿任务、单测），此时放行——
// 这类调用不经过 HTTP 鉴权层，本来就不该受管理员的可见范围约束。
// HTTP 路径上主体一定非 nil（Authenticate 中间件保证）。
func AllowsApp(u *User, perm string, appID int64) bool {
	if u == nil {
		return true
	}
	return u.CanInApp(perm, appID)
}

// RestrictApp 把请求里的 appID 收敛到管理员的权限范围内。
//
// 三个返回值组合的含义：
//
//	(appID, true)   可以用，appID 是最终生效的应用（可能由范围补全）
//	(0,     false)  越界或无法确定，调用方应返回 404
//
// 为什么"没传 app_id 但有唯一范围"时自动补全：受限管理员只有一个应用，
// 让他每次都手动带 app_id 只是制造 403。反过来，范围里有多于一个应用
// 却没指明时拒绝——猜错应用会改错数据，而且事后很难发现。
func RestrictApp(u *User, perm string, requested int64) (int64, bool) {
	if u == nil {
		return requested, true
	}
	ids, restricted := u.ScopeFor(perm)
	if !restricted {
		return requested, true
	}
	if requested != 0 {
		for _, id := range ids {
			if id == requested {
				return requested, true
			}
		}
		return 0, false
	}
	if len(ids) == 1 {
		return ids[0], true
	}
	return 0, false
}

// Can 判断管理员是否拥有某项权限。
//
// 判定是【基础角色 ∪ 附加授权】：这样 K 组上线不需要一次性迁移所有
// 现有管理员，也不会因为漏迁而让人突然失去权限。
//
// ⚠️ 它只回答"有没有这个权限"，不回答"能用在哪个应用上"——
// 后者看 ScopeFor / CanInApp。中间件 adminmw.Require 已经把两者串起来，
// handler 里不要只调 Can 就认为安全。
func (u *User) Can(perm string) bool {
	if u == nil {
		return false
	}
	if u.Role.Has(perm) {
		return true
	}
	now := time.Now().UTC()
	for i := range u.Grants {
		g := &u.Grants[i]
		if g.Effective(now) && g.Role.Has(perm) {
			return true
		}
	}
	return false
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
