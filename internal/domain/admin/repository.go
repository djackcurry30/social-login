// Package admin 是管理端的领域端口。
//
// 端口（Port）由应用层定义，基础设施实现。这是六边形架构的标准做法。
package admin

import "context"

// UserRepository 是管理员账号的持久化端口。
type UserRepository interface {
	// FindByUsername 按用户名查找。未找到返回 ErrNotFound。
	FindByUsername(ctx context.Context, username string) (*User, error)
	// FindByID 按主键查找。未找到返回 ErrNotFound。
	FindByID(ctx context.Context, id int64) (*User, error)
	// Insert 插入新账号，返回带主键的实体。
	Insert(ctx context.Context, u *User) (*User, error)
	// UpdateLastLoginAt 把 last_login_at 置为 now。
	UpdateLastLoginAt(ctx context.Context, id int64) error
	// UpdatePassword 改密码（admin 改自己密码时用）。
	UpdatePassword(ctx context.Context, id int64, passwordHash string) error

	// List 列出管理员账号（按 id 升序），供管理端"管理员账号管理"使用。
	//
	// 返回的实体【不带 PasswordHash】：列表页会被导出、截图、贴进工单，
	// 让哈希离开存储层没有任何收益。
	List(ctx context.Context, limit int) ([]*User, error)

	// UpdateProfile 更新显示名 / 角色 / 启用状态。
	//
	// 单独一个方法而不是 Update(u *User)：那会把 password_hash 也带进
	// UPDATE 子句，一次手误就能把别人的密码改成空串。改密走 UpdatePassword。
	UpdateProfile(ctx context.Context, id int64, in ProfileUpdate) error

	// CountEnabledSuperAdmins 统计"启用中的 super_admin"数量。
	//
	// 存在的唯一目的是防止把最后一个超级管理员降级或停用——那会让整个
	// 管理端再也无人能改配置，只能靠改库恢复。
	CountEnabledSuperAdmins(ctx context.Context) (int64, error)
}

// ProfileUpdate 是一次资料变更。
//
// 三个字段都是指针：nil 表示"这次不改这一项"。用零值表达"不改"是行不通的
// （Status=0 恰好是"停用"，Role="" 恰好是非法值），指针是这里唯一干净的写法。
type ProfileUpdate struct {
	DisplayName *string
	Role        *Role
	Status      *int16
}

// SessionRepository 是管理员会话的持久化端口。
type SessionRepository interface {
	// Insert 写入会话。
	Insert(ctx context.Context, s *Session) error
	// FindByTokenHash 按 token SHA-256 查找未撤销的会话。
	FindByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	// Revoke 主动撤销会话。
	Revoke(ctx context.Context, id int64) error
	// RevokeAllByUser 撤销某管理员的全部未撤销会话。
	//
	// 重置密码与停用账号必须调用它：只改库不撤会话，等于对方手里的 token
	// 还能继续用 8 小时——"改了密码"给人一种已经止损的错觉，实际没有。
	RevokeAllByUser(ctx context.Context, userID int64) error
}

// AuditWriter 是 admin_audit_logs 的写入端口。
//
// 业务审计（auth_audit_logs）已有 audit.Writer；这里单独一个端口，
// 是为了【在依赖图上保持 admin 独立】——管理端将来拆服务时，
// 仓储层直接切到独立 DB，不需要业务审计端口参与。
type AuditWriter interface {
	Write(ctx context.Context, e *AuditEvent) error
}
