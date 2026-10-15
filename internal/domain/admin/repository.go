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
}

// SessionRepository 是管理员会话的持久化端口。
type SessionRepository interface {
	// Insert 写入会话。
	Insert(ctx context.Context, s *Session) error
	// FindByTokenHash 按 token SHA-256 查找未撤销的会话。
	FindByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	// Revoke 主动撤销会话。
	Revoke(ctx context.Context, id int64) error
}

// AuditWriter 是 admin_audit_logs 的写入端口。
//
// 业务审计（auth_audit_logs）已有 audit.Writer；这里单独一个端口，
// 是为了【在依赖图上保持 admin 独立】——管理端将来拆服务时，
// 仓储层直接切到独立 DB，不需要业务审计端口参与。
type AuditWriter interface {
	Write(ctx context.Context, e *AuditEvent) error
}
