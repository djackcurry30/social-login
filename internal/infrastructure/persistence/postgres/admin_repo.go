// Package postgres 的 admin 仓储。
//
// 三个仓储（User / Session / AuditWriter）合并在同一个文件，因为：
//   - 都属于 admin 域，规模不大
//   - 共享一些 helper（如 INET 与 string 互转、JSONMap 输出）
//   - 拆 3 个文件反而增加阅读跳转成本
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AdminUserRepository 是 admin.adminUserRepository 的 PostgreSQL 实现。
type AdminUserRepository struct {
	db *gorm.DB
}

// NewAdminUserRepository 构造仓储。
func NewAdminUserRepository(db *gorm.DB) *AdminUserRepository {
	return &AdminUserRepository{db: db}
}

var _ admin.UserRepository = (*AdminUserRepository)(nil)

// FindByUsername 按用户名查找。
func (r *AdminUserRepository) FindByUsername(ctx context.Context, username string) (*admin.User, error) {
	if username == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "username 不能为空")
	}
	var m adminUserModel
	err := r.db.WithContext(ctx).Where("username = ?", username).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, admin.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询管理员账号失败", err)
	}
	u := adminUserToDomain(&m)
	if err := attachGrants(ctx, r.db, time.Now().UTC(), u); err != nil {
		return nil, err
	}
	return u, nil
}

// FindByID 按主键查找。
func (r *AdminUserRepository) FindByID(ctx context.Context, id int64) (*admin.User, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "id 不合法")
	}
	var m adminUserModel
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, admin.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询管理员账号失败", err)
	}
	u := adminUserToDomain(&m)
	if err := attachGrants(ctx, r.db, time.Now().UTC(), u); err != nil {
		return nil, err
	}
	return u, nil
}

// Insert 插入新账号。
func (r *AdminUserRepository) Insert(ctx context.Context, u *admin.User) (*admin.User, error) {
	if u == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "admin user 为空")
	}
	if u.Username == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "username 不能为空")
	}
	if u.PasswordHash == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "password_hash 不能为空")
	}
	if u.Role == "" {
		u.Role = admin.RoleViewer
	}
	if !u.Role.IsValid() {
		return nil, errs.Newf(errs.CodeInvalidRequest, "非法的 role: %s", u.Role)
	}
	now := time.Now().UTC()
	m := adminUserModel{
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		DisplayName:  u.DisplayName,
		Role:         string(u.Role),
		Status:       1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		// 唯一键冲突 (username) 翻译为业务错误
		if isUniqueViolation(err) {
			return nil, errs.Newf(errs.CodeAdminConflict, "username 已存在: %s", u.Username).
				WithDetail("field", "username")
		}
		return nil, errs.Wrap(errs.CodeInternal, "插入管理员账号失败", err)
	}
	return adminUserToDomain(&m), nil
}

// UpdateLastLoginAt 把 last_login_at 置为 now。
func (r *AdminUserRepository) UpdateLastLoginAt(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&adminUserModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"last_login_at": now,
			"updated_at":    now,
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "更新 last_login_at 失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return admin.ErrNotFound
	}
	return nil
}

// UpdatePassword 改密码。
func (r *AdminUserRepository) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	if passwordHash == "" {
		return errs.New(errs.CodeInvalidRequest, "password_hash 不能为空")
	}
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&adminUserModel{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"password_hash": passwordHash,
			"updated_at":    now,
		})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "更新密码失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return admin.ErrNotFound
	}
	return nil
}

func adminUserToDomain(m *adminUserModel) *admin.User {
	role := admin.Role(m.Role)
	return &admin.User{
		ID:           m.ID,
		Username:     m.Username,
		PasswordHash: m.PasswordHash,
		DisplayName:  m.DisplayName,
		Role:         role,
		Status:       m.Status,
		LastLoginAt:  m.LastLoginAt,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

// --- 会话仓储 ---

// AdminSessionRepository 是 admin.SessionRepository 的 PostgreSQL 实现。
type AdminSessionRepository struct {
	db *gorm.DB
}

// NewAdminSessionRepository 构造仓储。
func NewAdminSessionRepository(db *gorm.DB) *AdminSessionRepository {
	return &AdminSessionRepository{db: db}
}

var _ admin.SessionRepository = (*AdminSessionRepository)(nil)

// Insert 写入会话。
func (r *AdminSessionRepository) Insert(ctx context.Context, s *admin.Session) error {
	if s == nil {
		return errs.New(errs.CodeInvalidRequest, "session 为空")
	}
	if s.UserID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "session.user_id 不合法")
	}
	if s.TokenHash == "" {
		return errs.New(errs.CodeInvalidRequest, "session.token_hash 不能为空")
	}
	if s.ExpiresAt.IsZero() {
		return errs.New(errs.CodeInvalidRequest, "session.expires_at 不能为零值")
	}
	m := adminSessionModel{
		UserID:    s.UserID,
		TokenHash: s.TokenHash,
		UserAgent: s.UserAgent,
		ExpiresAt: s.ExpiresAt.UTC(),
		CreatedAt: time.Now().UTC(),
	}
	if s.ClientIP != "" {
		ip := s.ClientIP
		m.ClientIP = &ip
	}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		if isUniqueViolation(err) {
			return errs.New(errs.CodeAdminConflict, "session token 冲突（概率极低）")
		}
		return errs.Wrap(errs.CodeInternal, "插入管理员会话失败", err)
	}
	s.ID = m.ID
	s.CreatedAt = m.CreatedAt
	return nil
}

// FindByTokenHash 按 token SHA-256 查找未撤销的会话。
//
// 不主动过滤 expires_at 与 revoked_at：上层用 Session.Expired() / Revoked() 判断，
// 仓储只负责"是否存在"。这样调用方可以基于同一份实体做多种判断
// （如审计时想知道"会话被撤销的时间点"）。
func (r *AdminSessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*admin.Session, error) {
	if tokenHash == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "token_hash 不能为空")
	}
	var m adminSessionModel
	err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, admin.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询管理员会话失败", err)
	}
	return adminSessionToDomain(&m), nil
}

// Revoke 主动撤销会话（写 revoked_at = now）。
func (r *AdminSessionRepository) Revoke(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&adminSessionModel{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", now)
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "撤销管理员会话失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return admin.ErrNotFound
	}
	return nil
}

func adminSessionToDomain(m *adminSessionModel) *admin.Session {
	s := &admin.Session{
		ID:        m.ID,
		UserID:    m.UserID,
		TokenHash: m.TokenHash,
		UserAgent: m.UserAgent,
		ExpiresAt: m.ExpiresAt,
		RevokedAt: m.RevokedAt,
		CreatedAt: m.CreatedAt,
	}
	if m.ClientIP != nil {
		s.ClientIP = *m.ClientIP
	}
	return s
}

// --- 审计写入 ---

// AdminAuditWriter 是 admin.AuditWriter 的 PostgreSQL 实现。
type AdminAuditWriter struct {
	db *gorm.DB
}

// NewAdminAuditWriter 构造审计写入。
func NewAdminAuditWriter(db *gorm.DB) *AdminAuditWriter {
	return &AdminAuditWriter{db: db}
}

var _ admin.AuditWriter = (*AdminAuditWriter)(nil)

// Write 写入一条审计事件。
//
// 失败时只返回错误，由调用方决定是否要重试或降级（admin 中间件写审计失败
// 不应阻塞请求，但会记一条 ERROR 日志，便于发现"审计空洞"）。
func (w *AdminAuditWriter) Write(ctx context.Context, e *admin.AuditEvent) error {
	if e == nil {
		return errs.New(errs.CodeInvalidRequest, "audit event 为空")
	}
	if e.SubjectID == "" {
		return errs.New(errs.CodeInvalidRequest, "audit event.subject_id 不能为空")
	}
	if e.Action == "" {
		return errs.New(errs.CodeInvalidRequest, "audit event.action 不能为空")
	}
	if e.Reason == "" {
		return errs.New(errs.CodeInvalidRequest, "audit event.reason 不能为空")
	}
	if e.Result == "" {
		return errs.New(errs.CodeInvalidRequest, "audit event.result 不能为空")
	}

	m := adminAuditLogModel{
		SubjectID:   e.SubjectID,
		Action:      e.Action,
		TargetType:  e.TargetType,
		TargetID:    e.TargetID,
		AppID:       e.AppID,
		Reason:      e.Reason,
		BeforeState: jsonFromMap(e.BeforeState),
		AfterState:  jsonFromMap(e.AfterState),
		TraceID:     e.TraceID,
		Result:      e.Result,
		ErrorCode:   e.ErrorCode,
		CreatedAt:   time.Now().UTC(),
	}
	if e.ClientIP != "" {
		ip := e.ClientIP
		m.ClientIP = &ip
	}
	if err := w.db.WithContext(ctx).Create(&m).Error; err != nil {
		return fmt.Errorf("admin audit: 写入失败: %w", err)
	}
	return nil
}

// jsonFromMap 把 map 转 JSONMap（nil/空 → nil，避免存空对象）。
func jsonFromMap(in map[string]any) JSONMap {
	if len(in) == 0 {
		return nil
	}
	out := make(JSONMap, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// isUniqueViolation 复用在 app_repo / providerconfig_repo 中已有的判定。
//
// app_repo / providerconfig_repo 是私有函数；这里直接重写一份以避免改动 scope.go。
// pgx 错误码 23505 = unique_violation。strings.Contains 兜底处理：
// gorm 用 wrap 包装过的错误可能在 messages 末尾露出 SQLState。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	type pgErr interface {
		SQLState() string
	}
	var p pgErr
	if errors.As(err, &p) && p.SQLState() == "23505" {
		return true
	}
	return strings.Contains(err.Error(), "23505") ||
		strings.Contains(err.Error(), "duplicate key value")
}
