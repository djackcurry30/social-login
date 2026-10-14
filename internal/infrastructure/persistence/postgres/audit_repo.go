package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/17track/social-login/internal/domain/audit"
	"github.com/17track/social-login/internal/pkg/appctx"
	"github.com/17track/social-login/internal/pkg/errs"
)

// AuditRepository 是 auth_audit_logs 表的仓储。
type AuditRepository struct {
	db *gorm.DB
}

// NewAuditRepository 构造仓储。
func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

var _ audit.Writer = (*AuditRepository)(nil)

// Write 写入一条审计记录。
//
// 关于失败处理：本方法如实返回错误，但【调用方必须忽略它】——审计是旁路，
// 不能因为审计写不进去就让用户登录失败。应用层用 SafeWriter 包装后使用。
func (r *AuditRepository) Write(ctx context.Context, e *audit.Event) error {
	if e == nil {
		return nil
	}
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// 审计日志按应用隔离。系统级事件（app_id 为 0，如管理端操作、
	// 渠道回调异常）走显式跨应用作用域——这是代码里可见的一次声明。
	if e.AppID > 0 {
		ctx = appctx.WithAppScope(ctx, e.AppID)
	} else {
		ctx = appctx.WithCrossAppScope(ctx)
	}

	m := auditLogModel{
		AppID:          e.AppID,
		ExternalUserID: e.ExternalUserID,
		Platform:       e.Platform,
		Scene:          e.Scene,
		Client:         e.Client,
		Action:         e.Action,
		Result:         e.Result,
		ErrorCode:      e.ErrorCode,
		UserAgent:      e.UserAgent,
		TraceID:        e.TraceID,
		Detail:         JSONMap(e.Detail),
		CreatedAt:      at,
	}
	if e.ClientIP != "" {
		ip := e.ClientIP
		m.ClientIP = &ip
	}

	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return errs.Wrap(errs.CodeInternal, "写入审计日志失败", err)
	}
	return nil
}
