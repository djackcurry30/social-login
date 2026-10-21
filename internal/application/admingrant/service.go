// Package admingrant 是管理端"管理员授权（K 组）"用例。
//
// 交付范围（架构 §15.4 K 组）：
//
//	GET    /admin/v1/admin-grants      授权列表
//	POST   /admin/v1/admin-grants      授予角色（支持 expires_at 临时授权）
//	DELETE /admin/v1/admin-grants/{id} 撤销授权
//
// 与 admin_users.role 的关系是**并存取并集**，不是替代：
// role 是"基础角色"，grants 是"附加授权"。这样 K 组上线不需要一次性迁移
// 所有现有管理员，也不会因为漏迁让人突然失去权限（见 admin.User.Can）。
package admingrant

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Deps 是用例依赖。
type Deps struct {
	Grants     admin.GrantRepository
	Users      admin.UserRepository
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
	Now        func() time.Time
}

// Service 是 K 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: d}
}

// Item 是授权的对外视图。
type Item struct {
	ID         int64      `json:"id"`
	SubjectID  string     `json:"subject_id"`
	Role       string     `json:"role"`
	ScopeAppID *int64     `json:"scope_app_id,omitempty"`
	GrantedBy  string     `json:"granted_by"`
	GrantedAt  time.Time  `json:"granted_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// Effective 是派生字段：未撤销且未过期。
	// 前端不该自己算——浏览器与服务端时钟不一致时列表会显示错。
	Effective bool `json:"effective"`
}

// ListInput 是列表入参。
type ListInput struct {
	SubjectID      string
	IncludeRevoked bool
	Page           int
	PageSize       int
}

// ListOutput 是列表出参。
type ListOutput struct {
	Items    []Item `json:"items"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// List 查询授权。
func (s *Service) List(ctx context.Context, in ListInput) (*ListOutput, error) {
	rows, total, err := s.deps.Grants.List(ctx, admin.GrantFilter{
		SubjectID:      in.SubjectID,
		IncludeRevoked: in.IncludeRevoked,
		Page:           in.Page,
		PageSize:       in.PageSize,
	})
	if err != nil {
		return nil, err
	}
	now := s.deps.Now()
	items := make([]Item, 0, len(rows))
	for i := range rows {
		g := &rows[i]
		items = append(items, Item{
			ID:         g.ID,
			SubjectID:  g.SubjectID,
			Role:       string(g.Role),
			ScopeAppID: g.ScopeAppID,
			GrantedBy:  g.GrantedBy,
			GrantedAt:  g.GrantedAt,
			ExpiresAt:  g.ExpiresAt,
			RevokedAt:  g.RevokedAt,
			Effective:  g.Effective(now),
		})
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &ListOutput{Items: items, Total: total, Page: page, PageSize: in.PageSize}, nil
}

// GrantInput 是授予入参。
type GrantInput struct {
	SubjectID string `json:"subject_id" binding:"required"`
	Role      string `json:"role" binding:"required"`
	// ScopeAppID 可空；非空表示只对该应用生效（当前鉴权层忽略，见 Grant 注释）。
	ScopeAppID *int64 `json:"scope_app_id"`
	// ExpiresAt 可空；非空为临时授权。
	ExpiresAt string `json:"expires_at"`
	Reason    string `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// Grant 授予角色。
func (s *Service) Grant(ctx context.Context, in GrantInput) (*Item, error) {
	if len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired, "授予角色必须填写 reason（≥4 字符）")
	}
	role := admin.Role(in.Role)
	if !role.IsValid() {
		return nil, errs.Newf(errs.CodeInvalidRequest, "未知角色: %s", in.Role).
			WithDetail("allowed", roleNames())
	}

	subject := strings.TrimSpace(in.SubjectID)
	if subject == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "subject_id 不能为空")
	}
	// 受授主体必须是已存在的管理员账号。
	//
	// 不校验的话会建出一条"授予了一个不存在的人"的记录：列表里能看到，
	// 但永远不会生效，排查时会被当成"授权没起作用"。
	if err := s.ensureSubjectExists(ctx, subject); err != nil {
		return nil, err
	}

	var expires *time.Time
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest,
				"expires_at 格式非法，应为 RFC3339")
		}
		now := s.deps.Now()
		if !t.After(now) {
			// 过去的到期时间等于"授予即失效"，几乎必然是填错。
			return nil, errs.New(errs.CodeInvalidRequest, "expires_at 必须是未来时间")
		}
		utc := t.UTC()
		expires = &utc
	}

	g := &admin.Grant{
		SubjectID:  subject,
		Role:       role,
		ScopeAppID: in.ScopeAppID,
		GrantedBy:  subjectOf(in.Principal),
		GrantedAt:  s.deps.Now(),
		ExpiresAt:  expires,
	}
	saved, err := s.deps.Grants.Insert(ctx, g)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "admin.grant", fmt.Sprintf("%d", 0), in.Reason, nil, "error", err)
		return nil, err
	}

	now := s.deps.Now()
	item := &Item{
		ID:         saved.ID,
		SubjectID:  saved.SubjectID,
		Role:       string(saved.Role),
		ScopeAppID: saved.ScopeAppID,
		GrantedBy:  saved.GrantedBy,
		GrantedAt:  saved.GrantedAt,
		ExpiresAt:  saved.ExpiresAt,
		RevokedAt:  saved.RevokedAt,
		Effective:  saved.Effective(now),
	}
	s.writeAudit(ctx, in.Principal, "admin.grant", fmt.Sprintf("%d", saved.ID), in.Reason,
		map[string]any{"subject_id": saved.SubjectID, "role": string(saved.Role),
			"expires_at": saved.ExpiresAt}, "success", nil)
	s.logger().Info("管理员授权已授予",
		zap.String("subject", saved.SubjectID), zap.String("role", string(saved.Role)))
	return item, nil
}

// Revoke 撤销授权。
func (s *Service) Revoke(ctx context.Context, id int64, reason string, p *admin.Principal) error {
	if id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "grant_id 不合法")
	}
	if len([]rune(reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired, "撤销授权必须填写 reason（≥4 字符）")
	}

	g, err := s.deps.Grants.Revoke(ctx, id, s.deps.Now())
	if err != nil {
		if err == admin.ErrGrantNotFound {
			// 裸领域错误会被折算成 500，必须归一化。
			return errs.New(errs.CodeNotFound, "授权不存在")
		}
		return err
	}
	s.writeAudit(ctx, p, "admin.grant_revoke", fmt.Sprintf("%d", id), reason,
		map[string]any{"subject_id": g.SubjectID, "role": string(g.Role)}, "success", nil)
	s.logger().Info("管理员授权已撤销",
		zap.Int64("grant_id", id), zap.String("subject", g.SubjectID))
	return nil
}

// ensureSubjectExists 校验受授主体存在。
//
// 只支持本地账号形态（"admin:<id>"）：将来切 SSO 时 subject 变成 IdP 的 sub，
// 这里的校验改为"在 IdP 中存在"——接口不变。
func (s *Service) ensureSubjectExists(ctx context.Context, subject string) error {
	const prefix = "admin:"
	if !strings.HasPrefix(subject, prefix) {
		return errs.New(errs.CodeInvalidRequest,
			"暂只支持本地管理员账号（subject_id 形如 admin:<id>）").
			WithDetail("subject_id", subject)
	}
	idStr := strings.TrimPrefix(subject, prefix)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return errs.New(errs.CodeInvalidRequest, "subject_id 格式应为 admin:<数字>").
			WithDetail("subject_id", subject)
	}
	if s.deps.Users == nil {
		return nil
	}
	if _, err := s.deps.Users.FindByID(ctx, id); err != nil {
		if err == admin.ErrNotFound {
			return errs.New(errs.CodeNotFound, "被授权的管理员账号不存在").
				WithDetail("subject_id", subject)
		}
		return err
	}
	return nil
}

func subjectOf(p *admin.Principal) string {
	if p != nil && p.User != nil {
		return admin.SubjectOf(p.User.ID)
	}
	return "admin:unknown"
}

func roleNames() []string {
	roles := admin.AllRoles()
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, string(r))
	}
	return out
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action, targetID, reason string,
	after map[string]any, result string, cause error,
) {
	if s.deps.AdminAudit == nil {
		return
	}
	e := &admin.AuditEvent{
		Action:     action,
		TargetType: "admin_grant",
		TargetID:   targetID,
		Reason:     reason,
		AfterState: after,
		Result:     result,
	}
	e.SubjectID = subjectOf(p)
	if cause != nil {
		if ee, ok := errs.As(cause); ok {
			e.ErrorCode = string(ee.Code)
		} else {
			e.ErrorCode = string(errs.CodeInternal)
		}
	}
	_ = s.deps.AdminAudit.Write(ctx, e)
}

func (s *Service) logger() *zap.Logger {
	if s.deps.Logger == nil {
		return zap.NewNop()
	}
	return s.deps.Logger
}
