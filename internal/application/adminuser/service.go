// Package adminuser 是"管理员账号管理"的用例层（§25 B 组的第 4 项）。
//
// 在这之前，加人只能走 cmd/adminseed 或直接改库：没有审计、没有校验、
// 也没有"最后一个人不能把自己锁死"这类护栏。本包补的就是这三件事。
//
// 三条规则值得单独解释，因为它们都是"不写就会以事故形式被发现"的那种：
//
//  1. 不能修改自己的角色、不能停用自己 —— 一个手滑就把自己降级或锁在门外，
//     而恢复手段只有改库。
//  2. 不能移除最后一个启用中的 super_admin —— 同样只能改库恢复。
//  3. 重置密码与停用必须撤销该账号的全部会话 —— 只改库不撤会话等于没改：
//     对方手里的 token 还能继续用满一个会话周期。
package adminuser

import (
	"context"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/adminx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// Deps 是依赖集合。
type Deps struct {
	Users    admin.UserRepository
	Sessions admin.SessionRepository
	// Audit 为 nil 时跳过审计写入（测试与最小装配）。生产必须提供：
	// 没有审计的"管理员账号管理"被入侵时查不出谁加了后门账号。
	Audit  admin.AuditWriter
	Logger *zap.Logger
}

// Service 提供管理员账号的增查改与改密。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(deps Deps) *Service { return &Service{deps: deps} }

// View 是对外的管理员视图。
//
// 独立于 admin.User 是有意的：admin.User 带着 PasswordHash，而视图
// 【永远】不含它。用同一个结构体靠"记得清空"来保证不泄漏，迟早会漏。
type View struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	Status      int16      `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func toView(u *admin.User) View {
	return View{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		Status:      u.Status,
		LastLoginAt: u.LastLoginAt,
		CreatedAt:   u.CreatedAt,
	}
}

// List 列出管理员账号。
func (s *Service) List(ctx context.Context, limit int) ([]View, error) {
	users, err := s.deps.Users.List(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(users))
	for _, u := range users {
		out = append(out, toView(u))
	}
	return out, nil
}

// CreateInput 是新建管理员的入参。
type CreateInput struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	// Reason 是审计必填项。
	//
	// 管理端的高危写操作一律要求 reason（与 K 组撤权、I 组熔断复位一致）：
	// "谁在什么时候给谁开了账号"如果没有原因，审计表只能回答 what，
	// 回答不了 why——而 why 才是事后追责与复盘的对象。
	Reason string `json:"reason"`
}

// Create 新建管理员。
func (s *Service) Create(ctx context.Context, actor *admin.User, in CreateInput) (*View, error) {
	if actor == nil {
		return nil, errs.New(errs.CodeUnauthorized, "未认证")
	}
	username := strings.TrimSpace(in.Username)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if len(in.Password) < minPasswordLen {
		return nil, errs.Newf(errs.CodeInvalidRequest, "密码至少 %d 位", minPasswordLen).
			WithDetail("field", "password")
	}
	reason, err := requireReason(in.Reason)
	if err != nil {
		return nil, err
	}
	role := admin.Role(strings.TrimSpace(in.Role))
	if role == "" {
		role = admin.RoleViewer
	}
	if !role.IsValid() {
		return nil, errs.Newf(errs.CodeInvalidRequest, "非法的 role: %s", role).
			WithDetail("field", "role")
	}
	display := strings.TrimSpace(in.DisplayName)
	if len([]rune(display)) > maxDisplayNameLen {
		return nil, errs.Newf(errs.CodeInvalidRequest, "display_name 超长（最多 %d 字）", maxDisplayNameLen)
	}

	hash, err := adminx.HashPassword(in.Password)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成密码哈希失败", err)
	}
	created, err := s.deps.Users.Insert(ctx, &admin.User{
		Username:     username,
		PasswordHash: hash,
		DisplayName:  display,
		Role:         role,
	})
	if err != nil {
		return nil, err
	}

	s.writeAudit(ctx, actor, "admin.create", created.ID, reason,
		map[string]any{"username": created.Username, "role": string(created.Role)},
		nil, "success")
	if s.deps.Logger != nil {
		s.deps.Logger.Info("创建管理员账号",
			zap.String("actor", actor.Username),
			zap.String("username", created.Username),
			zap.String("role", string(created.Role)))
	}
	v := toView(created)
	return &v, nil
}

// UpdateInput 是修改管理员的入参。三个字段都可选。
type UpdateInput struct {
	DisplayName *string `json:"display_name"`
	Role        *string `json:"role"`
	Reason      string  `json:"reason"`
	// Status 用指针：0（停用）是合法值，零值不能让"没传"和"传了 0"混为一谈。
	Status *int16 `json:"status"`
}

// Update 修改显示名 / 角色 / 启用状态。
func (s *Service) Update(ctx context.Context, actor *admin.User, id int64, in UpdateInput) (*View, error) {
	if actor == nil {
		return nil, errs.New(errs.CodeUnauthorized, "未认证")
	}
	reason, err := requireReason(in.Reason)
	if err != nil {
		return nil, err
	}
	target, err := s.deps.Users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	before := map[string]any{
		"display_name": target.DisplayName,
		"role":         string(target.Role),
		"status":       target.Status,
	}

	pu := admin.ProfileUpdate{}
	if in.DisplayName != nil {
		d := strings.TrimSpace(*in.DisplayName)
		if len([]rune(d)) > maxDisplayNameLen {
			return nil, errs.Newf(errs.CodeInvalidRequest, "display_name 超长（最多 %d 字）", maxDisplayNameLen)
		}
		pu.DisplayName = &d
	}
	if in.Role != nil {
		r := admin.Role(strings.TrimSpace(*in.Role))
		if !r.IsValid() {
			return nil, errs.Newf(errs.CodeInvalidRequest, "非法的 role: %s", r).
				WithDetail("field", "role")
		}
		pu.Role = &r
	}
	if in.Status != nil {
		if *in.Status != 0 && *in.Status != 1 {
			return nil, errs.New(errs.CodeInvalidRequest, "status 只能是 0（停用）或 1（启用）").
				WithDetail("field", "status")
		}
		pu.Status = in.Status
	}

	// 自锁保护：改自己的角色或停用自己，都会让当前这个人失去操作能力。
	demoting := pu.Role != nil && *pu.Role != target.Role
	disabling := pu.Status != nil && *pu.Status == 0
	if target.ID == actor.ID && (demoting || disabling) {
		return nil, errs.New(errs.CodeForbidden,
			"不能修改自己的角色或停用自己（会立刻失去管理权限）").
			WithDetail("rule", "no_self_lockout")
	}

	// 最后一个超级管理员保护：降级或停用之后，没人能再改配置。
	losingSuper := target.Role == admin.RoleSuperAdmin &&
		target.Status == 1 &&
		(demoting || disabling)
	if losingSuper {
		n, err := s.deps.Users.CountEnabledSuperAdmins(ctx)
		if err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, errs.New(errs.CodeForbidden,
				"这是最后一个启用中的超级管理员，不能降级或停用").
				WithDetail("rule", "last_super_admin")
		}
	}

	if err := s.deps.Users.UpdateProfile(ctx, id, pu); err != nil {
		return nil, err
	}

	// 停用要立刻撤会话，否则"停用"在 8 小时内不会真的生效。
	if disabling {
		if err := s.deps.Sessions.RevokeAllByUser(ctx, id); err != nil {
			// 已经停用了，撤会话失败不能回滚——但要记下来，让运维手工补。
			if s.deps.Logger != nil {
				s.deps.Logger.Error("停用管理员后撤销会话失败，该账号的既有会话仍有效",
					zap.Int64("admin_id", id), zap.Error(err))
			}
		}
	}

	updated, err := s.deps.Users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	after := map[string]any{
		"display_name": updated.DisplayName,
		"role":         string(updated.Role),
		"status":       updated.Status,
	}
	s.writeAudit(ctx, actor, "admin.update", id, reason, after, before, "success")
	if s.deps.Logger != nil {
		s.deps.Logger.Info("修改管理员账号",
			zap.String("actor", actor.Username),
			zap.Int64("admin_id", id),
			zap.Any("before", before),
			zap.Any("after", after))
	}
	v := toView(updated)
	return &v, nil
}

// ResetPassword 重置某管理员的密码，并撤销其全部会话。
//
// 由超级管理员执行，因此不需要旧密码：这是"员工离职/账号疑似泄漏"时的止损手段。
func (s *Service) ResetPassword(ctx context.Context, actor *admin.User, id int64, newPassword, reason string) error {
	if actor == nil {
		return errs.New(errs.CodeUnauthorized, "未认证")
	}
	if len(newPassword) < minPasswordLen {
		return errs.Newf(errs.CodeInvalidRequest, "密码至少 %d 位", minPasswordLen).
			WithDetail("field", "password")
	}
	if _, err := requireReason(reason); err != nil {
		return err
	}
	target, err := s.deps.Users.FindByID(ctx, id)
	if err != nil {
		return err
	}
	hash, err := adminx.HashPassword(newPassword)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "生成密码哈希失败", err)
	}
	if err := s.deps.Users.UpdatePassword(ctx, id, hash); err != nil {
		return err
	}
	if err := s.deps.Sessions.RevokeAllByUser(ctx, id); err != nil {
		// 密码已经改了，撤会话失败要显式说出来：对方可能还在用旧会话。
		if s.deps.Logger != nil {
			s.deps.Logger.Error("重置密码后撤销会话失败，该账号的既有会话仍有效",
				zap.Int64("admin_id", id), zap.Error(err))
		}
		return errs.Wrap(errs.CodeInternal, "密码已重置，但撤销该账号会话失败，请重试或手工撤销", err)
	}
	s.writeAudit(ctx, actor, "admin.reset_password", target.ID, reason,
		map[string]any{"username": target.Username}, nil, "success")
	if s.deps.Logger != nil {
		s.deps.Logger.Info("重置管理员密码",
			zap.String("actor", actor.Username),
			zap.String("username", target.Username))
	}
	return nil
}

// --- 内部 ---

const (
	minPasswordLen    = 8
	maxDisplayNameLen = 64
	minUsernameLen    = 3
	maxUsernameLen    = 64
)

// requireReason 校验审计原因。
//
// 不允许空串是刻意的：没有原因的管理端审计，事后只能回答"谁改了什么"，
// 回答不了"为什么"。而后者才是复盘与追责真正需要的。
func requireReason(raw string) (string, error) {
	r := strings.TrimSpace(raw)
	if r == "" {
		return "", errs.New(errs.CodeInvalidRequest, "reason 必填（管理端写操作需要审计原因）").
			WithDetail("field", "reason")
	}
	if len([]rune(r)) > 200 {
		return "", errs.New(errs.CodeInvalidRequest, "reason 超长（最多 200 字）").
			WithDetail("field", "reason")
	}
	return r, nil
}

// validateUsername 只做长度与字符集校验。
//
// 不允许空白与冒号：空白会在登录表单里被 trim 掉造成"明明输对了"，
// 冒号则容易与控制台/Audit 的 "actor:action" 记法混淆。
func validateUsername(name string) error {
	if len(name) < minUsernameLen || len(name) > maxUsernameLen {
		return errs.Newf(errs.CodeInvalidRequest,
			"username 长度需在 %d~%d 之间", minUsernameLen, maxUsernameLen).
			WithDetail("field", "username")
	}
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.'
		if !ok {
			return errs.New(errs.CodeInvalidRequest,
				"username 只能包含字母、数字、下划线、短横线与点").
				WithDetail("field", "username")
		}
	}
	return nil
}

// writeAudit 写管理端审计。失败只记录不阻断——审计是证据，不是业务前提。
func (s *Service) writeAudit(
	ctx context.Context,
	actor *admin.User,
	action string,
	targetID int64,
	reason string,
	after, before map[string]any,
	result string,
) {
	if s.deps.Audit == nil {
		return
	}
	e := &admin.AuditEvent{
		SubjectID:   strconv.FormatInt(actor.ID, 10),
		Action:      action,
		TargetType:  "admin_user",
		TargetID:    strconv.FormatInt(targetID, 10),
		Reason:      reason,
		BeforeState: before,
		AfterState:  after,
		TraceID:     reqmeta.TraceID(ctx),
		Result:      result,
	}
	if err := s.deps.Audit.Write(ctx, e); err != nil && s.deps.Logger != nil {
		s.deps.Logger.Warn("写管理端审计失败", zap.String("action", action), zap.Error(err))
	}
}
