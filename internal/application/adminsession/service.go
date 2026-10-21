// Package adminsession 是管理端"会话与令牌（E 组）"用例。
//
// 交付范围（架构 §15.4 E 组）：
//
//	GET  /admin/v1/tokens              按账号查活跃会话
//	POST /admin/v1/tokens/revoke       管理员强制下线（高危撤销）
//	GET  /admin/v1/revoked-jti         查撤销名单 / 账号撤销水位
//
// 这一组的真正价值是**安全事件响应**：账号被盗时，"撤销 refresh_token"
// 只挡住下一次刷新，已经发出去的 access_token 还能用满 15 分钟。
// 强制下线必须同时写撤销名单（§8.4 的分层撤销），否则客服告诉用户
// "已经踢下线了"，攻击者手里那个令牌还在用。
package adminsession

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Deps 是用例依赖。
type Deps struct {
	Sessions   session.Repository
	AdminList  session.AdminLister
	Revocation session.RevocationList
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
	// AccessTokenTTL 决定撤销水位的保留时长：水位只需覆盖"在飞令牌"的
	// 剩余寿命，过了这个时间它们自己就过期了。
	AccessTokenTTL time.Duration
	Now            func() time.Time
}

// Service 是 E 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.AccessTokenTTL <= 0 {
		d.AccessTokenTTL = 15 * time.Minute
	}
	return &Service{deps: d}
}

// TokenItem 是会话的对外视图。
//
// ⚠️ 不含 token_hash：那是"持有即可换令牌"的凭据哈希，管理端只需要
// 定位会话（id / 设备 / 时间），不需要拿到它。即便哈希不可逆，
// 泄露也等于给离线爆破留了材料。
type TokenItem struct {
	ID             int64     `json:"id"`
	AppID          int64     `json:"app_id"`
	ExternalUserID string    `json:"external_user_id"`
	DeviceID       string    `json:"device_id,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	Revoked        bool      `json:"revoked"`
	RevokedReason  string    `json:"revoked_reason,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
	RotatedFrom    *int64    `json:"rotated_from,omitempty"`
	// Active 是派生字段："未撤销且未过期"。前端不该自己算——
	// 服务端时间与浏览器时间不一致时，列表会出现"已过期但仍显示生效"。
	Active bool `json:"active"`
}

// ListInput 是 GET /admin/v1/tokens 的入参。
type ListInput struct {
	AppID          int64
	ExternalUserID string
	DeviceID       string
	// Active 为空表示不过滤。
	Active   string // "true" | "false" | ""
	Page     int
	PageSize int
}

// ListOutput 是列表出参。
type ListOutput struct {
	Items    []TokenItem `json:"items"`
	Total    int64       `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

// List 查询会话。
func (s *Service) List(ctx context.Context, in ListInput) (*ListOutput, error) {
	if s.deps.AdminList == nil {
		return nil, errs.New(errs.CodeInternal, "会话查询未装配")
	}
	f := session.AdminFilter{
		AppID:          in.AppID,
		ExternalUserID: in.ExternalUserID,
		DeviceID:       in.DeviceID,
		Page:           in.Page,
		PageSize:       in.PageSize,
	}
	switch in.Active {
	case "":
	case "true", "1":
		v := true
		f.Active = &v
	case "false", "0":
		v := false
		f.Active = &v
	default:
		return nil, errs.Newf(errs.CodeInvalidRequest, "active 不合法: %s（应为 true/false）", in.Active)
	}

	rows, total, err := s.deps.AdminList.ListAdmin(ctx, f)
	if err != nil {
		return nil, err
	}
	now := s.deps.Now()
	items := make([]TokenItem, 0, len(rows))
	for i := range rows {
		t := &rows[i]
		items = append(items, TokenItem{
			ID:             t.ID,
			AppID:          t.AppID,
			ExternalUserID: t.ExternalUserID,
			DeviceID:       t.DeviceID,
			Scope:          t.Scope,
			Revoked:        t.Revoked,
			RevokedReason:  t.RevokedReason,
			ExpiresAt:      t.ExpiresAt,
			CreatedAt:      t.CreatedAt,
			RotatedFrom:    t.RotatedFrom,
			Active:         t.Valid(now),
		})
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &ListOutput{Items: items, Total: total, Page: page, PageSize: in.PageSize}, nil
}

// RevokeInput 是强制下线入参。
type RevokeInput struct {
	AppID          int64  `json:"app_id"`
	ExternalUserID string `json:"external_user_id" binding:"required"`
	Reason         string `json:"reason" binding:"required"`
	Principal      *admin.Principal
}

// RevokeOutput 是强制下线结果。
type RevokeOutput struct {
	// RevokedTokens 是被撤销的 refresh_token 条数。
	RevokedTokens int64 `json:"revoked_tokens"`
	// RevokedAt 是写入的撤销水位：早于该时刻签发的 access_token 全部失效。
	RevokedAt time.Time `json:"revoked_at"`
	// EffectiveWindowSeconds 是"未开启强校验的调用方"仍可能接受的剩余时间，
	// 等于 access_token 的 TTL。必须如实告诉运营，不能让他们以为瞬时全站生效。
	EffectiveWindowSeconds int `json:"effective_window_seconds"`
}

// Revoke 管理员强制下线（§8.4 高危撤销）。
//
// 两步缺一不可：
//
//	① 撤销全部 refresh_token —— 挡住"下一次刷新"
//	② 写账号级撤销水位        —— 让已签发的 access_token 在强校验下立即失效
//
// 只做 ① 的话，客服对用户说"已下线"，而攻击者手里的 access_token
// 还能继续用 15 分钟——这正是修正 P0-5 要解决的问题。
func (s *Service) Revoke(ctx context.Context, in RevokeInput) (*RevokeOutput, error) {
	if in.ExternalUserID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "external_user_id 必填")
	}
	if in.AppID <= 0 {
		// 强制下线必须指明应用：同一个账号在不同应用下是不同主体（约束 C1），
		// 不指定就可能把用户在别的应用里的会话一起踢掉。
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 必填（会话按应用隔离）")
	}
	if len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired, "强制下线必须填写 reason（≥4 字符）")
	}
	if s.deps.Revocation == nil {
		// 没有撤销名单就无法兑现"立即失效"的承诺。宁可失败也不做半套：
		// 半套会让运营以为下线成功。
		return nil, errs.New(errs.CodeInternal,
			"撤销名单未装配，无法保证 access_token 立即失效")
	}

	n, err := s.deps.Sessions.RevokeAllByUser(ctx, in.AppID, in.ExternalUserID, "admin_force_offline")
	if err != nil {
		s.writeAudit(ctx, in.Principal, in, 0, "error")
		return nil, err
	}

	now := s.deps.Now()
	// 水位 TTL = access TTL：再久也没有意义（那批令牌已自然过期）。
	// 多加 1 分钟余量，避免边界上"刚好差几秒"的令牌漏网。
	ttl := s.deps.AccessTokenTTL + time.Minute
	if err := s.deps.Revocation.RevokeUser(ctx, in.AppID, in.ExternalUserID, now, ttl); err != nil {
		s.writeAudit(ctx, in.Principal, in, n, "error")
		return nil, err
	}

	s.writeAudit(ctx, in.Principal, in, n, "success")
	s.logger().Warn("管理员强制下线",
		zap.Int64("app_id", in.AppID),
		zap.String("external_user_id", in.ExternalUserID),
		zap.Int64("revoked_tokens", n),
		zap.String("reason", in.Reason))

	return &RevokeOutput{
		RevokedTokens:          n,
		RevokedAt:              now,
		EffectiveWindowSeconds: int(s.deps.AccessTokenTTL.Seconds()),
	}, nil
}

// RevocationView 是撤销状态查询结果。
type RevocationView struct {
	AppID          int64  `json:"app_id"`
	ExternalUserID string `json:"external_user_id"`
	// RevokedAt 为空表示该账号当前没有撤销水位（可能已过期，也可能从未撤销）。
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// JTI 与 JTIRevoked 仅当查询参数带 jti 时返回。
	JTI        string `json:"jti,omitempty"`
	JTIRevoked *bool  `json:"jti_revoked,omitempty"`
}

// RevocationInput 是 GET /admin/v1/revoked-jti 的入参。
type RevocationInput struct {
	AppID          int64
	ExternalUserID string
	JTI            string
}

// GetRevocation 查询撤销状态。
//
// 用途是排查"用户说自己被莫名登出"：要么有管理员强制下线（水位非空），
// 要么某个 jti 被单独拉黑。两种都要能查。
func (s *Service) GetRevocation(ctx context.Context, in RevocationInput) (*RevocationView, error) {
	if s.deps.Revocation == nil {
		return nil, errs.New(errs.CodeInternal, "撤销名单未装配")
	}
	if in.ExternalUserID == "" && in.JTI == "" {
		return nil, errs.New(errs.CodeInvalidRequest,
			"external_user_id 与 jti 至少给一个")
	}
	out := &RevocationView{
		AppID:          in.AppID,
		ExternalUserID: in.ExternalUserID,
		JTI:            in.JTI,
	}
	if in.ExternalUserID != "" {
		at, err := s.deps.Revocation.RevokedAt(ctx, in.AppID, in.ExternalUserID)
		if err != nil {
			return nil, err
		}
		if !at.IsZero() {
			out.RevokedAt = &at
		}
	}
	if in.JTI != "" {
		hit, err := s.deps.Revocation.IsJTIRevoked(ctx, in.JTI)
		if err != nil {
			return nil, err
		}
		out.JTIRevoked = &hit
	}
	return out, nil
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, in RevokeInput, n int64, result string) {
	if s.deps.AdminAudit == nil {
		return
	}
	e := &admin.AuditEvent{
		Action:     "token.force_offline",
		TargetType: "session",
		TargetID:   in.ExternalUserID,
		Reason:     in.Reason,
		Result:     result,
		AfterState: map[string]any{
			"app_id":         in.AppID,
			"revoked_tokens": n,
			"revoked_at":     s.deps.Now().Format(time.RFC3339),
		},
	}
	e.SubjectID = "admin:anonymous"
	if p != nil && p.User != nil {
		e.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	}
	_ = s.deps.AdminAudit.Write(ctx, e)
}

func (s *Service) logger() *zap.Logger {
	if s.deps.Logger == nil {
		return zap.NewNop()
	}
	return s.deps.Logger
}
