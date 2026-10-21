// Package adminidentity 是管理端"身份与绑定（C 组）"用例。
//
// 交付范围（架构 §15.4 C 组）：
//
//	GET    /admin/v1/identities                          多维查询身份
//	GET    /admin/v1/identities/{id}                     详情（claims + 绑定历史）
//	GET    /admin/v1/bindings                            绑定查询
//	GET    /admin/v1/accounts/{externalUserId}/bindings  某账号全部绑定
//	DELETE /admin/v1/bindings/{id}                       强制解绑（需 reason）
//	POST   /admin/v1/bindings/{id}/transfer              transfer 旁路（需 reason）
//
// 为什么与合并同批交付（§13 第三期）：合并过后最常见的问题是"到底谁绑了谁"。
// 没有查询入口，客服接到用户申诉只能靠连库；没有强制解绑，一个错误的
// 自动合并就只能等下一次合并来"盖住"。
package adminidentity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// Deps 是用例依赖。
type Deps struct {
	Identities  identity.AdminLister
	IdentityGet identity.Repository
	Claims      identity.ClaimRepository
	Bindings    binding.AdminLister
	Writer      binding.AdminWriter
	AdminAudit  admin.AuditWriter
	Logger      *zap.Logger
	Now         func() time.Time
}

// Service 是 C 组用例入口。
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

// --- 身份查询 ---

// IdentityItem 是身份的对外视图。
//
// 不含 profile_snapshot 之外的敏感信息；open_id 保留——运维定位问题时
// 就是要靠它跟平台后台对齐。
type IdentityItem struct {
	ID              int64          `json:"id"`
	AppID           int64          `json:"app_id"`
	Platform        string         `json:"platform"`
	ProviderAppID   string         `json:"provider_app_id"`
	OpenID          string         `json:"open_id"`
	IdentityKey     string         `json:"identity_key"`
	Profile         map[string]any `json:"profile_snapshot,omitempty"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastLoginAt     *time.Time     `json:"last_login_at,omitempty"`
	ProfileSyncedAt *time.Time     `json:"profile_synced_at,omitempty"`
}

// IdentityListInput 是 GET /admin/v1/identities 的入参。
type IdentityListInput struct {
	AppID          int64
	Platform       string
	OpenID         string
	IdentityKey    string
	ExternalUserID string
	Page           int
	PageSize       int
}

// IdentityListOutput 是列表出参。
type IdentityListOutput struct {
	Items    []IdentityItem `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// ListIdentities 多维查询身份。
func (s *Service) ListIdentities(ctx context.Context, in IdentityListInput) (*IdentityListOutput, error) {
	rows, total, err := s.deps.Identities.ListAdmin(ctx, identity.AdminQuery{
		AppID:          in.AppID,
		Platform:       in.Platform,
		OpenID:         in.OpenID,
		IdentityKey:    in.IdentityKey,
		ExternalUserID: in.ExternalUserID,
		Page:           in.Page,
		PageSize:       in.PageSize,
	})
	if err != nil {
		return nil, err
	}
	items := make([]IdentityItem, 0, len(rows))
	for i := range rows {
		items = append(items, toIdentityItem(&rows[i]))
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &IdentityListOutput{Items: items, Total: total, Page: page, PageSize: in.PageSize}, nil
}

// ClaimItem 是 claim 的对外视图。
//
// value_hash 只返回前缀：完整哈希可用于离线比对（例如拿一批疑似手机号
// 反查是否与库中某条匹配），没有必要完整暴露。
type ClaimItem struct {
	ID         int64      `json:"id"`
	Type       string     `json:"claim_type"`
	// 不回显凭证明文：库里只存哈希与信封加密后的密文（§8.5），
	// 展示明文等于给"管理端账号被盗"额外送一批手机号。
	ValueHash string `json:"value_hash_prefix,omitempty"`
	Verified   bool       `json:"verified"`
	Source     string     `json:"source"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// BindingItem 是绑定的对外视图。
type BindingItem struct {
	ID             int64      `json:"id"`
	AppID          int64      `json:"app_id"`
	ExternalUserID string     `json:"external_user_id"`
	IdentityID     int64      `json:"identity_id"`
	Status         string     `json:"status"`
	IsPrimary      bool       `json:"is_primary"`
	BindSource     string     `json:"bind_source"`
	BoundAt        time.Time  `json:"bound_at"`
	UnboundAt      *time.Time `json:"unbound_at,omitempty"`
}

// IdentityDetail 是 GET /admin/v1/identities/{id} 的出参。
type IdentityDetail struct {
	Identity IdentityItem  `json:"identity"`
	Claims   []ClaimItem   `json:"claims"`
	Bindings []BindingItem `json:"bindings"`
}

// GetIdentity 返回身份详情（含 claims 与绑定历史）。
func (s *Service) GetIdentity(ctx context.Context, appID, id int64) (*IdentityDetail, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "identity_id 不合法")
	}
	if appID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 必填（身份按应用隔离）")
	}
	idn, err := s.deps.IdentityGet.FindByID(ctx, appID, id)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return nil, errs.New(errs.CodeNotFound, "身份不存在")
		}
		return nil, err
	}

	detail := &IdentityDetail{
		Identity: toIdentityItem(idn),
		Claims:   []ClaimItem{},
		Bindings: []BindingItem{},
	}

	claims, err := s.deps.Claims.ListByIdentity(ctx, appID, id)
	if err != nil {
		return nil, err
	}
	for i := range claims {
		c := &claims[i]
		item := ClaimItem{
			ID:         c.ID,
			Type:       c.Type,
			Verified:   c.Verified,
			Source:     c.Source,
			VerifiedAt: c.VerifiedAt,
			RevokedAt:  c.RevokedAt,
			CreatedAt:  c.CreatedAt,
		}
		if len(c.ValueHash) > 8 {
			item.ValueHash = c.ValueHash[:8]
		} else {
			item.ValueHash = c.ValueHash
		}
		detail.Claims = append(detail.Claims, item)
	}

	bindings, _, err := s.deps.Bindings.ListAdmin(ctx, binding.AdminFilter{
		AppID: appID, IdentityID: id, PageSize: 100,
	})
	if err != nil {
		return nil, err
	}
	for i := range bindings {
		detail.Bindings = append(detail.Bindings, toBindingItem(&bindings[i]))
	}
	return detail, nil
}

// --- 绑定查询 ---

// BindingListInput 是绑定查询入参。
type BindingListInput struct {
	AppID          int64
	ExternalUserID string
	Status         string
	IdentityID     int64
	Page           int
	PageSize       int
}

// BindingListOutput 是列表出参。
type BindingListOutput struct {
	Items    []BindingItem `json:"items"`
	Total    int64         `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

// ListBindings 查询绑定。
func (s *Service) ListBindings(ctx context.Context, in BindingListInput) (*BindingListOutput, error) {
	if in.Status != "" && in.Status != binding.StatusActive && in.Status != binding.StatusUnbound {
		return nil, errs.Newf(errs.CodeInvalidRequest, "status 不合法: %s", in.Status)
	}
	rows, total, err := s.deps.Bindings.ListAdmin(ctx, binding.AdminFilter{
		AppID:          in.AppID,
		ExternalUserID: in.ExternalUserID,
		Status:         in.Status,
		IdentityID:     in.IdentityID,
		Page:           in.Page,
		PageSize:       in.PageSize,
	})
	if err != nil {
		return nil, err
	}
	items := make([]BindingItem, 0, len(rows))
	for i := range rows {
		items = append(items, toBindingItem(&rows[i]))
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &BindingListOutput{Items: items, Total: total, Page: page, PageSize: in.PageSize}, nil
}

// ListAccountBindings 返回某账号的全部绑定（含已解绑历史）。
func (s *Service) ListAccountBindings(ctx context.Context, appID int64, externalUserID string) (*BindingListOutput, error) {
	if externalUserID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "external_user_id 必填")
	}
	return s.ListBindings(ctx, BindingListInput{
		AppID: appID, ExternalUserID: externalUserID, PageSize: 100,
	})
}

// --- 强制解绑 ---

// UnbindInput 是强制解绑入参。
type UnbindInput struct {
	AppID     int64 `json:"app_id"`
	Reason    string `json:"reason"`
	Principal *admin.Principal
}

// ForceUnbind 强制解绑（客服处理申诉），写审计并同时写 outbox 事件。
func (s *Service) ForceUnbind(ctx context.Context, bindingID int64, in UnbindInput) (*BindingItem, error) {
	if bindingID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "binding_id 不合法")
	}
	if len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired, "强制解绑必须填写 reason（≥4 字符）")
	}
	// app_id 可选：仓储会按 binding id 读出真实归属（写入事件与审计需要它）。
	// 传了就作为校验条件，防止运维看错应用而误操作。
	ev := &binding.AdminEvent{
		EventID:       event.NewEventID(s.deps.Now()),
		Type:          event.TypeBindingRemoved,
		SchemaVersion: 1,
		Payload: map[string]any{
			"binding_id":     bindingID,
			"reason":         "admin_force_unbind",
			"admin_reason":   in.Reason,
			"occurred_at":    s.deps.Now().Format(time.RFC3339),
		},
	}

	b, err := s.deps.Writer.ForceUnbind(ctx, binding.AdminUnbindInput{
		AppID: in.AppID, BindingID: bindingID, Reason: in.Reason, Event: ev, At: s.deps.Now(),
	})
	if err != nil {
		s.writeAudit(ctx, in.Principal, "binding.force_unbind", bindingID, in.Reason, nil, "error", err)
		return nil, err
	}

	item := toBindingItem(b)
	s.writeAudit(ctx, in.Principal, "binding.force_unbind", bindingID, in.Reason,
		map[string]any{"external_user_id": b.ExternalUserID, "identity_id": b.IdentityID}, "success", nil)
	return &item, nil
}

// --- transfer 旁路 ---

// TransferInput 是 transfer 入参。
type TransferInput struct {
	AppID      int64  `json:"app_id"`
	TargetUser string `json:"target_user_id"`
	Reason     string `json:"reason"`
	Principal  *admin.Principal
}

// Transfer 把 identity 从旧账号转到新账号（旧账号保留）。
//
// 高危：它改变"谁能用这个渠道登录"。因此必须 reason，且写审计。
// 与 merge 的差别见 domain/binding.AdminWriter 注释。
func (s *Service) Transfer(ctx context.Context, bindingID int64, in TransferInput) (*BindingItem, error) {
	if bindingID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "binding_id 不合法")
	}
	if in.TargetUser == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "target_user_id 必填")
	}
	if len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired, "transfer 必须填写 reason（≥4 字符）")
	}
	ev := &binding.AdminEvent{
		EventID:       event.NewEventID(s.deps.Now()),
		Type:          event.TypeBindingRemoved,
		SchemaVersion: 1,
		Payload: map[string]any{
			"binding_id":   bindingID,
			"reason":       "admin_transfer",
			"admin_reason": in.Reason,
			"occurred_at":  s.deps.Now().Format(time.RFC3339),
		},
	}

	b, err := s.deps.Writer.Transfer(ctx, binding.AdminTransferInput{
		AppID: in.AppID, BindingID: bindingID, TargetUser: in.TargetUser,
		Reason: in.Reason, Event: ev, At: s.deps.Now(),
	})
	if err != nil {
		s.writeAudit(ctx, in.Principal, "binding.transfer", bindingID, in.Reason, nil, "error", err)
		return nil, err
	}

	item := toBindingItem(b)
	s.writeAudit(ctx, in.Principal, "binding.transfer", bindingID, in.Reason,
		map[string]any{"identity_id": b.IdentityID, "target_user_id": in.TargetUser}, "success", nil)
	return &item, nil
}

// --- helpers ---

func toIdentityItem(idn *identity.Identity) IdentityItem {
	return IdentityItem{
		ID:              idn.ID,
		AppID:           idn.AppID,
		Platform:        idn.Platform,
		ProviderAppID:   idn.ProviderAppID,
		OpenID:          idn.OpenID,
		IdentityKey:     idn.IdentityKey,
		Profile:         idn.ProfileSnapshot,
		FirstSeenAt:     idn.FirstSeenAt,
		LastLoginAt:     idn.LastLoginAt,
		ProfileSyncedAt: idn.ProfileSyncedAt,
	}
}

func toBindingItem(b *binding.Binding) BindingItem {
	return BindingItem{
		ID:             b.ID,
		AppID:          b.AppID,
		ExternalUserID: b.ExternalUserID,
		IdentityID:     b.IdentityID,
		Status:         b.Status,
		IsPrimary:      b.IsPrimary,
		BindSource:     b.BindSource,
		BoundAt:        b.BoundAt,
		UnboundAt:      b.UnboundAt,
	}
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action string, bindingID int64,
	reason string, detail map[string]any, result string, cause error,
) {
	if s.deps.AdminAudit == nil {
		return
	}
	m := reqmeta.From(ctx)
	e := &admin.AuditEvent{
		Action:      action,
		TargetType:  "binding",
		TargetID:    fmt.Sprintf("%d", bindingID),
		Reason:      reason,
		AfterState:  detail,
		Result:      result,
		TraceID:     m.TraceID,
		ClientIP:    m.ClientIP,
	}
	e.SubjectID = "admin:anonymous"
	if p != nil && p.User != nil {
		e.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	}
	if cause != nil {
		if ee, ok := errs.As(cause); ok {
			e.ErrorCode = string(ee.Code)
		} else {
			e.ErrorCode = string(errs.CodeInternal)
		}
	}
	// 审计是旁路：写失败不影响主流程（与 auditx.Emit 同口径）。
	_ = s.deps.AdminAudit.Write(ctx, e)
}

// 保证 audit 常量被引用（action 名称与业务审计保持同一套词汇）。
var _ = audit.ActionTransfer
