// claims.go 是管理端 J 组（凭证一致性运维）的用例。
//
// 交付范围（架构 §15.4 J 组）：
//
//	GET  /admin/v1/claims                    按 app_id / claim_type / identity_id 查询凭证
//	GET  /admin/v1/claims/mismatches          漂移记录（§8.5 回源核对失败）
//	POST /admin/v1/claims/{id}/revoke         人工失效某条凭证（需 reason）
//
// 这一组要回答的运维问题很具体：用户说"我明明换绑了手机号，为什么新号
// 还提示已被占用"。答案通常是 identity_claims 里还留着一条【已验证且未撤销】
// 的记录——它是"某次授权中平台证明过这个号属于他"的历史事实，平台不会主动
// 撤销，本服务也没有变更通知（§8.5 第 2 条仅是建议方案）。于是：
//
//  1. 归并时会回源核对并拒绝错误归并（不会劫持账号，这是设计目标）；
//  2. 但拒绝归并会留下一条漂移记录，运营要能看到并处理；
//  3. 处理后唯一的有效动作是撤销那条 claim，释放号码。
//
// 本文件正好就是这三步的 2 和 3。
package adminidentity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- 凭证查询 ---

// ClaimListInput 是 GET /admin/v1/claims 的入参。
type ClaimListInput struct {
	AppID      int64
	ClaimType  string
	IdentityID int64
	Status     string
	Page       int
	PageSize   int
}

// ClaimListOutput 是凭证列表出参。
type ClaimListOutput struct {
	Items    []ClaimItem `json:"items"`
	Total    int64       `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

// ListClaims 按条件分页查询凭证。
//
// 与 C 组 GetIdentity 里的 claims 相比，这里有两个刻意的差异：
//
//	含已撤销记录  换号排查的第一步就是"旧号是什么时候被释放的"
//	支持跨身份翻页  运营拿到一个号码碎片时要能反查，而不是先猜 identity_id
func (s *Service) ListClaims(ctx context.Context, in ClaimListInput) (*ClaimListOutput, error) {
	if s.deps.ClaimAdmin == nil {
		return nil, errs.New(errs.CodeInternal, "凭证查询未装配（J 组依赖缺失）")
	}
	if !identity.IsValidClaimStatusFilter(in.Status) {
		return nil, errs.Newf(errs.CodeInvalidRequest, "status 不合法: %s", in.Status).
			WithDetail("valid", []string{identity.ClaimStatusVerified,
				identity.ClaimStatusUnverified, identity.ClaimStatusRevoked})
	}

	rows, total, err := s.deps.ClaimAdmin.ListAdmin(ctx, identity.ClaimAdminQuery{
		AppID:      in.AppID,
		ClaimType:  in.ClaimType,
		IdentityID: in.IdentityID,
		Status:     in.Status,
		Page:       in.Page,
		PageSize:   in.PageSize,
	})
	if err != nil {
		return nil, err
	}

	items := make([]ClaimItem, 0, len(rows))
	for i := range rows {
		items = append(items, toClaimItem(&rows[i]))
	}
	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &ClaimListOutput{Items: items, Total: total, Page: page, PageSize: in.PageSize}, nil
}

// --- 漂移记录 ---

// MismatchListInput 是 GET /admin/v1/claims/mismatches 的入参。
type MismatchListInput struct {
	AppID      int64
	Status     string
	Kind       string
	ClaimType  string
	IdentityID int64
	Page       int
	PageSize   int
}

// MismatchListOutput 是漂移记录列表出参。
type MismatchListOutput struct {
	Items    []MismatchItem `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	// OpenTotal 是"未闭环总数"，不受 status 筛选影响。
	//
	// 单独给一个数字而不是让前端自己数当前页：§8.5 把 claim_mismatch 的
	// 非零值当作"需要人工介入"的信号，这个数字必须是全量的，
	// 否则运维翻到第二页时会以为已经处理完了。
	OpenTotal int64 `json:"open_total"`
}

// ListMismatches 查询漂移记录。
func (s *Service) ListMismatches(ctx context.Context, in MismatchListInput) (*MismatchListOutput, error) {
	if s.deps.Mismatches == nil {
		return nil, errs.New(errs.CodeInternal, "漂移记录查询未装配（J 组依赖缺失）")
	}
	if in.Status != "" && in.Status != identity.MismatchStatusOpen &&
		in.Status != identity.MismatchStatusResolved {
		return nil, errs.Newf(errs.CodeInvalidRequest, "status 不合法: %s", in.Status).
			WithDetail("valid", []string{identity.MismatchStatusOpen, identity.MismatchStatusResolved})
	}
	if in.Kind != "" && !identity.IsValidMismatchKind(in.Kind) {
		return nil, errs.Newf(errs.CodeInvalidRequest, "kind 不合法: %s", in.Kind)
	}

	rows, total, err := s.deps.Mismatches.ListAdmin(ctx, identity.MismatchAdminQuery{
		AppID:      in.AppID,
		Status:     in.Status,
		Kind:       in.Kind,
		ClaimType:  in.ClaimType,
		IdentityID: in.IdentityID,
		Page:       in.Page,
		PageSize:   in.PageSize,
	})
	if err != nil {
		return nil, err
	}

	items := make([]MismatchItem, 0, len(rows))
	for i := range rows {
		items = append(items, toMismatchItem(&rows[i]))
	}

	// 未闭环总数：只按应用过滤，忽略 status / kind / claim_type 等筛选，
	// 这样它表达的是"这个应用现在还有多少条待处理"。
	_, openTotal, err := s.deps.Mismatches.ListAdmin(ctx, identity.MismatchAdminQuery{
		AppID:    in.AppID,
		Status:   identity.MismatchStatusOpen,
		Page:     1,
		PageSize: 1,
	})
	if err != nil {
		return nil, err
	}

	page := in.Page
	if page <= 0 {
		page = 1
	}
	return &MismatchListOutput{
		Items: items, Total: total, Page: page, PageSize: in.PageSize, OpenTotal: openTotal,
	}, nil
}

// --- 人工撤销凭证 ---

// RevokeClaimInput 是人工撤销凭证的入参。
type RevokeClaimInput struct {
	// AppID 必填：凭证按应用隔离（约束 C1），拿到的 id 属于哪个应用必须显式声明。
	AppID     int64  `json:"app_id"`
	Reason    string `json:"reason"`
	Principal *admin.Principal
}

// RevokeClaimOutput 是撤销结果。
type RevokeClaimOutput struct {
	Claim ClaimItem `json:"claim"`
	// AlreadyRevoked 说明这条凭证此前已被撤销，本次是重复操作。
	//
	// 单独给出而不是静默成功：运维点完按钮要能确认"是我这次撤的"还是
	// "早就被别人撤了"。后者往往意味着另一个工单已经在处理同一件事。
	AlreadyRevoked bool `json:"already_revoked"`
	// ResolvedMismatches 是本次顺带闭环的漂移记录条数。
	ResolvedMismatches int64 `json:"resolved_mismatches"`
}

// RevokeClaim 人工失效一条凭证，并闭环它名下的漂移记录。
//
// 为什么"撤销"和"闭环漂移"必须绑在一起做：
// 漂移记录的根因是"这条 claim 不再代表事实"，而本服务能做的修正是撤销它。
// 如果撤销了却不闭环，claim_mismatch 计数就永远降不下来——一个只涨不落的
// 指标，第二次就没人看了。反过来，只闭环不撤销同样是假的修复：
// 下一次登录还会命中同一条 claim、再记一条新的漂移。
func (s *Service) RevokeClaim(ctx context.Context, claimID int64, in RevokeClaimInput) (*RevokeClaimOutput, error) {
	if claimID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "claim_id 不合法")
	}
	if in.AppID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 必填（凭证按应用隔离）")
	}
	if len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired, "撤销凭证必须填写 reason（≥4 字符）")
	}
	if s.deps.Claims == nil {
		return nil, errs.New(errs.CodeInternal, "凭证仓储未装配")
	}

	claim, err := s.deps.Claims.FindByID(ctx, in.AppID, claimID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// 统一翻译成 404：与 G 组事件不存在的处理同口径。
			// 不翻译的话 errs.From(nil) 会把它归一化成 500。
			return nil, errs.New(errs.CodeNotFound, "凭证不存在")
		}
		return nil, err
	}

	before := map[string]any{
		"claim_id":    claim.ID,
		"identity_id": claim.IdentityID,
		"claim_type":  claim.Type,
		"verified":    claim.Verified,
		"source":      claim.Source,
		"revoked_at":  claim.RevokedAt,
	}

	already := claim.RevokedAt != nil
	now := s.deps.Now()
	if !already {
		if err := s.deps.Claims.Revoke(ctx, in.AppID, claim.IdentityID,
			claim.Type, claim.ValueHash, now); err != nil {
			s.writeAuditFor(ctx, in.Principal, "claim", "claim.revoke", fmt.Sprintf("%d", claimID),
				in.Reason, before, nil, "error", err)
			return nil, err
		}
		claim.RevokedAt = &now
	}

	out := &RevokeClaimOutput{
		Claim:          toClaimItem(claim),
		AlreadyRevoked: already,
	}

	// 闭环漂移记录。已撤销的旧凭证仍然可能有 open 记录（撤销动作早于本功能
	// 上线、或撤销来自别的路径），所以即便 already 也照样尝试闭环。
	if s.deps.Mismatches != nil {
		n, err := s.deps.Mismatches.ResolveByClaim(ctx, identity.ResolveInput{
			AppID:      in.AppID,
			ClaimID:    claimID,
			By:         principalSubject(in.Principal),
			Resolution: fmt.Sprintf("claim 已被人工撤销：%s", in.Reason),
			At:         now,
		})
		if err != nil {
			// 闭环失败不能让撤销回滚——撤销已经生效，回滚反而更糟。
			// 记审计与日志，让运维手工补。
			s.writeAuditFor(ctx, in.Principal, "claim", "claim.revoke",
				fmt.Sprintf("%d", claimID), in.Reason, before,
				map[string]any{"resolved_mismatches": 0, "resolve_error": err.Error()},
				"partial", err)
			return nil, err
		}
		out.ResolvedMismatches = n
	}

	s.writeAuditFor(ctx, in.Principal, "claim", "claim.revoke", fmt.Sprintf("%d", claimID),
		in.Reason, before,
		map[string]any{
			"revoked_at":          claim.RevokedAt,
			"already_revoked":     already,
			"resolved_mismatches": out.ResolvedMismatches,
		}, "success", nil)
	return out, nil
}

// --- helpers ---

// toClaimItem 把领域对象转成对外视图。
//
// 哈希只回前缀：完整哈希可用于"拿一批疑似手机号离线反查库中是否匹配"，
// 而管理端账号被盗的代价不该包括一整批手机号（§8.5 不明文回显的同一考虑）。
func toClaimItem(c *identity.Claim) ClaimItem {
	item := ClaimItem{
		ID:         c.ID,
		AppID:      c.AppID,
		IdentityID: c.IdentityID,
		Type:       c.Type,
		Verified:   c.Verified,
		Source:     c.Source,
		VerifiedAt: c.VerifiedAt,
		RevokedAt:  c.RevokedAt,
		CreatedAt:  c.CreatedAt,
	}
	switch {
	case c.RevokedAt != nil:
		item.Status = identity.ClaimStatusRevoked
	case c.Verified:
		item.Status = identity.ClaimStatusVerified
	default:
		item.Status = identity.ClaimStatusUnverified
	}
	if len(c.ValueHash) > 8 {
		item.ValueHash = c.ValueHash[:8]
	} else {
		item.ValueHash = c.ValueHash
	}
	return item
}

// MismatchItem 是漂移记录的对外视图。
type MismatchItem struct {
	ID         int64  `json:"id"`
	AppID      int64  `json:"app_id"`
	ClaimID    int64  `json:"claim_id"`
	IdentityID int64  `json:"identity_id"`
	ClaimType  string `json:"claim_type"`
	// 仍只回前缀，理由同 ClaimItem。
	ValueHash   string `json:"value_hash_prefix,omitempty"`
	Platform    string `json:"platform"`
	ClaimSource string `json:"claim_source"`
	Kind        string `json:"kind"`
	// ExpectedUserID / ActualUserID 是分叉的两侧，任一可能为空。
	ExpectedUserID string     `json:"expected_user_id,omitempty"`
	ActualUserID   string     `json:"actual_user_id,omitempty"`
	Detail         string     `json:"detail,omitempty"`
	Status         string     `json:"status"`
	Occurrences    int        `json:"occurrences"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy     string     `json:"resolved_by,omitempty"`
	Resolution     string     `json:"resolution,omitempty"`
}

func toMismatchItem(m *identity.Mismatch) MismatchItem {
	item := MismatchItem{
		ID:             m.ID,
		AppID:          m.AppID,
		ClaimID:        m.ClaimID,
		IdentityID:     m.IdentityID,
		ClaimType:      m.ClaimType,
		Platform:       m.Platform,
		ClaimSource:    m.ClaimSource,
		Kind:           m.Kind,
		ExpectedUserID: m.ExpectedUserID,
		ActualUserID:   m.ActualUserID,
		Detail:         m.Detail,
		Status:         m.Status,
		Occurrences:    m.Occurrences,
		FirstSeenAt:    m.FirstSeenAt,
		LastSeenAt:     m.LastSeenAt,
		ResolvedAt:     m.ResolvedAt,
		ResolvedBy:     m.ResolvedBy,
		Resolution:     m.Resolution,
	}
	if len(m.ValueHash) > 8 {
		item.ValueHash = m.ValueHash[:8]
	} else {
		item.ValueHash = m.ValueHash
	}
	return item
}

// principalSubject 返回审计主体标识（与 writeAudit 内部同一口径）。
func principalSubject(p *admin.Principal) string {
	if p != nil && p.User != nil {
		return fmt.Sprintf("admin:%d", p.User.ID)
	}
	return "admin:anonymous"
}
