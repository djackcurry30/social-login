// Package account 提供 AccountProvider SPI 的实现。
//
// 第一期交付 StubAccountProvider：用户中心尚未就位，但接口不将就——
// 应用层依赖的是 account.Provider 端口，等用户中心好了换成 HTTPAccountProvider
// 即可，业务逻辑零改动（架构 §13 第一期）。
package account

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// StubProvider 是内存实现的账号提供者，仅供开发与集成测试使用。
//
// 它刻意实现了完整语义（含幂等键、状态、claim 反查、按类型替换），而不是只
// 返回固定值——这样集成测试才能真正覆盖"首次登录 → 引导注册 → 绑定 → 签发令牌"
// 的链路，而不会因为桩太简单而在接入真实用户中心时才发现问题。
//
// 内部按 appKey 分区（与真实用户中心同构）。这一条不是"顺手做的隔离"：
// 如果桩是全局的，测试里两个应用会共用账号空间，而生产行为是按应用隔离——
// 桩与真实实现的分歧恰好落在最容易出事的地方（跨应用串号）。
//
// ⚠️ 生产环境必须替换为 HTTPAccountProvider，并通过配置显式断言
// （见 bootstrap 的启动自检），避免桩实现被误带上线。
type StubProvider struct {
	mu   sync.RWMutex
	apps map[string]*appSpace
	// seq 是全局递增，保证 user_id 在各应用间也不重复，便于日志排查。
	seq int
}

// appSpace 是一个应用的账号空间。
type appSpace struct {
	byID    map[string]*domainaccount.Account
	byClaim map[string]string // claimKey → userID
	// merges 记录幂等键 → 结果，用于验证 P0-4 的幂等语义。
	merges map[string]*domainaccount.MergeResult
}

func newAppSpace() *appSpace {
	return &appSpace{
		byID:    make(map[string]*domainaccount.Account),
		byClaim: make(map[string]string),
		merges:  make(map[string]*domainaccount.MergeResult),
	}
}

// NewStubProvider 构造内存账号提供者。
func NewStubProvider() *StubProvider {
	return &StubProvider{apps: make(map[string]*appSpace)}
}

var (
	_ domainaccount.Provider      = (*StubProvider)(nil)
	_ domainaccount.ClaimReplacer = (*StubProvider)(nil)
)

// space 返回某应用的空间，不存在时创建。调用方必须持锁。
func (s *StubProvider) space(appKey string) *appSpace {
	sp, ok := s.apps[appKey]
	if !ok {
		sp = newAppSpace()
		s.apps[appKey] = sp
	}
	return sp
}

// Get 按 user_id 查询账号。
func (s *StubProvider) Get(_ context.Context, appKey, userID string) (*domainaccount.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sp, ok := s.apps[appKey]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	acc, ok := sp.byID[userID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	return cloneAccount(acc), nil
}

// GetByClaim 按已验证凭证反查账号。
func (s *StubProvider) GetByClaim(_ context.Context, appKey string, claim domainaccount.Claim) (*domainaccount.Account, error) {
	if claim.Type == "" || claim.Value == "" {
		return nil, errs.New(errs.CodeInternal, "凭证反查缺少类型或取值")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sp, ok := s.apps[appKey]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	userID, ok := sp.byClaim[claimKey(claim.Type, claim.Value)]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	acc, ok := sp.byID[userID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	return cloneAccount(acc), nil
}

// Create 创建账号，按 IdempotencyKey 去重。
func (s *StubProvider) Create(_ context.Context, req domainaccount.CreateRequest) (*domainaccount.Account, error) {
	if req.AppKey == "" {
		return nil, errs.New(errs.CodeInternal, "Create 缺少 app_key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sp := s.space(req.AppKey)

	// 幂等：同一个幂等键重复创建时返回既有账号。
	// 真实用户中心必须实现同样的语义，否则接入方重试会产生重复账号。
	if req.IdempotencyKey != "" {
		for _, acc := range sp.byID {
			if acc.Extra != nil && acc.Extra["idempotency_key"] == req.IdempotencyKey {
				return cloneAccount(acc), nil
			}
		}
	}

	// 若任一已验证凭证已存在，视为同一账号（等价于用户中心的"按手机号识别老用户"）。
	for _, c := range req.Claims {
		if c.Value == "" {
			continue
		}
		if userID, ok := sp.byClaim[claimKey(c.Type, c.Value)]; ok {
			return cloneAccount(sp.byID[userID]), nil
		}
	}

	s.seq++
	userID := "u_stub_" + strconv.Itoa(s.seq) + "_" + randomSuffix(4)
	acc := &domainaccount.Account{
		UserID: userID,
		Status: domainaccount.StatusActive,
		Claims: req.Claims,
		Extra: map[string]any{
			"app_key":         req.AppKey,
			"idempotency_key": req.IdempotencyKey,
			"nickname":        req.Nickname,
			"avatar_url":      req.AvatarURL,
			"created_at":      time.Now().UTC().Format(time.RFC3339),
		},
	}
	sp.byID[userID] = acc
	for _, c := range req.Claims {
		if c.Value != "" {
			sp.byClaim[claimKey(c.Type, c.Value)] = userID
		}
	}
	return cloneAccount(acc), nil
}

// Merge 把 source 合并进 target。
//
// 幂等键必须生效（修正 P0-4）：补偿任务会用同一个键重试，若不去重就会重复执行。
func (s *StubProvider) Merge(_ context.Context, req domainaccount.MergeRequest) (*domainaccount.MergeResult, error) {
	if req.AppKey == "" {
		return nil, errs.New(errs.CodeInternal, "Merge 缺少 app_key")
	}
	if req.IdempotencyKey == "" {
		// 幂等键是硬性要求，不允许缺失——缺了就退化成"可能被重复执行"。
		return nil, errs.New(errs.CodeInternal, "Merge 缺少幂等键（P0-4 要求）")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sp := s.space(req.AppKey)

	if prev, ok := sp.merges[req.IdempotencyKey]; ok {
		clone := *prev
		clone.Merged = false
		clone.AlreadyMerged = true
		return &clone, nil
	}

	if req.TargetUserID == req.SourceUserID {
		return nil, errs.New(errs.CodeInvalidRequest, "不能把账号合并到它自己")
	}
	target, ok := sp.byID[req.TargetUserID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	source, ok := sp.byID[req.SourceUserID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}

	// 凭证按【类型】目标优先：target 已有该类型（哪怕号不同）时，source 的
	// 这条只能撤销——一个账号每类凭证只允许一条活跃。
	occupied := make(map[string]bool, len(target.Claims))
	for _, c := range target.Claims {
		occupied[c.Type] = true
	}
	var discarded []domainaccount.Claim
	for _, c := range source.Claims {
		if occupied[c.Type] {
			discarded = append(discarded, c)
			continue
		}
		occupied[c.Type] = true
		target.Claims = append(target.Claims, c)
	}
	// 反向索引跟着走：迁移的指向 target，丢弃的删除（撤销即释放）。
	for _, c := range source.Claims {
		if c.Value == "" {
			continue
		}
		k := claimKey(c.Type, c.Value)
		if isDiscarded(discarded, c) {
			delete(sp.byClaim, k)
			continue
		}
		sp.byClaim[k] = target.UserID
	}

	source.Claims = nil
	source.Status = domainaccount.StatusClosed
	if source.Extra == nil {
		source.Extra = map[string]any{}
	}
	source.Extra["merged_into"] = target.UserID

	result := &domainaccount.MergeResult{
		Merged:          true,
		DiscardedClaims: discarded,
		RemoteRef: map[string]any{
			"target_user_id": target.UserID,
			"source_user_id": source.UserID,
			"reason":         req.Reason,
			"merged_at":      time.Now().UTC().Format(time.RFC3339),
		},
	}
	sp.merges[req.IdempotencyKey] = result
	clone := *result
	return &clone, nil
}

// ReplaceClaim 换绑某类型凭证。
func (s *StubProvider) ReplaceClaim(_ context.Context, req domainaccount.ReplaceClaimRequest) (*domainaccount.Account, error) {
	if req.AppKey == "" {
		return nil, errs.New(errs.CodeInternal, "ReplaceClaim 缺少 app_key")
	}
	if req.UserID == "" || req.Claim.Type == "" || req.Claim.Value == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "换绑缺少 user_id / claim_type / value")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sp := s.space(req.AppKey)

	acc, ok := sp.byID[req.UserID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	newKey := claimKey(req.Claim.Type, req.Claim.Value)

	// 新值已被其他账号占用：不动本账号的任何数据。
	if owner, ok := sp.byClaim[newKey]; ok && owner != acc.UserID {
		return nil, errs.New(errs.CodeBindIdentityTaken,
			"该凭证已被用户中心的另一个账号占用").
			WithDetail("claim_type", req.Claim.Type)
	}
	// 新值已经是本账号当前的同类凭证：幂等 no-op。
	for _, c := range acc.Claims {
		if c.Type == req.Claim.Type && claimKey(c.Type, c.Value) == newKey {
			return cloneAccount(acc), nil
		}
	}

	// 撤销本账号该类型的旧凭证，再插入新值。
	next := make([]domainaccount.Claim, 0, len(acc.Claims)+1)
	for _, c := range acc.Claims {
		if c.Type == req.Claim.Type {
			delete(sp.byClaim, claimKey(c.Type, c.Value))
			continue
		}
		next = append(next, c)
	}
	next = append(next, req.Claim)
	acc.Claims = next
	sp.byClaim[newKey] = acc.UserID
	return cloneAccount(acc), nil
}

// SetClaims 直接设置某账号的已验证凭证，供测试构造"用户中心里已有该手机号"的场景。
//
// 会清掉该账号原有的反向索引：否则测试里改完凭证后，按旧号码仍能反查到它，
// 而真实用户中心不会这样。
func (s *StubProvider) SetClaims(appKey, userID string, claims []domainaccount.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, ok := s.apps[appKey]
	if !ok {
		return domainaccount.ErrNotFound
	}
	acc, ok := sp.byID[userID]
	if !ok {
		return domainaccount.ErrNotFound
	}
	for _, c := range acc.Claims {
		if c.Value != "" {
			delete(sp.byClaim, claimKey(c.Type, c.Value))
		}
	}
	acc.Claims = claims
	for _, c := range claims {
		if c.Value != "" {
			sp.byClaim[claimKey(c.Type, c.Value)] = userID
		}
	}
	return nil
}

// Seed 预置一个账号，供测试与本地联调使用。
func (s *StubProvider) Seed(appKey, userID string, claims []domainaccount.Claim) *domainaccount.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp := s.space(appKey)
	acc := &domainaccount.Account{
		UserID: userID,
		Status: domainaccount.StatusActive,
		Claims: claims,
		Extra:  map[string]any{"app_key": appKey},
	}
	sp.byID[userID] = acc
	for _, c := range claims {
		if c.Value != "" {
			sp.byClaim[claimKey(c.Type, c.Value)] = userID
		}
	}
	return acc
}

func isDiscarded(discarded []domainaccount.Claim, c domainaccount.Claim) bool {
	for _, d := range discarded {
		if d.Type == c.Type && d.Value == c.Value {
			return true
		}
	}
	return false
}

func claimKey(claimType, value string) string {
	return claimType + "|" + identity.Normalize(claimType, value)
}

func cloneAccount(a *domainaccount.Account) *domainaccount.Account {
	if a == nil {
		return nil
	}
	out := *a
	out.Claims = append([]domainaccount.Claim(nil), a.Claims...)
	out.Extra = make(map[string]any, len(a.Extra))
	for k, v := range a.Extra {
		out.Extra[k] = v
	}
	return &out
}

func randomSuffix(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "0000"
	}
	return hex.EncodeToString(buf)[:n]
}
