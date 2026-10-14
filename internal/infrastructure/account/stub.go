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

	domainaccount "github.com/alex/social-login/internal/domain/account"
	"github.com/alex/social-login/internal/domain/identity"
	"github.com/alex/social-login/internal/pkg/errs"
)

// StubProvider 是内存实现的账号提供者，仅供开发与集成测试使用。
//
// 它刻意实现了完整语义（含幂等键、状态、claim 反查），而不是只返回固定值——
// 这样集成测试才能真正覆盖"首次登录 → 引导注册 → 绑定 → 签发令牌"的链路，
// 而不会因为桩太简单而在接入真实用户中心时才发现问题。
//
// ⚠️ 生产环境必须替换为 HTTPAccountProvider，并通过配置显式断言
// （见 bootstrap 的启动自检），避免桩实现被误带上线。
type StubProvider struct {
	mu      sync.RWMutex
	byID    map[string]*domainaccount.Account
	byClaim map[string]string // claimKey → userID
	// merges 记录幂等键 → 结果，用于验证 P0-4 的幂等语义。
	merges map[string]*domainaccount.MergeResult
	seq    int
}

// NewStubProvider 构造内存账号提供者。
func NewStubProvider() *StubProvider {
	return &StubProvider{
		byID:    make(map[string]*domainaccount.Account),
		byClaim: make(map[string]string),
		merges:  make(map[string]*domainaccount.MergeResult),
	}
}

var _ domainaccount.Provider = (*StubProvider)(nil)

// Get 按 user_id 查询账号。
func (s *StubProvider) Get(_ context.Context, userID string) (*domainaccount.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	acc, ok := s.byID[userID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	return cloneAccount(acc), nil
}

// GetByClaim 按已验证凭证反查账号。
func (s *StubProvider) GetByClaim(_ context.Context, claim domainaccount.Claim) (*domainaccount.Account, error) {
	if claim.Type == "" || claim.Value == "" {
		return nil, errs.New(errs.CodeInternal, "凭证反查缺少类型或取值")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID, ok := s.byClaim[claimKey(claim.Type, claim.Value)]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	acc, ok := s.byID[userID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	return cloneAccount(acc), nil
}

// Create 创建账号，按 IdempotencyKey 去重。
func (s *StubProvider) Create(_ context.Context, req domainaccount.CreateRequest) (*domainaccount.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 幂等：同一个幂等键重复创建时返回既有账号。
	// 真实用户中心必须实现同样的语义，否则接入方重试会产生重复账号。
	if req.IdempotencyKey != "" {
		for _, acc := range s.byID {
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
		if userID, ok := s.byClaim[claimKey(c.Type, c.Value)]; ok {
			return cloneAccount(s.byID[userID]), nil
		}
	}

	s.seq++
	userID := "u_stub_" + strconv.Itoa(s.seq) + "_" + randomSuffix(4)
	acc := &domainaccount.Account{
		UserID: userID,
		Status: domainaccount.StatusActive,
		Claims: req.Claims,
		Extra: map[string]any{
			"idempotency_key": req.IdempotencyKey,
			"nickname":        req.Nickname,
			"avatar_url":      req.AvatarURL,
			"created_at":      time.Now().UTC().Format(time.RFC3339),
		},
	}
	s.byID[userID] = acc
	for _, c := range req.Claims {
		if c.Value != "" {
			s.byClaim[claimKey(c.Type, c.Value)] = userID
		}
	}
	return cloneAccount(acc), nil
}

// Merge 把 source 合并进 target。
//
// 幂等键必须生效（修正 P0-4）：补偿任务会用同一个键重试，若不去重就会重复执行。
func (s *StubProvider) Merge(_ context.Context, req domainaccount.MergeRequest) (*domainaccount.MergeResult, error) {
	if req.IdempotencyKey == "" {
		// 幂等键是硬性要求，不允许缺失——缺了就退化成"可能被重复执行"。
		return nil, errs.New(errs.CodeInternal, "Merge 缺少幂等键（P0-4 要求）")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if prev, ok := s.merges[req.IdempotencyKey]; ok {
		clone := *prev
		clone.Merged = false
		clone.AlreadyMerged = true
		return &clone, nil
	}

	target, ok := s.byID[req.TargetUserID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	source, ok := s.byID[req.SourceUserID]
	if !ok {
		return nil, domainaccount.ErrNotFound
	}
	if req.TargetUserID == req.SourceUserID {
		return nil, errs.New(errs.CodeInvalidRequest, "不能把账号合并到它自己")
	}

	// 迁移凭证归属，并把 source 标记为已合并。
	for _, c := range source.Claims {
		if c.Value != "" {
			s.byClaim[claimKey(c.Type, c.Value)] = target.UserID
		}
	}
	target.Claims = append(target.Claims, source.Claims...)
	source.Status = domainaccount.StatusClosed
	source.Extra["merged_into"] = target.UserID

	result := &domainaccount.MergeResult{
		Merged: true,
		RemoteRef: map[string]any{
			"target_user_id": target.UserID,
			"source_user_id": source.UserID,
			"reason":         req.Reason,
			"merged_at":      time.Now().UTC().Format(time.RFC3339),
		},
	}
	s.merges[req.IdempotencyKey] = result
	clone := *result
	return &clone, nil
}

// SetClaims 直接设置某账号的已验证凭证，供测试构造"用户中心里已有该手机号"的场景。
func (s *StubProvider) SetClaims(userID string, claims []domainaccount.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.byID[userID]
	if !ok {
		return domainaccount.ErrNotFound
	}
	acc.Claims = claims
	for _, c := range claims {
		if c.Value != "" {
			s.byClaim[claimKey(c.Type, c.Value)] = userID
		}
	}
	return nil
}

// Seed 预置一个账号，供测试与本地联调使用。
func (s *StubProvider) Seed(userID string, claims []domainaccount.Claim) *domainaccount.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := &domainaccount.Account{
		UserID: userID,
		Status: domainaccount.StatusActive,
		Claims: claims,
		Extra:  map[string]any{},
	}
	s.byID[userID] = acc
	for _, c := range claims {
		if c.Value != "" {
			s.byClaim[claimKey(c.Type, c.Value)] = userID
		}
	}
	return acc
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
