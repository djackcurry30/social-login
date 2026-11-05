package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// CreateRequest 是建号请求。
type CreateRequest struct {
	// IdempotencyKey 由调用方提供（首次登录的稳定键）。
	IdempotencyKey string
	Claims         []domain.Claim
	Nickname       string
	AvatarURL      string
}

// CreateOutcome 是建号结果。
type CreateOutcome struct {
	Account *domain.Account
	// Replayed 表示命中幂等键，本次没有新建账号。
	Replayed bool
}

// Create 建号。
//
// 允许 claims 为空：有的渠道首登拿不到手机号/邮箱，先建一个"空账号"再
// 由后续绑定流程补凭证是合法的。但空 claims 的账号无法被 by-claim 找到，
// 所以它只能靠 user_id 引用——调用方要自己记住这一点。
func (s *Service) Create(ctx context.Context, app domain.App, req CreateRequest) (*CreateOutcome, error) {
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		// 缺幂等键必须失败：首次登录可能因接入方重试而调用两次，
		// 没有幂等键就会建出两个账号，而这两个账号此后只能靠人工合并。
		return nil, domain.New(domain.CodeInvalid, "缺少 Idempotency-Key：建号必须幂等")
	}

	normalized, err := normalizeClaims(req.Claims)
	if err != nil {
		return nil, err
	}
	inputs, err := s.buildClaimInputs(app.ID, normalized)
	if err != nil {
		return nil, err
	}

	res, err := s.store.CreateAccount(ctx, postgres.CreateInput{
		AppID:       app.ID,
		AppKey:      app.Key,
		IdemKey:     req.IdempotencyKey,
		RequestHash: requestHashOf(normalized, req.Nickname, req.AvatarURL),
		PublicID:    s.newID(),
		Nickname:    req.Nickname,
		AvatarURL:   req.AvatarURL,
		Claims:      inputs,
		// 账号创建是数据主体生命周期上的第一个事件，必须留痕。
		Audit: s.auditFor(ctx, app, postgres.AuditAccountCreated, "", map[string]any{
			"claim_types": claimTypesOf(normalized),
		}),
	})
	if err != nil {
		if e, ok := domain.As(err); ok && e.Code == domain.CodeClaimTaken {
			s.m.RecordConflict(app.Key, "create")
		}
		return nil, err
	}

	if res.Replayed {
		s.m.RecordReplay(app.Key)
		s.log.Info("建号幂等重放",
			zap.String("app_key", app.Key),
			zap.String("user_id", res.PublicID))
	} else {
		s.m.RecordCreated(app.Key)
		s.log.Info("账号已创建",
			zap.String("app_key", app.Key),
			zap.String("user_id", res.PublicID),
			zap.Int("claims", len(normalized)))
	}

	// 响应里的凭证用归一化后的值：调用方传 +86 138-0000-0000 时，
	// 返回 13800000000 才是"库里实际存的那个"，也才能让后续 by-claim 对得上。
	return &CreateOutcome{
		Account: &domain.Account{
			UserID:    res.PublicID,
			Status:    res.Status,
			Claims:    normalized,
			Nickname:  req.Nickname,
			AvatarURL: req.AvatarURL,
		},
		Replayed: res.Replayed,
	}, nil
}

// Get 按 user_id 查账号。
func (s *Service) Get(ctx context.Context, app domain.App, userID string) (*domain.Account, error) {
	if strings.TrimSpace(userID) == "" {
		// 空 id 会拼出 /accounts/ 这样的路径，落到"列出账号"或 404 两种
		// 都很危险的实现上；在本地拒绝。
		return nil, domain.New(domain.CodeInvalid, "缺少 user_id")
	}
	snap, err := s.store.GetAccount(ctx, app.ID, userID)
	if err != nil {
		return nil, err
	}
	return s.toAccount(snap), nil
}

// GetByClaim 按已验证凭证反查账号（强一致读）。
//
// 注意这里【只做归一化，不做格式校验】：
//
//	by-claim 的语义是"有没有账号持有这个值"。传一个根本不像手机号的值
//	（__nobody_123）时，正确答案是 404「没有账号持有」，而不是 400
//	「参数不合法」——后者会泄漏"我们判断了它像不像手机号"这层信息，
//	也会让消费方把一次正常的"未命中"当成自己的参数 bug。
//
//	建号与换绑则必须校验：垃圾值一旦入库，会占住唯一索引，
//	表现为"某个真实号码注册时提示已被占用"，而占用者是空字符串。
func (s *Service) GetByClaim(ctx context.Context, app domain.App, claimType, value string) (*domain.Account, error) {
	if !domain.IsValidClaimType(claimType) {
		return nil, domain.Newf(domain.CodeInvalid, "不支持的凭证类型: %q", claimType)
	}
	normalized := domain.Normalize(claimType, value)
	if normalized == "" {
		// 归一化后为空（例如 phone 传了一串字母）→ 无法表达"查什么"。
		return nil, domain.New(domain.CodeInvalid, "凭证值为空：归一化后没有任何有效字符")
	}
	snap, err := s.store.FindByClaim(ctx, app.ID, claimType,
		s.hasher.Hash(app.ID, claimType, normalized))
	if err != nil {
		return nil, err
	}
	return s.toAccount(snap), nil
}

// MergeRequest 是合并请求。
type MergeRequest struct {
	IdempotencyKey string
	TargetUserID   string
	SourceUserID   string
	Reason         string
}

// MergeOutcome 是合并结果（字段名与契约报文一致）。
type MergeOutcome struct {
	Merged          bool           `json:"merged"`
	AlreadyMerged   bool           `json:"already_merged"`
	DiscardedClaims []domain.Claim `json:"discarded_claims,omitempty"`
	TargetUserID    string         `json:"target_user_id,omitempty"`
	SourceUserID    string         `json:"source_user_id,omitempty"`
}

// Merge 把 source 合并进 target。
func (s *Service) Merge(ctx context.Context, app domain.App, req MergeRequest) (*MergeOutcome, error) {
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		// 补偿任务会重试合并。不幂等的 Merge 会重复迁移数据——第一次迁移，
		// 第二次"看起来成功"但实际什么都没做，却让调用方以为又合并了一次。
		return nil, domain.New(domain.CodeInvalid, "缺少 Idempotency-Key：合并必须幂等")
	}
	if strings.TrimSpace(req.TargetUserID) == "" || strings.TrimSpace(req.SourceUserID) == "" {
		return nil, domain.New(domain.CodeInvalid, "缺少 target_user_id 或 source_user_id")
	}

	res, err := s.store.MergeAccounts(ctx, postgres.MergeInput{
		AppID:          app.ID,
		IdemKey:        req.IdempotencyKey,
		TargetPublicID: req.TargetUserID,
		SourcePublicID: req.SourceUserID,
		Reason:         req.Reason,
		Audit: s.auditFor(ctx, app, postgres.AuditAccountMerged, req.TargetUserID, map[string]any{
			"trigger": "merge",
		}),
	})
	if err != nil {
		if e, ok := domain.As(err); ok && e.Code == domain.CodeMergeRejected {
			s.m.RecordMerge(app.Key, "rejected")
		}
		return nil, err
	}

	out := &MergeOutcome{
		Merged:          res.Merged,
		AlreadyMerged:   res.AlreadyMerged,
		TargetUserID:    res.TargetPublicID,
		SourceUserID:    res.SourcePublicID,
		DiscardedClaims: s.decryptAll(res.Discarded),
	}
	if res.Merged {
		s.m.RecordMerge(app.Key, "merged")
		s.log.Info("账号已合并",
			zap.String("app_key", app.Key),
			zap.String("target", res.TargetPublicID),
			zap.String("source", res.SourcePublicID),
			zap.Int("discarded_claims", len(out.DiscardedClaims)))
	} else if res.AlreadyMerged {
		s.m.RecordMerge(app.Key, "already_merged")
	}
	return out, nil
}

// ReplaceClaim 换绑某类型凭证。
//
// P0 只把接口做出来并自测；真正由 social-login 在登录链路里发现"平台侧
// 手机号变了"时调用，属 P1（§5.4）。
func (s *Service) ReplaceClaim(ctx context.Context, app domain.App, userID, claimType, value, source string) (*domain.Account, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, domain.New(domain.CodeInvalid, "缺少 user_id")
	}
	if !domain.IsValidClaimType(claimType) {
		return nil, domain.Newf(domain.CodeInvalid, "不支持的凭证类型: %q", claimType)
	}
	normalized := domain.Normalize(claimType, value)
	if err := domain.ValidateClaimValue(claimType, normalized); err != nil {
		return nil, err
	}

	inputs, err := s.buildClaimInputs(app.ID, []domain.Claim{
		{Type: claimType, Value: normalized, Source: defaultSource(source)},
	})
	if err != nil {
		return nil, err
	}

	// 动作名（绑定 / 换绑）由 store 判定：只有它知道这次是首次绑定还是覆盖。
	// 这里只给触发者与元信息。
	audit := s.auditFor(ctx, app, postgres.AuditClaimBound, userID, map[string]any{})
	if err := s.store.ReplaceClaim(ctx, app.ID, userID, inputs[0], audit); err != nil {
		if e, ok := domain.As(err); ok &&
			(e.Code == domain.CodeClaimTaken || e.Code == domain.CodeConflict) {
			s.m.RecordConflict(app.Key, "replace")
		}
		return nil, err
	}

	s.log.Info("凭证已换绑",
		zap.String("app_key", app.Key),
		zap.String("user_id", userID),
		zap.String("claim_type", claimType))
	return s.Get(ctx, app, userID)
}

// Close 关闭账号并撤销全部凭证。
func (s *Service) Close(ctx context.Context, app domain.App, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return domain.New(domain.CodeInvalid, "缺少 user_id")
	}
	audit := s.auditFor(ctx, app, postgres.AuditAccountClosed, userID, nil)
	if err := s.store.CloseAccount(ctx, app.ID, userID, audit); err != nil {
		return err
	}
	s.m.RecordClosed(app.Key)
	s.log.Info("账号已关闭", zap.String("app_key", app.Key), zap.String("user_id", userID))
	return nil
}

// --- 内部 ---

// toAccount 把存储快照转成对外视图（解密凭证）。
//
// 单条凭证解不开时跳过并记 error，而不是让整个账号读失败：
// 解密失败通常意味着某次密钥配置出错，受影响的可能是一批账号。让这些账号
// 完全不可读（登录直接 500）比"少返回一条凭证"的危害大得多——
// 后者只会让漂移检测多报一条，前者是整站登录不可用。
func (s *Service) toAccount(snap *postgres.Snapshot) *domain.Account {
	acc := snap.Account
	acc.Claims = s.decryptAll(snap.Claims)
	return &acc
}

// decryptAll 解密凭证列表，跳过坏行。
func (s *Service) decryptAll(records []domain.ClaimRecord) []domain.Claim {
	out := make([]domain.Claim, 0, len(records))
	for _, r := range records {
		v, err := s.env.Open(r.ValueCipher, r.DEKID)
		if err != nil {
			s.log.Error("凭证解密失败，已跳过该条",
				zap.Int64("claim_id", r.ID),
				zap.String("claim_type", r.Type),
				zap.String("dek_id", r.DEKID),
				zap.Error(err))
			continue
		}
		out = append(out, domain.Claim{Type: r.Type, Value: v, Source: r.Source})
	}
	return out
}

// normalizeClaims 校验并归一化请求里的凭证。
//
// 同类型重复直接拒绝：一个账号每类只能有一条（§12.1 决策 2）。
// 数据库的 uk_claim_one_per_type 也能挡住，但那会以"唯一冲突"的形式出现，
// 看起来像并发问题；这里能给出"请求里传了两条手机号"这个准确原因。
func normalizeClaims(in []domain.Claim) ([]domain.Claim, error) {
	out := make([]domain.Claim, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, c := range in {
		if !domain.IsValidClaimType(c.Type) {
			return nil, domain.Newf(domain.CodeInvalid, "不支持的凭证类型: %q", c.Type)
		}
		if seen[c.Type] {
			return nil, domain.Newf(domain.CodeInvalid,
				"同一请求包含多条 %s 凭证：一个账号每类凭证只能有一条", c.Type)
		}
		seen[c.Type] = true

		v := domain.Normalize(c.Type, c.Value)
		if err := domain.ValidateClaimValue(c.Type, v); err != nil {
			return nil, err
		}
		out = append(out, domain.Claim{Type: c.Type, Value: v, Source: defaultSource(c.Source)})
	}
	return out, nil
}

// defaultSource 给缺省来源一个保守值。
//
// "manual" 在 social-login 的可信来源白名单之外（R4 红线 1）：
// 来源不明的凭证一律不参与自动归并。缺省成 wechat_phone 之类的可信来源
// 会凭空造出一条"用户手填的手机号可以自动归并"的账号劫持路径。
func defaultSource(source string) string {
	s := strings.TrimSpace(source)
	if s == "" {
		return "manual"
	}
	return s
}

// buildClaimInputs 计算 hash 与密文。
func (s *Service) buildClaimInputs(appID int64, claims []domain.Claim) ([]postgres.ClaimInput, error) {
	out := make([]postgres.ClaimInput, 0, len(claims))
	for _, c := range claims {
		cipher, err := s.env.Seal(c.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, postgres.ClaimInput{
			Type:        c.Type,
			ValueHash:   s.hasher.Hash(appID, c.Type, c.Value),
			HashVersion: s.hasher.Version(),
			ValueCipher: cipher,
			DEKID:       s.env.CurrentDEKID(),
			Source:      defaultSource(c.Source),
		})
	}
	return out, nil
}

// requestHashOf 计算幂等请求体指纹。
//
// 顺序：claims 先按 (type, value) 排序再哈希——否则 "手机号在前"
// 与 "邮箱在前" 会被当成不同请求体，从而拒绝一次本应重放的调用。
// 用归一化后的值参与计算，保证 "+86 138..." 与 "138..." 视为同一个请求。
func requestHashOf(claims []domain.Claim, nickname, avatarURL string) []byte {
	sorted := append([]domain.Claim(nil), claims...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].Value < sorted[j].Value
	})

	payload, _ := json.Marshal(struct {
		Claims    []domain.Claim `json:"claims"`
		Nickname  string         `json:"nickname"`
		AvatarURL string         `json:"avatar_url"`
	}{Claims: sorted, Nickname: nickname, AvatarURL: avatarURL})

	sum := sha256.Sum256(payload)
	return sum[:]
}
