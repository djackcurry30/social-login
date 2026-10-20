// Package adminapp 是管理端"应用与策略（A 组）"用例。
//
// 职责严格按 §15.4 A 组限定：
//   - apps CRUD + secret:rotate
//   - policy 读取 / 保存 / 校验
//
// 所有写操作自动写 admin_audit_logs（A 组是高危操作清单，强制 reason）。
package adminapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Deps 是用例依赖。
type Deps struct {
	TenantApps tenant.ApplicationRepository
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
	// Now 用于审计时间；测试时可注入。
	Now func() time.Time
	// ListAppIDs 注入仓储层"列出最近 N 个应用 id"的能力。
	// 本期简化：admin 端不提供应用列表分页（生产应接上游仓储 List 方法），
	// 留 ListAppIDs 为 nil 时 GetApp / ListApps 走"按 ID 直查"。
	ListAppIDs func(ctx context.Context, limit int) ([]int64, error)
	// HashSecret 注入密钥哈希逻辑。生产使用 crypto.AppSecretHasher；
	// 测试可用伪实现。
	HashSecret func(plain string) (string, error)
	// EncryptSecret 加密 webhook 签名密钥（注入 KeyManager，避免本包依赖 infra/crypto）。
	//
	// 为什么 webhook 密钥要加密而不是像 app_secret 那样只存哈希：
	// HMAC 签名需要【明文】密钥参与运算，哈希是单向的，用不了。
	EncryptSecret func(plain string) (ciphertext []byte, dekID string, err error)
	// SetWebhook 保存投递配置（仓储方法按需注入，避免撑大 tenant.ApplicationRepository 接口）。
	SetWebhook func(ctx context.Context, appID int64, url string, secretEnc []byte, kid string) error
	// GetWebhook 读取当前投递配置，仅用于写审计的 before 快照
	// （排障时"改之前是哪个地址"往往比"改成什么"更有用）。
	GetWebhook func(ctx context.Context, appID int64) (appCode, url string, secretEnc []byte, kid string, err error)
}

// Service 是 A 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.HashSecret == nil {
		d.HashSecret = defaultHashSecret
	}
	return &Service{deps: d}
}

// CreateAppInput 是 POST /admin/v1/apps 的入参。
type CreateAppInput struct {
	Name        string           `json:"name" binding:"required"`
	AccountMode string           `json:"account_mode"` // 留空 = remote
	Policy      *tenant.Policy   `json:"policy,omitempty"`
	Reason      string           `json:"reason" binding:"required"` // 高危操作必填
	Principal   *admin.Principal // 解析自中间件；写审计用
}

// AppView 是应用在管理端接口上的对外投影。
//
// 为什么不直接返回 *tenant.Application：领域模型里带 AppSecretHash，
// 而 JSON 序列化默认导出全部字段——此前 GET /admin/v1/apps 就把 app_secret
// 的哈希原样发给了 viewer 角色。哈希虽不可逆，但它是对外验签密钥的全部
// 秘密所在，泄露后可用于离线爆破，属于【不必要的暴露】。
//
// 这里改成显式白名单：新增内部字段时默认不外发，要外发必须在这里加一行。
// 这是"默认拒绝"与"默认放行"的差别，也正是当初漏掉它的原因。
//
// ⚠️ 字段的 JSON key 沿用 Go 字段名（大驼峰），是为了不破坏现有前端
// （web/src/lib/types.ts 与 AppsPage/AppDetailPage 都按 `AppCode` 读取）。
// 与项目其它接口的 snake_case 不一致属于历史包袱，统一改造需单独排期。
type AppView struct {
	ID          int64         `json:"ID"`
	AppCode     string        `json:"AppCode"`
	Name        string        `json:"Name"`
	Status      int16         `json:"Status"`
	AccountMode string        `json:"AccountMode"`
	Policy      tenant.Policy `json:"Policy"`
	CreatedAt   time.Time     `json:"CreatedAt"`
	UpdatedAt   time.Time     `json:"UpdatedAt"`
}

// toAppView 把领域模型投影成对外视图（白名单，天然屏蔽 AppSecretHash）。
func toAppView(a *tenant.Application) *AppView {
	if a == nil {
		return nil
	}
	return &AppView{
		ID:          a.ID,
		AppCode:     a.AppCode,
		Name:        a.Name,
		Status:      a.Status,
		AccountMode: a.AccountMode,
		Policy:      a.Policy,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
}

// CreateAppOutput 是 POST /admin/v1/apps 的出参。
type CreateAppOutput struct {
	App *AppView `json:"app"`
	// AppSecret 是明文密钥，【仅在创建时】返回一次，不入库、不再次下发。
	AppSecret string `json:"app_secret"`
}

// CreateApp 创建应用。
//
// 生成 app_code（16 字节随机 hex）与 app_secret（32 字节随机 hex）；
// app_secret 一次性展示，存库只存哈希。
func (s *Service) CreateApp(ctx context.Context, in CreateAppInput) (*CreateAppOutput, error) {
	if in.Name == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "name 不能为空")
	}
	if in.AccountMode == "" {
		in.AccountMode = tenant.AccountModeRemote
	}
	if in.AccountMode != tenant.AccountModeRemote {
		return nil, errs.Newf(errs.CodeConfigInvalid,
			"account_mode=%s 与约束 C4（remote）不符", in.AccountMode).
			WithDetail("account_mode", in.AccountMode)
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（app.create）必须填写 reason（≥4 字符）")
	}

	secret, err := generateAppSecret()
	if err != nil {
		return nil, err
	}
	secretHash, err := s.deps.HashSecret(secret)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "哈希 app_secret 失败", err)
	}

	policy := tenant.DefaultPolicy()
	if in.Policy != nil {
		check, err := in.Policy.Validate()
		if err != nil {
			return nil, err
		}
		policy = check.Normalized
	}

	app := &tenant.Application{
		AppCode:       generateAppCode(),
		Name:          in.Name,
		AppSecretHash: secretHash,
		Status:        1,
		AccountMode:   in.AccountMode,
		Policy:        policy,
	}
	created, err := s.deps.TenantApps.Upsert(ctx, app)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "app.create", "application", createdID(app),
			in.Reason, nil, appToState(created), "error", err)
		return nil, err
	}
	s.writeAudit(ctx, in.Principal, "app.create", "application", fmt.Sprintf("%d", created.ID),
		in.Reason, nil, appToState(created), "success", nil)

	return &CreateAppOutput{App: toAppView(created), AppSecret: secret}, nil
}

// UpdateAppInput 是 PATCH /admin/v1/apps/{id} 的入参。
type UpdateAppInput struct {
	Name      *string `json:"name,omitempty"`
	Status    *int16  `json:"status,omitempty"` // 1=enable, 0=disable
	Reason    string  `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// UpdateApp 改名称或启停状态。
func (s *Service) UpdateApp(ctx context.Context, appID int64, in UpdateAppInput) (*AppView, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	if in.Name == nil && in.Status == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "name 与 status 至少给一个")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（app.update）必须填写 reason（≥4 字符）")
	}

	current, err := s.deps.TenantApps.FindByID(ctx, appID)
	if err != nil {
		return nil, err
	}

	before := appToState(current)
	if in.Name != nil {
		current.Name = *in.Name
	}
	if in.Status != nil {
		current.Status = *in.Status
	}
	updated, err := s.deps.TenantApps.Upsert(ctx, current)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "app.update", "application", fmt.Sprintf("%d", appID),
			in.Reason, before, nil, "error", err)
		return nil, err
	}
	s.writeAudit(ctx, in.Principal, "app.update", "application", fmt.Sprintf("%d", appID),
		in.Reason, before, appToState(updated), "success", nil)
	return toAppView(updated), nil
}

// RotateAppSecretInput 是 POST /admin/v1/apps/{id}/secret:rotate 的入参。
type RotateAppSecretInput struct {
	Reason    string `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// RotateAppSecretOutput 是轮换的出参。
type RotateAppSecretOutput struct {
	NewSecret string `json:"app_secret"`
}

// RotateAppSecret 轮换应用级密钥。
//
// 生成新 secret 并立即覆盖；旧 secret 同步失效（不在仓储里保留 prev）。
// 想要双活期可在仓储层加 secret_hash_prev 字段，本期不做。
func (s *Service) RotateAppSecret(ctx context.Context, appID int64, in RotateAppSecretInput) (*RotateAppSecretOutput, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（app.rotate_secret）必须填写 reason（≥4 字符）")
	}
	current, err := s.deps.TenantApps.FindByID(ctx, appID)
	if err != nil {
		return nil, err
	}

	secret, err := generateAppSecret()
	if err != nil {
		return nil, err
	}
	hash, err := s.deps.HashSecret(secret)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "哈希新 secret 失败", err)
	}
	before := appToState(current)
	current.AppSecretHash = hash
	updated, err := s.deps.TenantApps.Upsert(ctx, current)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "app.rotate_secret", "application", fmt.Sprintf("%d", appID),
			in.Reason, before, nil, "error", err)
		return nil, err
	}
	s.writeAudit(ctx, in.Principal, "app.rotate_secret", "application", fmt.Sprintf("%d", appID),
		in.Reason, before, appToState(updated), "success", nil)
	return &RotateAppSecretOutput{NewSecret: secret}, nil
}

// GetPolicy 读策略（GET /admin/v1/apps/{id}/policy）。
func (s *Service) GetPolicy(ctx context.Context, appID int64) (*tenant.Policy, error) {
	app, err := s.deps.TenantApps.FindByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	// 显式从 DefaultPolicy() 出发再覆盖，避免零值 Policy 被下游误读
	p := tenant.DefaultPolicy()
	if app.Policy.OnUnboundLogin != "" {
		p.OnUnboundLogin = app.Policy.OnUnboundLogin
	}
	p.Merge = app.Policy.Merge
	p.AllowedRedirectURIs = app.Policy.AllowedRedirectURIs
	return &p, nil
}

// SavePolicyInput 是 PUT /admin/v1/apps/{id}/policy 的入参。
type SavePolicyInput struct {
	Policy    *tenant.Policy `json:"policy" binding:"required"`
	Reason    string         `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// SavePolicy 保存策略（执行 §7.5.4 一致性校验，非法组合 REJECT）。
func (s *Service) SavePolicy(ctx context.Context, appID int64, in SavePolicyInput) (*tenant.Policy, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	if in.Policy == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "policy 不能为空")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired,
			"高危操作（app.update）必须填写 reason（≥4 字符）")
	}
	current, err := s.deps.TenantApps.FindByID(ctx, appID)
	if err != nil {
		return nil, err
	}

	check, err := in.Policy.Validate()
	if err != nil {
		return nil, err
	}
	before := appToState(current)
	current.Policy = check.Normalized
	updated, err := s.deps.TenantApps.Upsert(ctx, current)
	if err != nil {
		s.writeAudit(ctx, in.Principal, "app.update", "application", fmt.Sprintf("%d", appID),
			in.Reason, before, nil, "error", err)
		return nil, err
	}
	s.writeAudit(ctx, in.Principal, "app.update", "application", fmt.Sprintf("%d", appID),
		in.Reason, before, appToState(updated), "success", nil)
	return &updated.Policy, nil
}

// ValidatePolicyInput 是 POST /admin/v1/apps/{id}/policy:validate 的入参。
type ValidatePolicyInput struct {
	Policy *tenant.Policy `json:"policy" binding:"required"`
}

// ValidatePolicyResult 是 dry-run 校验的结果。
type ValidatePolicyResult struct {
	Warnings   []string      `json:"warnings"`
	Normalized tenant.Policy `json:"normalized"`
}

// ValidatePolicy dry-run：只校验不落库，供前端实时提示。
func (s *Service) ValidatePolicy(_ context.Context, in ValidatePolicyInput) (*ValidatePolicyResult, error) {
	if in.Policy == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "policy 不能为空")
	}
	check, err := in.Policy.Validate()
	if err != nil {
		return nil, err
	}
	return &ValidatePolicyResult{
		Warnings:   check.Warnings,
		Normalized: check.Normalized,
	}, nil
}

// GetApp 按 ID 查应用。返回白名单视图——AppSecretHash 不外发。
func (s *Service) GetApp(ctx context.Context, appID int64) (*AppView, error) {
	if appID <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	a, err := s.deps.TenantApps.FindByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	return toAppView(a), nil
}

// ListAppsInput 是 GET /admin/v1/apps 的入参。
type ListAppsInput struct {
	Page     int
	PageSize int
	// Status 过滤：-1 = 全部，0 = 停用，1 = 启用。
	Status int
	Name   string
}

// ListAppsOutput 是列表出参。
type ListAppsOutput struct {
	Items         []AppView `json:"items"`
	NextPageToken string    `json:"next_page_token"`
}

// ListApps 列表（按 ID 倒序分页）。
//
// 本期简化：仓储未提供 List，依赖外部注入 ListAppIDs。
// 留口在下一期把 List 接到 tenant.ApplicationRepository。
func (s *Service) ListApps(ctx context.Context, in ListAppsInput) (*ListAppsOutput, error) {
	if s.deps.ListAppIDs == nil {
		// 没有 List 能力时返回空列表（不报错），让 UI 至少能加载。
		return &ListAppsOutput{Items: []AppView{}, NextPageToken: ""}, nil
	}
	if in.PageSize <= 0 {
		in.PageSize = 20
	}
	if in.PageSize > 100 {
		in.PageSize = 100
	}
	if in.Page <= 0 {
		in.Page = 1
	}
	ids, err := s.deps.ListAppIDs(ctx, in.PageSize*in.Page)
	if err != nil {
		return nil, err
	}
	out := make([]AppView, 0, len(ids))
	for _, id := range ids {
		a, err := s.deps.TenantApps.FindByID(ctx, id)
		if err != nil {
			if errors.Is(err, tenant.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if in.Status >= 0 && int(a.Status) != in.Status {
			continue
		}
		if in.Name != "" && !containsFold(a.Name, in.Name) {
			continue
		}
		out = append(out, *toAppView(a))
	}
	return &ListAppsOutput{Items: out, NextPageToken: ""}, nil
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			cs, cb := s[i+j], sub[j]
			if cs >= 'A' && cs <= 'Z' {
				cs += 'a' - 'A'
			}
			if cb >= 'A' && cb <= 'Z' {
				cb += 'a' - 'A'
			}
			if cs != cb {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// writeAudit 是内部审计写 helper。
func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action, targetType, targetID, reason string,
	before, after map[string]any, result string, auditErr error,
) {
	if s.deps.AdminAudit == nil {
		return
	}
	ev := &admin.AuditEvent{
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Reason:      reason,
		BeforeState: before,
		AfterState:  after,
		Result:      result,
	}
	if p != nil && p.User != nil {
		ev.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	} else {
		ev.SubjectID = "admin:anonymous"
	}
	if auditErr != nil {
		if e, ok := errs.As(auditErr); ok {
			ev.ErrorCode = string(e.Code)
		} else {
			ev.ErrorCode = string(errs.CodeInternal)
		}
	}
	if err := s.deps.AdminAudit.Write(ctx, ev); err != nil {
		if s.deps.Logger != nil {
			s.deps.Logger.Error("写入管理审计失败", zap.Error(err), zap.String("action", action))
		}
	}
}

// appToState 把 Application 投影成审计快照（屏蔽敏感字段）。
func appToState(a *tenant.Application) map[string]any {
	if a == nil {
		return nil
	}
	return map[string]any{
		"id":           a.ID,
		"app_code":     a.AppCode,
		"name":         a.Name,
		"status":       a.Status,
		"account_mode": a.AccountMode,
		"policy":       a.Policy,
	}
}

func createdID(a *tenant.Application) string {
	if a == nil || a.ID == 0 {
		return "new"
	}
	return fmt.Sprintf("%d", a.ID)
}

// generateAppCode 生成对外 app_code。
//
// 用 8 字节随机 hex——同 §5.7 的"防同秒并发撞码"经验：
// 之前用 ULID 时间戳前缀出现过同秒应用 code 撞车，改尾部随机后通过。
func generateAppCode() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("app-%d", time.Now().UnixNano())
	}
	return "app-" + hex.EncodeToString(b[:])
}

// generateAppSecret 生成 32 字节随机 secret（hex 编码 → 64 字符）。
func generateAppSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errs.Wrap(errs.CodeInternal, "生成 app_secret 失败", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// defaultHashSecret 是【故意失败】的兜底实现。
//
// 历史上这里是 `return "placeholder:" + plain`，把明文直接拼在哈希位，
// 造成两个后果（已于 2026-10-19 修复）：
//  1. 管理端建的应用在业务端验签永远失败（HMAC 结果与 placeholder 前缀不等）；
//  2. app_secret 明文落库。
//
// 现在改为显式报错，而不是悄悄退化成可用但错误的实现：
// 一个"能跑但前后台对不上"的默认值，比直接失败危险得多——它会让问题
// 推迟到联调甚至上线后才暴露。调用方必须在 Deps 里注入 crypto.AppSecretHasher。
func defaultHashSecret(_ string) (string, error) {
	return "", errs.New(errs.CodeInternal,
		"adminapp 未注入 HashSecret：必须传入 crypto.AppSecretHasher，否则管理端写入的 app_secret 无法被业务端校验")
}

// UpdateWebhookInput 是 PUT /admin/v1/apps/{id}/webhook 的入参。
//
// 为什么单独一个端点而不并进 app.update：
// webhook 签名密钥是【明文可解】的密钥材料（HMAC 需要），
// 与 name/status 这类普通字段的敏感级别不同，混在一起会让 A 组的密钥轮换
// 语义变得含糊。单独端点也便于后续做"只改地址、不重传密钥"。
type UpdateWebhookInput struct {
	// URL 为空字符串表示关闭事件外发（此后事件标 skipped，而不是 pending 堆积）。
	URL string `json:"url"`
	// Secret 留空表示保留原密钥。
	Secret    string `json:"secret"`
	Reason    string `json:"reason" binding:"required"`
	Principal *admin.Principal
}

// UpdateWebhook 配置事件投递目标。
func (s *Service) UpdateWebhook(ctx context.Context, appID int64, in UpdateWebhookInput) error {
	if appID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	if in.Reason == "" || len([]rune(in.Reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired,
			"高危操作（app.webhook）必须填写 reason（≥4 字符）")
	}
	if in.URL != "" && !strings.HasPrefix(in.URL, "https://") && !strings.HasPrefix(in.URL, "http://") {
		return errs.New(errs.CodeInvalidRequest, "webhook url 必须是 http(s) 绝对地址")
	}
	if s.deps.SetWebhook == nil {
		return errs.New(errs.CodeInternal, "adminapp 未注入 SetWebhook")
	}

	var cipher []byte
	var kid string
	if in.Secret != "" {
		if s.deps.EncryptSecret == nil {
			return errs.New(errs.CodeInternal, "adminapp 未注入 EncryptSecret")
		}
		var err error
		cipher, kid, err = s.deps.EncryptSecret(in.Secret)
		if err != nil {
			return errs.Wrap(errs.CodeInternal, "加密 webhook 密钥失败", err)
		}
	}

	// before 快照：地址与"是否已设密钥"，绝不含密钥本身。
	var before map[string]any
	if s.deps.GetWebhook != nil {
		if _, oldURL, oldEnc, _, err := s.deps.GetWebhook(ctx, appID); err == nil {
			before = map[string]any{"webhook_url": oldURL, "secret_set": len(oldEnc) > 0}
		}
	}
	if err := s.deps.SetWebhook(ctx, appID, in.URL, cipher, kid); err != nil {
		s.writeAudit(ctx, in.Principal, "app.webhook", "application", fmt.Sprintf("%d", appID),
			in.Reason, before, nil, "error", err)
		return err
	}
	after := map[string]any{"webhook_url": in.URL, "secret_rotated": in.Secret != ""}
	s.writeAudit(ctx, in.Principal, "app.webhook", "application", fmt.Sprintf("%d", appID),
		in.Reason, before, after, "success", nil)
	return nil
}
