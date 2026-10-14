package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// AppRepository 是 applications 表的仓储。
//
// 注意：applications 表【不在 scopedTables 中】——它本身就是应用表，
// 查询它不需要应用作用域（否则会陷入"要先知道 app_id 才能查 app_id"的死循环）。
type AppRepository struct {
	db *gorm.DB
}

// NewAppRepository 构造仓储。
func NewAppRepository(db *gorm.DB) *AppRepository {
	return &AppRepository{db: db}
}

var _ tenant.ApplicationRepository = (*AppRepository)(nil)

// FindByAppCode 按对外 app_id 查找应用。
func (r *AppRepository) FindByAppCode(ctx context.Context, appCode string) (*tenant.Application, error) {
	if appCode == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "app_id 不能为空")
	}
	var m applicationModel
	err := r.db.WithContext(ctx).Where("app_code = ?", appCode).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询应用失败", err)
	}
	return appToDomain(&m), nil
}

// FindByID 按主键查找应用。
func (r *AppRepository) FindByID(ctx context.Context, id int64) (*tenant.Application, error) {
	if id <= 0 {
		return nil, errs.New(errs.CodeInvalidRequest, "应用主键非法")
	}
	var m applicationModel
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询应用失败", err)
	}
	return appToDomain(&m), nil
}

// Upsert 按 app_code 插入或更新应用（供引导脚本与测试使用）。
func (r *AppRepository) Upsert(ctx context.Context, app *tenant.Application) (*tenant.Application, error) {
	if app == nil || app.AppCode == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "应用信息不完整")
	}
	if app.AccountMode == "" {
		app.AccountMode = tenant.AccountModeRemote
	}
	// 写入前先校验：非法策略一旦落库，就会在用户登录时以"行为与配置不符"的形式
	// 暴露出来（例如运维以为开了自动合并、实际没有），排查成本极高。
	// 在写入这一道关口拦住它，成本几乎为零。
	check, err := app.Policy.Validate()
	if err != nil {
		return nil, err
	}
	app.Policy = check.Normalized

	m := applicationModel{
		AppCode:       app.AppCode,
		Name:          app.Name,
		AppSecretHash: app.AppSecretHash,
		Status:        1,
		AccountMode:   app.AccountMode,
		Policy:        policyToModel(app.Policy),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if app.Status != 0 {
		m.Status = app.Status
	}

	err = r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "app_code"}},
		DoUpdates: clause.Assignments(map[string]any{
			"name":            m.Name,
			"app_secret_hash": m.AppSecretHash,
			"status":          m.Status,
			"account_mode":    m.AccountMode,
			"policy":          m.Policy,
			"updated_at":      m.UpdatedAt,
		}),
	}).Create(&m).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "保存应用失败", err)
	}
	return appToDomain(&m), nil
}

func appToDomain(m *applicationModel) *tenant.Application {
	return &tenant.Application{
		ID:            m.ID,
		AppCode:       m.AppCode,
		Name:          m.Name,
		AppSecretHash: m.AppSecretHash,
		Status:        m.Status,
		AccountMode:   m.AccountMode,
		Policy:        policyFromModel(m.Policy),
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

// policyFromModel 把 JSONB 转成结构化 Policy。
//
// 刻意不用 json.Unmarshal 直接反序列化到结构体：这样未知字段会被静默忽略
// （未来版本新增字段时，旧代码读到不会出错），而缺失字段能落到默认值上。
// 若直接反序列化，缺失字段会变成零值 false/""，把"未配置"误当成"配置为关闭"——
// 对 notify_source_account 这种安全开关是致命的。
func policyFromModel(m JSONMap) tenant.Policy {
	p := tenant.DefaultPolicy()
	if m == nil {
		return p
	}
	if v, ok := m["on_unbound_login"].(string); ok && v != "" {
		p.OnUnboundLogin = v
	}
	p.AllowedRedirectURIs = stringSlice(m["allowed_redirect_uris"])
	merge, ok := m["merge"].(map[string]any)
	if !ok {
		p.Normalize()
		return p
	}
	if v, ok := merge["mode"].(string); ok && v != "" {
		p.Merge.Mode = v
	}
	if v, ok := merge["verification"].(string); ok && v != "" {
		p.Merge.Verification = v
	}
	if v, ok := merge["on_login"].(string); ok && v != "" {
		p.Merge.OnLogin = v
	}
	if v, ok := merge["notify_source_account"].(bool); ok {
		p.Merge.NotifySourceAccount = v
	}
	if v, ok := merge["source_disposal"].(string); ok && v != "" {
		p.Merge.SourceDisposal = v
	}
	if v, ok := merge["allow_cross_platform_auto"].(bool); ok {
		p.Merge.AllowCrossPlatformAuto = v
	}
	p.Normalize()
	return p
}

func policyToModel(p tenant.Policy) JSONMap {
	p.Normalize()
	uris := make([]any, 0, len(p.AllowedRedirectURIs))
	for _, u := range p.AllowedRedirectURIs {
		uris = append(uris, u)
	}
	return JSONMap{
		"on_unbound_login":      p.OnUnboundLogin,
		"allowed_redirect_uris": uris,
		"merge": map[string]any{
			"mode":                      p.Merge.Mode,
			"verification":              p.Merge.Verification,
			"on_login":                  p.Merge.OnLogin,
			"notify_source_account":     p.Merge.NotifySourceAccount,
			"source_disposal":           p.Merge.SourceDisposal,
			"allow_cross_platform_auto": p.Merge.AllowCrossPlatformAuto,
		},
	}
}

// stringSlice 把 JSONB 里的数组转成 []string，容忍 []any / string / nil。
func stringSlice(v any) []string {
	switch raw := v.(type) {
	case []string:
		return raw
	case []any:
		out := make([]string, 0, len(raw))
		for _, item := range raw {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if raw == "" {
			return nil
		}
		return []string{raw}
	default:
		return nil
	}
}
