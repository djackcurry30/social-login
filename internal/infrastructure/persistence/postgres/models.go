// Package postgres 是 PostgreSQL 的持久化实现。
//
// DDL 的唯一真相源是 migrations/*.sql 中的手写 SQL，【禁止使用 AutoMigrate
// 管理生产 schema】（tech-stack 的两条 GORM 不变量之一）。原因是 AutoMigrate：
//   - 表达不了部分唯一索引——而 uk_claims_verified / uk_bindings_active 这两条
//     部分唯一索引正是整个数据模型的安全底线
//   - 只加不删，且会"静默做错事"（改列类型失败时只记日志）
//
// 本文件中的 GORM 模型只用于查询与写入，不用于建表。
package postgres

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// JSONMap 是 JSONB 列的类型映射。
//
// 不用 gorm.io/datatypes.JSON 是为了少一个依赖；而直接用 []byte 会在
// gorm 的批量写入与默认值判断上出现意外（nil vs 空对象语义不清）。
type JSONMap map[string]any

// Value 实现 driver.Valuer。
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// jsonNotNull 把可能为 nil 的 map 转成可直接写 NOT NULL jsonb 列的 JSONMap。
//
// 为什么需要它：JSONMap.Value() 对 nil 返回 SQL NULL（这是可空列
// before_state / after_state 需要的语义——NULL 表示"没记录快照"），
// 但 NOT NULL 的 jsonb 列（applications.policy / app_provider_configs.extra /
// oauth_identities.profile_snapshot / 审计 detail）收到 NULL 会直接触发
//
//	ERROR: null value in column "extra" violates not-null constraint (23502)
//
// 这类错误只会在"某个调用方恰好没填 extra"时出现，靠 review 很难发现，
// 因此把判定收到一个函数里：写 NOT NULL 列一律走它。
func jsonNotNull(m map[string]any) JSONMap {
	if len(m) == 0 {
		return JSONMap{}
	}
	out := make(JSONMap, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Scan 实现 sql.Scanner。
func (m *JSONMap) Scan(src any) error {
	if src == nil {
		*m = nil
		return nil
	}
	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("postgres.JSONMap: 不支持的源类型 %T", src)
	}
	if len(raw) == 0 {
		*m = JSONMap{}
		return nil
	}
	out := JSONMap{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("postgres.JSONMap: 反序列化失败: %w", err)
	}
	*m = out
	return nil
}

// --- 表模型 ---
//
// 字段顺序与 DDL 保持一致，便于对照检查。

type applicationModel struct {
	ID            int64     `gorm:"column:id;primaryKey"`
	AppCode       string    `gorm:"column:app_code"`
	Name          string    `gorm:"column:name"`
	AppSecretHash string    `gorm:"column:app_secret_hash"`
	Status        int16     `gorm:"column:status"`
	AccountMode   string    `gorm:"column:account_mode"`
	Policy        JSONMap   `gorm:"column:policy;type:jsonb"`
	CreatedAt     time.Time `gorm:"column:created_at"`
	UpdatedAt     time.Time `gorm:"column:updated_at"`
}

func (applicationModel) TableName() string { return "applications" }

type providerConfigModel struct {
	ID               int64      `gorm:"column:id;primaryKey"`
	AppID            int64      `gorm:"column:app_id"`
	Platform         string     `gorm:"column:platform"`
	Scene            string     `gorm:"column:scene"`
	ConfigKey        string     `gorm:"column:config_key"`
	ProviderAppID    string     `gorm:"column:provider_app_id"`
	SecretCipher     []byte     `gorm:"column:secret_cipher"`
	SecretCipherPrev []byte     `gorm:"column:secret_cipher_prev"`
	SecretRotatedAt  *time.Time `gorm:"column:secret_rotated_at"`
	SecretDEKID      string     `gorm:"column:secret_dek_id"`
	Env              string     `gorm:"column:env"`
	Extra            JSONMap    `gorm:"column:extra;type:jsonb"`
	Version          int64      `gorm:"column:version"`
	Status           int16      `gorm:"column:status"`
	CreatedAt        time.Time  `gorm:"column:created_at"`
	UpdatedAt        time.Time  `gorm:"column:updated_at"`
}

func (providerConfigModel) TableName() string { return "app_provider_configs" }

type identityModel struct {
	ID              int64      `gorm:"column:id;primaryKey"`
	AppID           int64      `gorm:"column:app_id"`
	Platform        string     `gorm:"column:platform"`
	ProviderAppID   string     `gorm:"column:provider_app_id"`
	OpenID          string     `gorm:"column:open_id"`
	UnionID         string     `gorm:"column:union_id"`
	IdentityKey     string     `gorm:"column:identity_key"`
	ProfileSnapshot JSONMap    `gorm:"column:profile_snapshot;type:jsonb"`
	ProfileSyncedAt *time.Time `gorm:"column:profile_synced_at"`
	FirstSeenAt     time.Time  `gorm:"column:first_seen_at"`
	LastLoginAt     *time.Time `gorm:"column:last_login_at"`
}

func (identityModel) TableName() string { return "oauth_identities" }

type claimModel struct {
	ID               int64      `gorm:"column:id;primaryKey"`
	AppID            int64      `gorm:"column:app_id"`
	IdentityID       int64      `gorm:"column:identity_id"`
	ClaimType        string     `gorm:"column:claim_type"`
	ClaimValueHash   string     `gorm:"column:claim_value_hash"`
	ClaimValueCipher []byte     `gorm:"column:claim_value_cipher"`
	Verified         bool       `gorm:"column:verified"`
	VerifiedAt       *time.Time `gorm:"column:verified_at"`
	Source           string     `gorm:"column:source"`
	CreatedAt        time.Time  `gorm:"column:created_at"`
	RevokedAt        *time.Time `gorm:"column:revoked_at"`
}

func (claimModel) TableName() string { return "identity_claims" }

type bindingModel struct {
	ID             int64      `gorm:"column:id;primaryKey"`
	AppID          int64      `gorm:"column:app_id"`
	ExternalUserID string     `gorm:"column:external_user_id"`
	IdentityID     int64      `gorm:"column:identity_id"`
	Status         string     `gorm:"column:status"`
	IsPrimary      bool       `gorm:"column:is_primary"`
	BindSource     string     `gorm:"column:bind_source"`
	BoundAt        time.Time  `gorm:"column:bound_at"`
	UnboundAt      *time.Time `gorm:"column:unbound_at"`
}

func (bindingModel) TableName() string { return "oauth_bindings" }

type refreshTokenModel struct {
	ID             int64     `gorm:"column:id;primaryKey"`
	AppID          int64     `gorm:"column:app_id"`
	ExternalUserID string    `gorm:"column:external_user_id"`
	TokenHash      string    `gorm:"column:token_hash"`
	DeviceID       string    `gorm:"column:device_id"`
	Scope          string    `gorm:"column:scope"`
	ExpiresAt      time.Time `gorm:"column:expires_at"`
	RotatedFrom    *int64    `gorm:"column:rotated_from"`
	Revoked        bool      `gorm:"column:revoked"`
	RevokedReason  string    `gorm:"column:revoked_reason"`
	CreatedAt      time.Time `gorm:"column:created_at"`
}

func (refreshTokenModel) TableName() string { return "refresh_tokens" }

type auditLogModel struct {
	ID             int64     `gorm:"column:id;primaryKey"`
	AppID          int64     `gorm:"column:app_id"`
	ExternalUserID string    `gorm:"column:external_user_id"`
	Platform       string    `gorm:"column:platform"`
	Scene          string    `gorm:"column:scene"`
	Client         string    `gorm:"column:client"`
	Action         string    `gorm:"column:action"`
	Result         string    `gorm:"column:result"`
	ErrorCode      string    `gorm:"column:error_code"`
	ClientIP       *string   `gorm:"column:client_ip;type:inet"`
	UserAgent      string    `gorm:"column:user_agent"`
	TraceID        string    `gorm:"column:trace_id"`
	Detail         JSONMap   `gorm:"column:detail;type:jsonb"`
	CreatedAt      time.Time `gorm:"column:created_at"`
}

func (auditLogModel) TableName() string { return "auth_audit_logs" }

type adminGrantModel struct {
	ID         int64      `gorm:"column:id;primaryKey"`
	SubjectID  string     `gorm:"column:subject_id"`
	Role       string     `gorm:"column:role"`
	ScopeAppID *int64     `gorm:"column:scope_app_id"`
	GrantedBy  string     `gorm:"column:granted_by"`
	GrantedAt  time.Time  `gorm:"column:granted_at"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
	RevokedAt  *time.Time `gorm:"column:revoked_at"`
}

func (adminGrantModel) TableName() string { return "admin_grants" }

type adminAuditLogModel struct {
	ID          int64     `gorm:"column:id;primaryKey"`
	SubjectID   string    `gorm:"column:subject_id"`
	Action      string    `gorm:"column:action"`
	TargetType  string    `gorm:"column:target_type"`
	TargetID    string    `gorm:"column:target_id"`
	AppID       *int64    `gorm:"column:app_id"`
	Reason      string    `gorm:"column:reason"`
	BeforeState JSONMap   `gorm:"column:before_state;type:jsonb"`
	AfterState  JSONMap   `gorm:"column:after_state;type:jsonb"`
	ClientIP    *string   `gorm:"column:client_ip;type:inet"`
	TraceID     string    `gorm:"column:trace_id"`
	Result      string    `gorm:"column:result"`
	ErrorCode   string    `gorm:"column:error_code"`
	CreatedAt   time.Time `gorm:"column:created_at"`
}

func (adminAuditLogModel) TableName() string { return "admin_audit_logs" }

// 管理员账号（00002_admin.sql）。
type adminUserModel struct {
	ID           int64      `gorm:"column:id;primaryKey"`
	Username     string     `gorm:"column:username"`
	PasswordHash string     `gorm:"column:password_hash"`
	DisplayName  string     `gorm:"column:display_name"`
	Role         string     `gorm:"column:role"`
	Status       int16      `gorm:"column:status"`
	LastLoginAt  *time.Time `gorm:"column:last_login_at"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	UpdatedAt    time.Time  `gorm:"column:updated_at"`
}

func (adminUserModel) TableName() string { return "admin_users" }

// 管理员会话（00002_admin.sql）。
type adminSessionModel struct {
	ID        int64      `gorm:"column:id;primaryKey"`
	UserID    int64      `gorm:"column:user_id"`
	TokenHash string     `gorm:"column:token_hash"`
	ClientIP  *string    `gorm:"column:client_ip;type:inet"`
	UserAgent string     `gorm:"column:user_agent"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	RevokedAt *time.Time `gorm:"column:revoked_at"`
	CreatedAt time.Time  `gorm:"column:created_at"`
}

func (adminSessionModel) TableName() string { return "admin_sessions" }
