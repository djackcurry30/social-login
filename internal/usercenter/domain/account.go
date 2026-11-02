package domain

import "time"

// Status 是账号状态。取值与 DDL 的 CHECK 约束、social-login 的
// domain/account.Status 一致——不一致会让消费方在校验阶段把合法账号拒掉。
type Status string

const (
	// StatusActive 正常。
	StatusActive Status = "active"
	// StatusFrozen 冻结：可读、不可新增绑定（由消费方决定）。
	StatusFrozen Status = "frozen"
	// StatusClosed 已关闭。合并的 source 与注销的账号都是这个状态，
	// 区分方式是 merged_into 是否为空。
	StatusClosed Status = "closed"
)

// IsValidStatus 判断状态是否在枚举内。
func IsValidStatus(s Status) bool {
	switch s {
	case StatusActive, StatusFrozen, StatusClosed:
		return true
	}
	return false
}

// Account 是账号的对外视图。
//
// JSON 字段名沿用契约 v1：user_id（值即 public_id）。不改成 public_id——
// 那会让消费方的 DTO 与已有用例一起改，收益为零（§4.1）。
type Account struct {
	// ID 是库内自增主键，只在服务内部使用（事务内引用），绝不对外。
	ID     int64   `json:"-"`
	UserID string  `json:"user_id"`
	Status Status  `json:"status"`
	Claims []Claim `json:"claims"`
	// Nickname / AvatarURL 只在 Create 时写入（MVP 不提供资料编辑）。
	Nickname  string `json:"nickname,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	// MergedInto 非空表示这个账号已被合并进另一个账号（status=closed）。
	// 契约里没有它，但内部读路径（按凭证反查命中已合并账号）需要据此
	// 给出可解释的响应，而不是干巴巴的 404。
	MergedInto string    `json:"-"`
	CreatedAt  time.Time `json:"-"`
	UpdatedAt  time.Time `json:"-"`
}

// App 是一个已注册的租户。
type App struct {
	ID     int64
	Key    string
	Name   string
	Status int16 // 1 启用 / 0 停用
}

// Enabled 判断应用是否启用。
func (a App) Enabled() bool { return a.Status == 1 }

// AppStatusActive / AppStatusDisabled 是对外协议里的应用状态词。
//
// 库内用 smallint，对外用这两个词：整数状态会被调用方硬编码成 0/1，
// 而"0 是启用还是停用"没有任何线索可言。
const (
	AppStatusActive   = "active"
	AppStatusDisabled = "disabled"
)

// ParseAppStatus 把协议里的状态词转成库内取值。
func ParseAppStatus(s string) (int16, bool) {
	switch s {
	case AppStatusActive:
		return 1, true
	case AppStatusDisabled:
		return 0, true
	}
	return 0, false
}

// AppStatusName 把库内取值转成协议里的状态词。
func AppStatusName(v int16) string {
	if v == 1 {
		return AppStatusActive
	}
	return AppStatusDisabled
}
