// Package audit 是审计日志的领域模型与写入端口。
//
// 审计与普通日志的区别（架构 §11.3 / §15.2）：普通日志给开发者排障用，
// 可以采样、可以丢；审计日志是给合规与事故追溯用的，必须【全量、不可丢失】，
// 且业务端审计与管理端审计分开存放——后者的保留期更长（3 年 vs 180 天）、
// 查询权限更严格。
package audit

import (
	"context"
	"time"
)

// 审计动作。
const (
	ActionLogin  = "login"
	ActionBind   = "bind"
	ActionUnbind = "unbind"
	ActionMerge  = "merge"
	ActionRevoke = "revoke"
)

// 审计结果。
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Event 是一条业务端审计记录。
type Event struct {
	AppID          int64
	ExternalUserID string
	Platform       string
	Scene          string
	// Client 是承载形态（ios / android / h5 / ...），仅用于遥测与风控，
	// 不参与配置查找（规则 2）。有了它才能回答"iOS 端登录成功率"这类问题。
	Client    string
	Action    string
	Result    string
	ErrorCode string
	ClientIP  string
	UserAgent string
	TraceID   string
	Detail    map[string]any
	At        time.Time
}

// Writer 是审计写入端口。
//
// 实现必须保证：写入失败【不影响主流程】——审计是旁路，不能因为审计写不进去
// 就让用户登录失败。失败应记录到错误日志与指标，由告警兜底。
type Writer interface {
	Write(ctx context.Context, e *Event) error
}

// Record 是一条查询出来的业务审计记录。
//
// 与 Event 分开而不是复用：Event 是"要写什么"，Record 是"读到了什么"（多一个
// 自增 ID、少一个"由谁触发"）。混用会让写入路径为了填 ID 传零值，读出来又
// 分不清哪些字段有意义。
type Record struct {
	ID             int64
	AppID          int64
	ExternalUserID string
	Platform       string
	Scene          string
	Client         string
	Action         string
	Result         string
	ErrorCode      string
	ClientIP       string
	UserAgent      string
	TraceID        string
	Detail         map[string]any
	CreatedAt      time.Time
}

// Filter 是业务审计的查询条件（§15.4 H 组）。
//
// 所有字段都是【与关系】。零值表示不限制——这一点由应用层在构造时保证：
// 管理端请求不带 app_id 时是"全应用"，带了就按应用过滤（§9.1 的显式跨应用）。
type Filter struct {
	AppID          int64
	Action         string
	Result         string
	ExternalUserID string
	TraceID        string
	Platform       string
	Client         string
	From           *time.Time
	To             *time.Time
	Page           int
	PageSize       int
}

// AdminRecord 是一条管理端审计记录。
type AdminRecord struct {
	ID          int64
	SubjectID   string
	Action      string
	TargetType  string
	TargetID    string
	AppID       *int64
	Reason      string
	BeforeState map[string]any
	AfterState  map[string]any
	ClientIP    string
	TraceID     string
	Result      string
	ErrorCode   string
	CreatedAt   time.Time
}

// AdminFilter 是管理端审计的查询条件。
//
// AppID 为 0 表示不限制应用。注意 admin_audit_logs 不在 scopedTables 里
// （管理端天然跨应用），因此这里的 AppID 只是业务过滤，不是安全边界。
type AdminFilter struct {
	SubjectID  string
	Action     string
	TargetType string
	TargetID   string
	AppID      int64
	Result     string
	From       *time.Time
	To         *time.Time
	Page       int
	PageSize   int
}

// Query 是审计查询端口（H 组 + 异步导出）。
type Query interface {
	// List 分页查询业务审计，返回当页记录与总数。
	List(ctx context.Context, f Filter) ([]Record, int64, error)
	// ListAdmin 分页查询管理端审计。
	ListAdmin(ctx context.Context, f AdminFilter) ([]AdminRecord, int64, error)
	// Stream 按批次回调业务审计，供【导出】使用。
	//
	// 为什么单独的流式方法而不是让调用方循环 List：审计表是仓库里唯一
	// 单表可能上千万行的表，一次导出把全量 Result 装进内存会直接把进程打爆。
	// 用回调 + 固定批次，内存占用与总量无关。
	//
	// fn 返回错误即中止（用于写盘失败），错误原样上抛。
	Stream(ctx context.Context, f Filter, batch int, fn func([]Record) error) error
}

