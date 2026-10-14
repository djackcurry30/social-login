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
