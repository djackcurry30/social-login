package admin

import "time"

// ConfigReloadResult 是一次配置热更新的结果。
//
// 三个列表的分工必须在返回里说清楚，否则调用方（运维脚本/前端）
// 只能看到"200 OK"却不知道哪些改动没生效：
//
//	Applied        已经生效的字段
//	RequiresRestart 检测到改动、但必须重启进程才生效的配置段
//	Warnings       可放行但需要提醒的情况（如 enabled 从 false 翻到 true）
type ConfigReloadResult struct {
	Applied         []string  `json:"applied"`
	RequiresRestart []string  `json:"requires_restart"`
	Warnings        []string  `json:"warnings"`
	ReloadedAt      time.Time `json:"reloaded_at"`
}

// ConfigReloader 是配置热更新的端口（实现见 bootstrap.Reloader）。
//
// 定义在 admin 包而不是 bootstrap：admin 是调用方，不该反向依赖装配层；
// 而 bootstrap 已经 import admin（装配路由），让 bootstrap 实现这个接口
// 不会形成循环。
type ConfigReloader interface {
	Reload() (ConfigReloadResult, error)
}
