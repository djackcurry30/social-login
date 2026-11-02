package observe

import "github.com/djackcurry30/social-login/internal/pkg/metrics"

// Metrics 是本服务的业务指标集合。
//
// 标签基数：app_key 的数量等于注册应用数（当前个位数，规划 5~20），
// 作为标签是安全的；public_id 绝不做标签——那是账号数，基数会爆炸。
type Metrics struct {
	// Requests / DurationMS 由中间件写入。
	// 用两个 counter 表达平均延迟（sum / count）而不是直方图：
	// 本服务的延迟由单条 SQL 决定，平均值足以发现"慢了一个量级"；
	// 分位数等真正需要时再加 histogram。
	Requests   *metrics.Counter
	DurationMS *metrics.Counter

	AccountsCreated  *metrics.Counter
	AccountsClosed   *metrics.Counter
	Merges           *metrics.Counter
	ClaimConflicts   *metrics.Counter
	IdempotentReplay *metrics.Counter
}

// NewMetrics 注册全部指标。
func NewMetrics(reg *metrics.Registry) *Metrics {
	return &Metrics{
		Requests: reg.Counter("user_center_http_requests_total",
			"HTTP 请求数", "method", "route", "status"),
		DurationMS: reg.Counter("user_center_http_duration_ms_total",
			"HTTP 请求累计耗时（毫秒）", "route"),
		AccountsCreated: reg.Counter("user_center_accounts_created_total",
			"创建的账号数", "app_key"),
		AccountsClosed: reg.Counter("user_center_accounts_closed_total",
			"关闭的账号数", "app_key"),
		Merges: reg.Counter("user_center_merge_total",
			"合并调用数", "app_key", "result"),
		ClaimConflicts: reg.Counter("user_center_claim_conflict_total",
			"凭证冲突次数", "app_key", "op"),
		IdempotentReplay: reg.Counter("user_center_idempotent_replay_total",
			"幂等键重放次数", "app_key"),
	}
}

// 以下方法在 m 为 nil 时安全：单测与命令行工具不注册指标，
// 但 service 的代码路径必须一致（不能为了指标而分叉）。

func (m *Metrics) RecordCreated(appKey string) {
	if m != nil {
		m.AccountsCreated.Inc(appKey)
	}
}

func (m *Metrics) RecordClosed(appKey string) {
	if m != nil {
		m.AccountsClosed.Inc(appKey)
	}
}

// RecordMerge 的 result 取 merged / already_merged / rejected。
func (m *Metrics) RecordMerge(appKey, result string) {
	if m != nil {
		m.Merges.Inc(appKey, result)
	}
}

// RecordConflict 的 op 取 create / replace / merge。
func (m *Metrics) RecordConflict(appKey, op string) {
	if m != nil {
		m.ClaimConflicts.Inc(appKey, op)
	}
}

func (m *Metrics) RecordReplay(appKey string) {
	if m != nil {
		m.IdempotentReplay.Inc(appKey)
	}
}
