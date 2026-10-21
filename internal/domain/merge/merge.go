// Package merge 是账号合并（约束 C5 + 需求 R1/R2/R4）的领域模型与端口。
//
// 核心约束（架构 §7.3，修正 P0-3）：本服务【不持有账号主数据】，
// 合并必须跨服务完成，因此绝不能"用一个数据库事务包住跨服务调用"——
// 那样会出现"远端已合并成功、本地事务回滚"的永久孤儿窗口。
//
// 正确形态是三次独立事务：
//
//	① INSERT merge_operations(status=pending) 并 COMMIT   ← 先持久化，保证可补偿
//	② 调 AccountProvider.Merge（不持有任何事务）
//	③ 本地收敛 + 写 outbox 事件，同一事务 COMMIT
//
// 本包只描述"合并操作"这条记录与它的状态机；编排在 application/merge。
package merge

import (
	"context"
	"errors"
	"time"
)

// 合并操作状态。
//
// 相比架构文档的 pending / done / failed，这里多两个：
//
//	dead     重试次数用尽，必须人工介入（与 failed 分开，否则"还能自动重试的"
//	         和"已经放弃的"混在一起，监控无意义）
//	rejected 前置校验拒绝（manual 模式、跨平台未授权等）。它不是失败，
//	         是"按规则不允许"，因此不重试、不计入错误率。
const (
	StatusPending  = "pending"
	StatusDone     = "done"
	StatusFailed   = "failed"
	StatusDead     = "dead"
	StatusRejected = "rejected"
)

// MaxAttempts 是自动补偿的最大尝试次数。
//
// 与 outbox 的 5 次不同：合并每次重试都会调用用户中心，代价与风险远高于
// 投递一次 webhook，且失败往往需要人工确认（例如对端幂等没做好）。
// 3 次之后转 dead，由管理端 D 组人工 retry。
const MaxAttempts = 3

// ErrNotFound 表示合并操作不存在。
var ErrNotFound = errors.New("merge: 操作不存在")

// ErrDuplicate 表示幂等键已存在（Create 内部会转换成"返回已有记录"，调用方一般看不到）。
var ErrDuplicate = errors.New("merge: 幂等键已存在")

// Operation 是一条合并操作记录（merge_operations 表）。
type Operation struct {
	ID    int64
	AppID int64
	// IdempotencyKey 由"场景 + 应用 + 双方账号"确定性生成，而不是随机。
	//
	// 这样同一个冲突被重复触发（用户连点、前端重试、补偿重跑）都会命中
	// 同一行记录，天然幂等；随机键只能保证"不重复插入"，挡不住重复执行。
	IdempotencyKey string
	TargetUserID   string
	SourceUserID   string
	// IdentityID 是触发本次合并的 identity（可空：登录场景下可能有多个）。
	IdentityID int64
	Status     string
	Reason     string
	Attempts   int
	LastError  string
	// RemoteResult 保存用户中心返回的排障引用（RemoteRef）。
	RemoteResult map[string]any
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Store 是合并操作的持久化端口。
type Store interface {
	// Create 写入一条 pending 记录。
	//
	// 幂等键冲突时【不报错】：返回已存在的记录与 created=false，
	// 调用方据此判断"这是一次重复请求"。
	Create(ctx context.Context, op *Operation) (saved *Operation, created bool, err error)

	Get(ctx context.Context, id int64) (*Operation, error)

	// List 分页查询（管理端 D 组）。
	List(ctx context.Context, f Filter) ([]*Operation, int64, error)

	// MarkDone 标记完成（本地收敛成功后调用，不再更新状态以外的东西）。
	MarkDone(ctx context.Context, id int64, remote map[string]any) error

	// MarkFailed 标记失败并累加 attempts。
	MarkFailed(ctx context.Context, id int64, remote map[string]any, lastErr string) error

	// MarkDead 标记为不可自动恢复。
	MarkDead(ctx context.Context, id int64, lastErr string) error

	// MarkRejected 标记为规则拒绝（不重试）。
	MarkRejected(ctx context.Context, id int64, reason string) error

	// ListDue 返回需要补偿的操作（pending / failed 且 attempts < max）。
	ListDue(ctx context.Context, limit int) ([]*Operation, error)
}

// Filter 是管理端查询条件。
type Filter struct {
	AppID  int64
	Status string
	// UserID 命中 target 或 source 任一侧。
	UserID   string
	From     *time.Time
	To       *time.Time
	Page     int
	PageSize int
}

// ConvergeInput 是"本地收敛"的入参。
type ConvergeInput struct {
	AppID        int64
	OperationID  int64
	TargetUserID string
	SourceUserID string
	// IdentityID 是触发合并的身份，便于审计与事件体携带。
	IdentityID int64
	// RemoteResult 原样落库，排障时能看到用户中心返回了什么。
	RemoteResult map[string]any
	// Event 是要与本地变更【同一事务】写入的 outbox 事件。
	//
	// 事件不能事后单独写：如果本地收敛成功、事件写入失败，业务方永远
	// 不知道账号被合并了（红线 2 的通知也就落空）。
	Event *ConvergeEvent
	// Audit 是与本地变更同一事务写入的业务审计。
	Audit *ConvergeAudit
}

// ConvergeEvent 描述要在事务内写入的 outbox 事件。
type ConvergeEvent struct {
	EventID       string
	Type          string
	SchemaVersion int
	Payload       map[string]any
}

// ConvergeAudit 描述要在事务内写入的业务审计（auth_audit_logs）。
type ConvergeAudit struct {
	Action         string
	ExternalUserID string
	Platform       string
	Scene          string
	Client         string
	TraceID        string
	Detail         map[string]any
}

// Converger 在一个数据库事务内完成本地收敛。
//
// 单独成端口而不是复用 binding / token / event 三个仓储：那三个仓储各自
// 持有独立的 *gorm.DB，无法共享事务。除非引入一个横跨全仓的 unit-of-work，
// 否则"在事务里调三个仓储"只是幻觉——每个调用都在自己的连接上自动提交。
//
// 实现见 infrastructure/persistence/postgres 的 MergeConverger。
type Converger interface {
	Converge(ctx context.Context, in ConvergeInput) error
}

// Locker 是合并互斥锁（lock:merge:{targetUserId}）。
//
// 为什么必须加锁：同一对账号的合并如果被并发触发两次，远端会收到两次
// Merge 调用。若用户中心的幂等实现有瑕疵，第二次就会重复迁移数据。
// 幂等键是最后一道防线，锁是第一道——两道都要有。
//
// 锁获取失败应返回 ErrLocked，调用方按"稍后重试"处理（不是失败）。
type Locker interface {
	// Lock 尝试获取锁，返回 unlock 函数。失败返回 ErrLocked。
	Lock(ctx context.Context, key string, ttl time.Duration) (unlock func(), err error)
}

// ErrLocked 表示同一目标的合并正在进行中。
var ErrLocked = errors.New("merge: 该目标账号的合并正在进行中")

// Impact 是一次合并的影响面预估（管理端 D 组 impact 端点）。
//
// 为什么要单独提供：合并是高风险不可逆操作，管理端在执行前必须能回答
// "会动到多少条数据"。没有这个数字，二次确认弹窗就只能写"确定要合并吗"。
type Impact struct {
	// Bindings 是 source 账号下将被改挂的活跃绑定数。
	Bindings int64
	// Tokens 是 source 账号下将被撤销的未失效令牌数。
	Tokens int64
	// Identities 是被改挂的 identity 摘要（平台:场景），供人工核对。
	Identities []string
}

// Impactor 计算合并影响面。
type Impactor interface {
	Estimate(ctx context.Context, appID int64, sourceUserID string) (*Impact, error)
}
