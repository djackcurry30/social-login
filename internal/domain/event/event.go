// Package event 是 Webhook 事件外发的领域模型与端口。
//
// 为什么走 Transactional Outbox 而不是在业务逻辑里直接发 HTTP（架构 §5.4 / P0-3）：
// 事件与业务变更必须在同一个事务里落库。否则一旦"HTTP 已经发出、本地事务回滚"，
// 业务方看到的是账号被合并，而我们这边什么都没发生——不可逆的不一致。
//
// 投递语义是【至少一次】：同一 event_id 可能重复到达，业务方按 event_id 去重。
// 因此死信重投必须保留原 event_id（换新 ID 等于绕过对方的去重）。
package event

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 事件状态。
//
// 架构文档只列了 pending / sent / dead 三种。本实现额外引入两种，
// 都是为了"让状态自身说明问题"，而不是把异常塞进 last_error 里假装成功：
//
//	skipped   应用未配置 webhook_url。事件不该无限 pending 堆积，
//	          更不能标成 sent 骗过监控。
//	discarded 管理端人工丢弃（需 reason）。与 dead 分开是为了区分
//	          "投递失败进入死信"与"人主动放弃"。
const (
	StatusPending   Status = "pending"
	StatusSent      Status = "sent"
	StatusDead      Status = "dead"
	StatusSkipped   Status = "skipped"
	StatusDiscarded Status = "discarded"
)

// Status 是事件投递状态。
type Status string

// Valid 判断状态是否合法（用于查询参数校验）。
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusSent, StatusDead, StatusSkipped, StatusDiscarded:
		return true
	}
	return false
}

// MaxAttempts 是最大投递次数（§5.4：最多 5 次）。
const MaxAttempts = 5

// RetrySchedule 是固定退避序列（§5.4）：1s / 10s / 1min / 10min / 1h。
//
// 用固定序列而不是 2^n 计算，是因为前几档的取值被契约写死了；
// 算出来的值一旦偏离，业务方按文档实现的重试对齐就会失效。
var RetrySchedule = []time.Duration{
	1 * time.Second,
	10 * time.Second,
	1 * time.Minute,
	10 * time.Minute,
	1 * time.Hour,
}

// Backoff 返回第 attempts 次失败后应等待的时长。
//
// attempts 已包含本次失败（从 1 开始）。超出序列时取最后一档，
// 由 MaxAttempts 兜底转为死信。
func Backoff(attempts int) time.Duration {
	if attempts <= 0 {
		return RetrySchedule[0]
	}
	if attempts > len(RetrySchedule) {
		return RetrySchedule[len(RetrySchedule)-1]
	}
	return RetrySchedule[attempts-1]
}

// Event 是一条待外发的业务事件。
type Event struct {
	ID            int64
	AppID         int64
	EventID       string
	Type          string
	SchemaVersion int
	Payload       map[string]any
	Status        Status
	Attempts      int
	NextRetryAt   *time.Time
	LastError     string
	CreatedAt     time.Time
	SentAt        *time.Time
}

// 常用事件类型。
//
// 命名的意义在于业务方按 event_type 路由；同一个类型一旦发布就不能改语义，
// 需要改语义时升 SchemaVersion（§5.4 版本化约定）。
const (
	TypeLoginSucceeded  = "auth.login_succeeded"
	TypeBindingCreated  = "binding.created"
	TypeBindingRemoved  = "binding.removed"
	TypeAccountMerged   = "account.merged"
	TypeIdentityRevoked = "identity.revoked"
)

// ErrNotFound 表示事件不存在。
var ErrNotFound = errors.New("event: 事件不存在")

// ErrNoWebhook 表示应用未配置 webhook_url。
//
// 单独成哨兵而不是普通错误：dispatcher 要把事件标成 skipped 而不是反复重试
// 到死信——"没配"是配置状态，不是投递故障。
var ErrNoWebhook = errors.New("event: 应用未配置 webhook_url")

// PermanentError 表示重试也不会成功（对方返回 4xx 且不是 408/429）。
//
// 与可重试错误分开，是为了不把 5 次重试浪费在必然失败的请求上，
// 也让死信里能直接看出"对方拒收"而不是"我们没送到"。
type PermanentError struct {
	StatusCode int
	Body       string
}

// Error 实现 error。
func (e *PermanentError) Error() string {
	return fmt.Sprintf("event: 对方拒收（HTTP %d）: %s", e.StatusCode, e.Body)
}

// IsPermanent 判断错误是否不可重试。
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// Filter 是管理端查询条件。零值字段表示不过滤。
type Filter struct {
	AppID    int64
	Status   Status
	Type     string
	From     *time.Time
	To       *time.Time
	Page     int
	PageSize int
}

// Store 是 outbox 的持久化端口。
type Store interface {
	// Append 追加一条事件。必须在业务事务内调用（见包注释）。
	Append(ctx context.Context, e *Event) error

	// ClaimDue 以"租约"方式领取最多 limit 条到期事件。
	//
	// 多副本必须靠它互斥：实现用 SELECT ... FOR UPDATE SKIP LOCKED 并在同一
	// 事务里把 next_retry_at 推到租约到期时间，其它副本自然跳过。
	ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]*Event, error)

	MarkSent(ctx context.Context, id int64) error
	MarkRetry(ctx context.Context, id int64, attempts int, next time.Time, lastErr string) error
	MarkDead(ctx context.Context, id int64, attempts int, lastErr string) error
	MarkSkipped(ctx context.Context, id int64, reason string) error

	Get(ctx context.Context, id int64) (*Event, error)
	List(ctx context.Context, f Filter) ([]*Event, int64, error)

	// Restore 把事件重置为待投递（死信重投）。attempts 归零，
	// event_id 【不变】——业务方按它去重。
	Restore(ctx context.Context, id int64) error

	// Discard 人工丢弃。
	Discard(ctx context.Context, id int64, reason string) error
}

// NewEventID 生成事件 ID（时间有序 + 随机后缀）。
//
// 不用 UUIDv4 是因为排障时按 ID 排序希望近似到达顺序；
// 不用严格 ULID 是为了不引入依赖——前缀毫秒时间戳 + 10 字节随机，
// 冲突概率足够低，且天然可排序。
func NewEventID(now time.Time) string {
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败意味着系统熵源异常，此时继续生成可预测 ID
		// 比直接失败更危险；但也不能返回空串——用时间兜底。
		return timeIDPrefix(now) + strings.Repeat("0", 16)
	}
	return timeIDPrefix(now) + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
}

func timeIDPrefix(now time.Time) string {
	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte{
			byte(now.UnixMilli() >> 40),
			byte(now.UnixMilli() >> 32),
			byte(now.UnixMilli() >> 24),
			byte(now.UnixMilli() >> 16),
			byte(now.UnixMilli() >> 8),
			byte(now.UnixMilli()),
		}))
}
