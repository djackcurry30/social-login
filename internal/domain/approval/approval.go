// Package approval 是管理端高危操作的双人复核（§15.5）。
//
// 它解决的是一个"单人权限过大"的问题：密钥轮换、渠道凭证轮换这类操作
// 一次误点就会让全站登录故障或让旧凭证继续可用，而单个账号被窃取时
// 不该有能力独自完成。审批单是唯一的"第二个人"载体。
//
// 三条硬约束（都落在数据层，不靠调用方自觉）：
//
//  1. 申请人 ≠ 批准人（数据库 CHECK + 应用层双重校验）；
//  2. 一次性（consumed_at 非空即作废，且消费是条件 UPDATE）；
//  3. 绑定动作与目标（action + app_id 不匹配的审批单无法用于别的接口）。
package approval

import (
	"context"
	"errors"
	"time"
)

// Status 是审批单状态。
type Status string

const (
	// StatusPending 待批准。
	StatusPending Status = "pending"
	// StatusApproved 已批准、待执行（尚未消费）。
	StatusApproved Status = "approved"
	// StatusRejected 已驳回。
	StatusRejected Status = "rejected"
	// StatusConsumed 已执行（一次性，不能再用于第二次操作）。
	StatusConsumed Status = "consumed"
)

// 常用动作标识。与审计 action 同一套命名，便于把"谁批的"和"谁做的"对上。
const (
	ActionAppRotateSecret    = "app.rotate_secret"
	ActionConfigRotateSecret = "config.rotate"
	ActionKeyRotate          = "key.rotate"
)

// DefaultTTL 是审批单有效期。
//
// 30 分钟：够走完"申请 → 找人批 → 执行"，又短到不会让一张批过的单子
// 在几小时后被翻出来用。审批的上下文（谁要做什么、为什么）会随时间失效。
const DefaultTTL = 30 * time.Minute

// Approval 是一张审批单。
type Approval struct {
	ID          int64
	Action      string
	AppID       *int64
	PayloadHash string
	RequestedBy int64
	RequestedAt time.Time
	Reason      string
	Status      Status
	ApprovedBy  *int64
	ApprovedAt  *time.Time
	ConsumedAt  *time.Time
	ExpiresAt   time.Time
}

// Effective 报告审批单在 at 时刻是否可用于执行。
func (a *Approval) Effective(at time.Time) bool {
	if a == nil {
		return false
	}
	return a.Status == StatusApproved && a.ConsumedAt == nil && at.Before(a.ExpiresAt)
}

// 领域错误。调用方（application 层）负责翻译成对外错误码。
var (
	ErrNotFound    = errors.New("approval: 不存在")
	ErrNotPending  = errors.New("approval: 不是待批准状态")
	ErrSelfApprove = errors.New("approval: 不能批准自己提交的申请")
	ErrExpired     = errors.New("approval: 已过期")
	ErrNotApproved = errors.New("approval: 未批准或已消费")
	ErrMismatch    = errors.New("approval: 审批单与本次操作不匹配")
)

// Filter 是列表查询条件。
type Filter struct {
	Status Status
	// RequestedBy 非 0 时只返回该管理员提交的单子（非超管只能看自己的）。
	RequestedBy int64
	Limit       int
}

// Store 是审批单持久化端口。
//
// Approve / Reject / Consume 都是【条件更新】：把"状态对不对"的判断放进
// SQL 的 WHERE，而不是先查再写。先查再写会在两个并发请求之间留窗口，
// 而这里恰好是"两个人同时点批准"和"同一张单被执行两次"的高发场景。
type Store interface {
	Create(ctx context.Context, a *Approval) error
	Get(ctx context.Context, id int64) (*Approval, error)
	List(ctx context.Context, f Filter) ([]*Approval, error)
	// Approve 把 pending 置为 approved。approverID == requested_by 时返回 ErrSelfApprove。
	Approve(ctx context.Context, id, approverID int64, at time.Time) error
	Reject(ctx context.Context, id, approverID int64, at time.Time) error
	// Consume 校验并消费：只有 approved、未消费、未过期、action/app 匹配才成功。
	Consume(ctx context.Context, id int64, action string, appID *int64, at time.Time) error
}
