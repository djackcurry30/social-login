// Package account 定义账号体系的端口（约束 C4：remote 模式）。
//
// 本服务【不持有账号主数据】——没有 accounts 表。账号由独立的用户中心持有，
// 本服务只通过本接口访问。这样做的收益是避免出现第二份用户数据（必然不一致），
// 代价是首次三方登录无法独立完成（见 §5.2 的未绑定分支）。
package account

import (
	"context"
	"errors"
)

// ErrNotFound 表示账号在用户中心不存在。
var ErrNotFound = errors.New("account: not found")

// 账号状态。
type Status string

const (
	StatusActive Status = "active"
	StatusFrozen Status = "frozen"
	StatusClosed Status = "closed"
)

// Claim 是一条已验证凭证。语义与 identity.Claim 一致：
// 它说明"用户中心当前认可这个值属于该账号"，因此可以用于归并判定。
type Claim struct {
	Type  string // phone | email
	Value string
	// Source 取值必须来自 identity 包的权威枚举（R4 白名单的判定依据）。
	Source string
}

// Account 是用户中心返回的账号视图。
type Account struct {
	UserID string
	Status Status
	// Claims 是该账号当前有效的已验证凭证，用于回源核对（修正 P0-6）。
	Claims []Claim
	Extra  map[string]any
}

// CreateRequest 是创建账号的入参。
type CreateRequest struct {
	// Claims 是本次授权中平台已验证的凭证，供用户中心落库。
	Claims    []Claim
	Nickname  string
	AvatarURL string
	// IdempotencyKey 保证重复调用不会产生两个账号——
	// 首次登录可能因网络原因被接入方重试，没有幂等键就会建出重复账号。
	IdempotencyKey string
}

// MergeRequest 是账号合并的入参。
//
// ⚠️ IdempotencyKey 是必填项（修正 P0-4）。合并是"调用远端成功后本地可能失败、
// 需要补偿重试"的跨服务操作；若用户中心不按幂等键去重，补偿重试会重复迁移
// 订单、资产等数据，造成不可逆的业务损坏。这是与用户中心对齐时的硬性要求。
type MergeRequest struct {
	TargetUserID   string
	SourceUserID   string
	IdempotencyKey string
	Reason         string
}

// MergeResult 是合并结果。
type MergeResult struct {
	// Merged 表示本次调用实际执行了合并。
	Merged bool
	// AlreadyMerged 表示幂等命中——此前已用同一幂等键合并过。
	AlreadyMerged bool
	// RemoteRef 是用户中心返回的排障引用，写入 merge_operations.remote_result。
	RemoteRef map[string]any
}

// Provider 是账号体系的 SPI。
//
// 生产实现为 HTTPAccountProvider；用户中心尚未就位时用 StubAccountProvider
// 打通链路（接口不将就，实现可以先桩）。
type Provider interface {
	// Get 按 user_id 查询账号。不存在返回 ErrNotFound。
	//
	// 用户中心不可用时的降级行为（架构 §6.2）：登录链路快速失败
	// （因为我们无法确认账号状态），但已签发的 access_token 仍然有效（本地验签）。
	Get(ctx context.Context, userID string) (*Account, error)

	// GetByClaim 按已验证凭证反查账号，用于归并前的回源核对与冲突排查。
	//
	// ⚠️ 必须【强一致读】，不能用有延迟的从库——否则回源核对本身就可能读到
	// 过期数据，P0-6 的防线失效（架构 §8.5 与 §13 并行事项）。
	GetByClaim(ctx context.Context, claim Claim) (*Account, error)

	// Create 创建账号。用户中心未提供该能力时返回
	// errs.CodeAccountNotSupported，此时首次三方登录只能走「引导注册」流程。
	Create(ctx context.Context, req CreateRequest) (*Account, error)

	// Merge 把 source 账号合并进 target。
	//
	// 由用户中心决定其内部数据（订单、资料、外键）如何迁移。必须：
	//   - 接收并真正使用 IdempotencyKey 去重
	//   - 完成后向本服务推送 account.merged 事件，或由本服务在本地收敛后发事件
	Merge(ctx context.Context, req MergeRequest) (*MergeResult, error)
}
