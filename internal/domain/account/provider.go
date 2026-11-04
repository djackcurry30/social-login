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

// ErrMultipleAccounts 表示按凭证反查命中了多个账号。
//
// 这不是"随便挑一个"的场景（§7.4 通用护栏）：一个手机号对应多个账号说明
// 用户中心的唯一性已经被破坏，自动归并进去无论选哪个都是错的。
var ErrMultipleAccounts = errors.New("account: multiple accounts matched")

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
	// AppKey 是账号所属的租户（= applications.app_code）。
	//
	// 账号空间边界是业务应用（约束 C1）：App1 与 App2 里同一个自然人是两个
	// 互不相干的账号。缺了它，用户中心只能有一个全局账号空间——App2 首次
	// 登录会命中 App1 的账号，那不是"多应用不方便"，是数据越权。
	AppKey string
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
	// AppKey 是账号所属的租户。合并必须校验两端同属一个应用（R3 要求
	// 拒绝跨应用合并），因此这个字段是判定依据，不只是路由前缀。
	AppKey         string
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
	// DiscardedClaims 是因"一个账号每类凭证只能有一条活跃"而被丢弃的凭证。
	//
	// 合并时 target 已持有同类型凭证（例如双方各有一个手机号），source 那条
	// 只能撤销。这个信息必须回传：否则用户侧对"我另一个号去哪了"完全无感知，
	// 客服也查不出原因，只能反复猜。
	DiscardedClaims []Claim
	// RemoteRef 是用户中心返回的排障引用，写入 merge_operations.remote_result。
	RemoteRef map[string]any
}

// ReplaceClaimRequest 是换绑某类型凭证的入参。
type ReplaceClaimRequest struct {
	AppKey string
	UserID string
	// Claim 是新的凭证值。它的 Type 决定替换哪一类（phone / email）。
	Claim Claim
}

// ClaimReplacer 是"换绑凭证"这一能力的可选端口。
//
// 为什么不并进 Provider：Provider 是登录链路的最小必需集合，换绑目前只有
// 管理端运维场景会用（P1 才接登录链路）。并进去会让所有实现方（含测试替身）
// 都被迫实现一个当下无人调用的方法。
//
// 调用方按需做类型断言：
//
//	if r, ok := provider.(account.ClaimReplacer); ok { ... }
//
// 这比在 Provider 上挂一个会返回 NOT_SUPPORTED 的方法更诚实——能力是否
// 存在，编译期就知道。
type ClaimReplacer interface {
	// ReplaceClaim 原子替换某账号某类型的凭证。
	//
	// 语义要求：
	//   - 新值已属于本账号同类 → 幂等成功（no-op），不报错
	//   - 新值被其他账号持有 → 返回 errs.CodeBindIdentityTaken
	//   - 替换与撤销必须在同一事务内完成，中间态不可见
	ReplaceClaim(ctx context.Context, req ReplaceClaimRequest) (*Account, error)
}

// AccountCloser 是"注销账号"这一能力的可选端口。
//
// 与 ClaimReplacer 同样是可选端口，理由相同：Provider 是登录链路的最小
// 必需集合，而"注销"只被主动注销流程调用。并且它【必须可缺省】——
// 账号状态的权威在用户中心（约束 C4），没有对端时根本无处可注销，
// 此时调用方要能明确地拒绝，而不是假装注销成功。
//
// 语义要求：
//   - 幂等：账号已是 closed、或对端返回 ACCOUNT.NOT_FOUND，都算成功。
//     重复注销是本流程的正常路径（客户端超时重试、以及"本地级联失败后
//     用户再点一次"），把已注销当成错误会让用户永远卡在中间态。
//   - 这是【不可逆】操作。实现方不得为了"看起来更友好"而做软关闭——
//     软关闭意味着用户可以继续用旧令牌访问，而界面告诉他账号已删除。
type AccountCloser interface {
	// Close 把某账号置为已注销（closed）。
	Close(ctx context.Context, appKey, userID string) error
}

// Provider 是账号体系的 SPI。
//
// 生产实现为 HTTPAccountProvider；用户中心尚未就位时用 StubAccountProvider
// 打通链路（接口不将就，实现可以先桩）。
type Provider interface {
	// Get 按 user_id 查询账号。不存在返回 ErrNotFound。
	//
	// appKey 是查询的租户范围：user_id 只在应用内唯一，同一个 id 在别的应用
	// 里可能属于另一个自然人的账号。
	//
	// 用户中心不可用时的降级行为（架构 §6.2）：登录链路快速失败
	// （因为我们无法确认账号状态），但已签发的 access_token 仍然有效（本地验签）。
	Get(ctx context.Context, appKey, userID string) (*Account, error)

	// GetByClaim 按已验证凭证反查账号，用于归并前的回源核对与冲突排查。
	//
	// ⚠️ 必须【强一致读】，不能用有延迟的从库——否则回源核对本身就可能读到
	// 过期数据，P0-6 的防线失效（架构 §8.5 与 §13 并行事项）。
	//
	// ⚠️ 应用范围是查询条件的一部分，不是附加过滤：同一个手机号在 App1 与
	// App2 是两条互不相干的记录，跨应用命中不是"多一条结果"，是查错了人。
	GetByClaim(ctx context.Context, appKey string, claim Claim) (*Account, error)

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
