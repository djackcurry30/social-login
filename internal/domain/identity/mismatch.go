// mismatch.go 是凭证漂移（claim mismatch）的记录与排查模型（J 组 / §8.5）。
//
// 术语先说清楚，否则这张表很容易被误解成"另一个事件表"：
//
//	identity_claims    "某次授权中，某平台【证明过】这个身份拥有该手机号"
//	用户中心           "这个手机号【当前】属于哪个账号"——权威源
//
// 两者天生会漂移：用户换了手机号、解绑了手机、两个业务账号被人工调过。
// §8.5 的结论是"宁可漏归并，不可错归并"，所以归并前必须回源核对，
// 核对不一致就拒绝归并。被拒绝的那一刻会留下一条【漂移记录】，
// 这就是本文件的对象。
//
// 为什么漂移记录需要状态（open / resolved）而不只是日志：
// "还有多少条漂移没处理"是一个要被盯的指标（§8.5 的 claim_mismatch_total）。
// 日志可以被轮转掉，事件出队后就没法再查，只有事实表能回答
// "现在还剩几条、每条是谁在什么时候处理的"。
package identity

import (
	"context"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// 漂移类型。取值会写进 claim_mismatches.kind，且有 CHECK 约束兜底。
const (
	// MismatchAccountNotFound 用户中心说没有任何账号持有该凭证。
	// 典型成因：用户在该业务系统里换号 / 解绑了手机，本服务的 claim 还没撤销。
	MismatchAccountNotFound = "account_not_found"

	// MismatchAccountMismatch 用户中心返回的账号 ≠ 本地绑定所在账号。
	// 最危险的一类：两边对"这个身份属于谁"的判断已经分叉，
	// 自动归并会把错误放大，必须人工判定以哪边为准。
	MismatchAccountMismatch = "account_mismatch"

	// MismatchMultipleAccounts 该凭证在用户中心命中多个账号。
	// 数据侧已有脏数据（同一手机号被两个账号占用），本服务无从判断。
	MismatchMultipleAccounts = "multiple_accounts"

	// MismatchIdentityMissing claim 指向的 identity 已不存在。
	// 多半是数据清理 / 人工删除留下的孤儿记录——这条 claim 已经无法
	// 用于归并，撤销它即可闭环。
	MismatchIdentityMissing = "identity_missing"
)

// 漂移记录状态。
const (
	MismatchStatusOpen     = "open"
	MismatchStatusResolved = "resolved"
)

// IsValidMismatchKind 判断类型取值是否合法（对外入参校验用）。
func IsValidMismatchKind(kind string) bool {
	switch kind {
	case MismatchAccountNotFound, MismatchAccountMismatch,
		MismatchMultipleAccounts, MismatchIdentityMissing:
		return true
	}
	return false
}

// Mismatch 是一条凭证漂移记录。
type Mismatch struct {
	ID         int64
	AppID      int64
	ClaimID    int64
	IdentityID int64
	ClaimType  string
	// ValueHash 完整保存：运维要拿它跟 identity_claims 比对，
	// 对外展示时才截前缀（与 ClaimItem 同口径）。
	ValueHash   string
	Platform    string
	ClaimSource string
	Kind        string
	// ExpectedUserID / ActualUserID 是分叉的两侧：
	// 本地绑定认为该凭证属于谁、用户中心说它属于谁。任一都可能为空。
	ExpectedUserID string
	ActualUserID   string
	Detail         string
	Status         string
	// Occurrences > 1 说明这处漂移长期存在、每次登录都命中。
	Occurrences int
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	ResolvedAt  *time.Time
	ResolvedBy  string
	Resolution  string
}

// MismatchRecordInput 是记录一条漂移的入参。
type MismatchRecordInput struct {
	AppID          int64
	ClaimID        int64
	IdentityID     int64
	ClaimType      string
	ValueHash      string
	Platform       string
	ClaimSource    string
	Kind           string
	ExpectedUserID string
	ActualUserID   string
	Detail         string
	At             time.Time
}

// MismatchRecorder 是漂移记录的写入端口。
//
// 单独一个只写接口，是因为登录链路（authflow）只需要写：把查询与闭环
// 一起塞给授权链路，会让核心路径为运维需求背债（与 AdminLister 同一考虑）。
//
// 【实现契约】Record 必须是幂等 upsert：
// 同一 (app_id, claim_id, kind) 在 open 状态下只累加 occurrences，
// 不新增行。理由见 migrations/00006 的注释——漂移是持续状态不是离散事件。
type MismatchRecorder interface {
	Record(ctx context.Context, in MismatchRecordInput) error
}

// MismatchAdminQuery 是管理端漂移列表的筛选条件。
type MismatchAdminQuery struct {
	AppID      int64
	Status     string
	Kind       string
	ClaimType  string
	IdentityID int64
	Page       int
	PageSize   int
}

// MismatchRepository 是 J 组漂移记录的完整持久化端口。
type MismatchRepository interface {
	MismatchRecorder

	// ListAdmin 分页查询漂移记录。返回值含 total 以便前端展示"还有 N 条"。
	ListAdmin(ctx context.Context, q MismatchAdminQuery) ([]Mismatch, int64, error)

	// ResolveByClaim 把某条 claim 下所有未闭环的漂移标记为已闭环。
	//
	// 为什么由"撤销 claim"触发而不是单独一个 resolve 端点：
	// 漂移的根因几乎都是"这条 claim 已经不代表事实"，人工判断后能做的
	// 唯一有效动作就是撤销它。撤销了却不闭环，指标就永远降不下来——
	// 一个只涨不落的数字，运维很快就不看了。
	// 需要保留 claim（例如"确认以用户中心为准，claim 继续有效"）时，
	// 调用方只调本方法闭环记录、不调 Revoke，语义同样成立。
	ResolveByClaim(ctx context.Context, in ResolveInput) (int64, error)
}

// ResolveInput 是闭环漂移的入参。
type ResolveInput struct {
	AppID      int64
	ClaimID    int64
	By         string
	Resolution string
	At         time.Time
}

// Validate 校验写入入参。
func (in MismatchRecordInput) Validate() error {
	if in.AppID <= 0 || in.ClaimID <= 0 {
		return errs.New(errs.CodeInternal, "漂移记录缺少 app_id 或 claim_id")
	}
	if !IsValidMismatchKind(in.Kind) {
		return errs.Newf(errs.CodeInternal, "未知的漂移类型: %s", in.Kind)
	}
	if in.ClaimType == "" {
		return errs.New(errs.CodeInternal, "漂移记录缺少 claim_type")
	}
	return nil
}
