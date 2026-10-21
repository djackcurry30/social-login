// Package ticket 是一次性票据机制（决策 D5）。
//
// 为什么全部流程都靠票据：回调 URL 只需要 /v1/oauth/callback/{platform} 一个，
// 全部上下文（appId、platform、scene、redirectUri、mode、绑定目标账号、Apple nonce）
// 凭 state 从 Redis 反查。这样前端无法篡改流程参数，也无法伪造 redirectUri
// 做开放重定向（架构 §5.2）。
//
// 票据生命周期：
//
//	state（授权上下文）  5 min   授权往返的最长容忍时间
//	bind_ticket         10 min   NEED_REGISTER 后引导用户注册/登录的时间
//	auth_code           60 s     回调后换令牌的一次性凭据
package ticket

import (
	"context"
	"errors"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/provider"
)

// 各类票据的默认有效期。
const (
	TTLContext    = 5 * time.Minute
	TTLBindTicket = 10 * time.Minute
	// TTLMergeTicket 是"待验证合并"的有效期。
	//
	// 比 bind_ticket 短：合并是账号归属变更，用户愿意验证就会当场完成；
	// 留 10 分钟窗口只扩大"手机不在身边时被别人拿走去验证"的机会。
	TTLMergeTicket = 5 * time.Minute
	TTLAuthCode    = 60 * time.Second
)

// 哨兵错误，便于调用方区分"过期"与"被篡改/不存在"。
var (
	// ErrContextExpired 表示授权上下文不存在或已过期（用户停留太久，或 state 被伪造）。
	ErrContextExpired = errors.New("ticket: context expired or not found")
	// ErrBindTicketInvalid 表示 bind_ticket 无效（伪造、已使用、或不属于该身份）。
	ErrBindTicketInvalid = errors.New("ticket: bind ticket invalid")
	// ErrAuthCodeInvalid 表示 auth_code 无效（伪造、已使用、或已过期）。
	ErrAuthCodeInvalid = errors.New("ticket: auth code invalid")
	// ErrMergeTicketInvalid 表示待验证合并票据无效（伪造、过期、或已被使用）。
	ErrMergeTicketInvalid = errors.New("ticket: merge ticket invalid")
)

// Context 是一次授权流程的服务端上下文。
//
// 注意 State 与 BusinessState 的区别：State 是本服务的票据 ID，BusinessState
// 是业务方透传的 state，本服务只原样回传、不做解释。
type Context struct {
	State     string
	AppID     int64
	AppCode   string
	Platform  string
	Scene     string
	ConfigKey string
	// Client 是承载形态，仅用于遥测与审计，不参与路由（规则 2）。
	Client string
	// Mode 是 provider.ModeLogin | provider.ModeBind。
	Mode string
	// RedirectURI 是最终回到业务方的地址，来自服务端配置，前端不可篡改。
	RedirectURI   string
	BusinessState string

	CodeChallenge       string
	CodeChallengeMethod string

	// Nonce 用于 Apple 的防重放（架构 §4.4）。
	Nonce string

	// BindExternalUserID 是 bind 模式下的目标业务账号。
	BindExternalUserID string

	CreatedAt time.Time
}

// BindTicket 是 NEED_REGISTER 分支返回的一次性绑定票据。
//
// 它存在的唯一理由是安全（修正 A16）：/v1/bind 若只凭"业务方说自己登了谁"就能
// 绑身份，那任何人都能把已存在的三方身份抢绑到自己名下。bind_ticket 与
// 【具体 identity】绑定，且一次性、10 分钟有效，因此无法被用来抢绑他人身份。
type BindTicket struct {
	Ticket     string
	AppID      int64
	AppCode    string
	IdentityID int64
	Platform   string
	Scene      string
	// Profile 是三方返回的展示资料快照，供业务方注册页预填。
	Profile   map[string]any
	CreatedAt time.Time
}

// MergeTicket 是 confirm 模式下"待验证合并"的上下文。
//
// 为什么不用 bind_ticket：bind_ticket 的语义是"把这个 identity 绑到我账号"，
// 而合并票据记录的是"对方账号是谁、我为什么要合并它"。两者的校验条件
// 与生命周期都不同，混用会让 bind_ticket 的防抢绑保证失效。
//
// ⚠️ 票据里不含任何验证码——验证码另行存放（见 merge.ChallengeStore），
// 且只存哈希。票据泄露不等于可以完成验证。
type MergeTicket struct {
	Ticket  string
	AppID   int64
	AppCode string
	// TargetUserID 是当前账号（用户已登录、主动发起绑定的一方）。
	TargetUserID string
	// SourceUserID 是被占用身份所属的旧账号（本次要并进来的一方）。
	SourceUserID string
	IdentityID   int64
	Platform     string
	Scene        string
	// Verification 是应用配置的验证强度（existing_binding | sms | strict）。
	Verification string
	CreatedAt    time.Time
}

// AuthCode 是一次性授权码，用于 /token 交换。
//
// 回调不直接返回令牌（架构 §5.2）：重定向 URL 会进入浏览器历史与 Referer，
// 直接带令牌不安全；而一次性 code 即使被截获也无法复用。
type AuthCode struct {
	Code           string
	AppID          int64
	AppCode        string
	ExternalUserID string
	IdentityID     int64
	Mode           string
	// Scope 决定业务方能否访问业务数据（见 identity.ScopeIdentityOnly）。
	Scope string
	// AMR 是认证方式，如 wechat:mini_program，写入令牌供业务方做风控。
	AMR       []string
	CreatedAt time.Time
}

// Store 是票据存储端口（Redis 实现）。
//
// Consume* 系列方法都是"读取即删除"语义：一次性票据被消费后必须立刻失效，
// 否则重放窗口依然存在。
type Store interface {
	SaveContext(ctx context.Context, c *Context, ttl time.Duration) error
	ConsumeContext(ctx context.Context, state string) (*Context, error)

	SaveBindTicket(ctx context.Context, t *BindTicket, ttl time.Duration) error
	ConsumeBindTicket(ctx context.Context, ticket string) (*BindTicket, error)

	SaveAuthCode(ctx context.Context, c *AuthCode, ttl time.Duration) error
	ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error)

	// SaveMergeTicket 保存待验证合并票据。
	SaveMergeTicket(ctx context.Context, t *MergeTicket, ttl time.Duration) error

	// GetMergeTicket 读取待验证合并票据（【不删除】）。
	//
	// 与 Consume* 不同：用户需要先用它发验证码、再用它提交验证码，
	// 同一条票据要被读两次。删除发生在验证成功或失败次数耗尽时。
	GetMergeTicket(ctx context.Context, ticketID string) (*MergeTicket, error)

	// DeleteMergeTicket 使票据失效（验证成功 / 次数耗尽 / 主动放弃）。
	DeleteMergeTicket(ctx context.Context, ticketID string) error

	// MarkReplay 记录票据指纹，用于重放检测告警（架构 §6.3）。
	// 注意命名与 Apple nonce 区分开：这里是"已消费票据指纹"，不是 nonce 库。
	MarkReplay(ctx context.Context, fingerprint string, ttl time.Duration) error
	// SeenReplay 判断指纹是否已出现过。
	SeenReplay(ctx context.Context, fingerprint string) (bool, error)
}

// AMR 构造认证方式标识，如 wechat:mini_program。
func AMR(platform, scene string) []string { return []string{provider.Key(platform, scene)} }
