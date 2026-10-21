package merge

import (
	"context"
	"errors"
	"time"
)

// 验证码挑战的默认参数。
//
// 这几个数字是安全参数，不是"随手定的常量"：
//
//	MaxVerifyAttempts 5   6 位码有 100 万种组合，5 次尝试成功率 5e-6；
//	                      再多一个数量级就足以被脚本刷开。
//	ResendInterval    60s 重发间隔既防短信轰炸（成本与投诉），
//	                      也让"换一条短信再猜"慢到不划算。
//	CodeTTL           5m  与票据 TTL 一致：票据没了，码也不该还活着。
const (
	MaxVerifyAttempts = 5
	ResendInterval    = 60 * time.Second
	CodeTTL           = 5 * time.Minute
	CodeLength        = 6
)

// 验证环节的哨兵错误。
var (
	// ErrCodeMismatch 表示验证码不匹配（仍可重试）。
	ErrCodeMismatch = errors.New("merge: 验证码不正确")
	// ErrTooManyAttempts 表示尝试次数耗尽，票据已作废。
	ErrTooManyAttempts = errors.New("merge: 验证码尝试次数过多")
	// ErrResendTooSoon 表示两次发送间隔不足。
	ErrResendTooSoon = errors.New("merge: 发送过于频繁，请稍后再试")
	// ErrChallengeMissing 表示还没发过码就来校验。
	ErrChallengeMissing = errors.New("merge: 尚未发送验证码")
	// ErrNoVerifiedPhone 表示旧账号在用户中心没有可用于验证的手机号。
	ErrNoVerifiedPhone = errors.New("merge: 该账号没有可用于验证的手机号")
)

// Challenge 是一次短信验证码挑战。
//
// 只存 code 的哈希，不存明文：Redis 快照、备份、运维误 cat 都不应该
// 直接泄露"当前有效的验证码"。加盐用 TicketID，避免同一批 6 位码的
// 哈希可以被预先算好（6 位空间只有 100 万，不加盐等于裸奔）。
type Challenge struct {
	TicketID    string
	CodeHash    string
	PhoneMasked string
	Attempts    int
	SentAt      time.Time
}

// Exhausted 判断尝试次数是否已耗尽。
func (c *Challenge) Exhausted() bool {
	return c != nil && c.Attempts >= MaxVerifyAttempts
}

// ChallengeStore 是验证码挑战的存储端口。
type ChallengeStore interface {
	Save(ctx context.Context, c *Challenge, ttl time.Duration) error
	Get(ctx context.Context, ticketID string) (*Challenge, error)
	// BumpAttempt 原子地把 attempts +1 并返回新值。
	//
	// 必须原子：并发提交多个错误码时，"读-改-写"会让 attempts 停在 1，
	// 限次形同虚设。
	BumpAttempt(ctx context.Context, ticketID string) (int, error)
	Delete(ctx context.Context, ticketID string) error
}

// CodeSender 是短信发送端口。
//
// 只暴露"发一条验证码"这一件事：本服务不需要模板管理、不需要送达回执，
// 那些属于短信服务商的职责。实现见 infrastructure/sms。
type CodeSender interface {
	Send(ctx context.Context, req CodeRequest) error
}

// CodeRequest 是一条验证码短信。
type CodeRequest struct {
	// Phone 是明文号码，仅在内存中传递，禁止写日志。
	Phone   string
	Code    string
	Purpose string
	TTL     time.Duration
}
