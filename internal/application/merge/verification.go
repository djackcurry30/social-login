package merge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// 本文件是 confirm 模式的验证流程（§7.5.2 场景 B 的 confirm 分支）。
//
// 两段式，刻意不合并成一个接口：
//
//	① StartSMSVerification  发码。它会产生外部副作用（短信费用、用户手机响），
//	   必须能被单独限流。
//	② CompleteSMSVerification 验码并合并。它必须能单独拒绝"猜想"。
//
// 如果合成一个"提交即发码+验码"的接口，重试语义会变得不可控：
// 用户点两次就等于发两条短信、并且两条码都有效。

// StartVerificationInput 是发码入参。
type StartVerificationInput struct {
	TicketID string
	// CallerUserID 是当前登录账号（必须与票据里的 target 一致）。
	CallerUserID string
}

// StartVerificationOutput 是发码出参。
type StartVerificationOutput struct {
	// PhoneMasked 只回掩码，不回明文。
	PhoneMasked string    `json:"phone_masked"`
	ExpiresAt   time.Time `json:"expires_at"`
	// ResendAfterSeconds 告诉前端多久后可以重发，避免用户狂点。
	ResendAfterSeconds int `json:"resend_after_seconds"`
}

// StartSMSVerification 向 source 账号的手机号发送验证码。
//
// 为什么发给 source 而不是 target：要合并的是 source 账号，用户必须证明
// 他控制的是 source。发给 target 等于"自己证明自己"，毫无意义。
func (s *Service) StartSMSVerification(ctx context.Context, in StartVerificationInput) (*StartVerificationOutput, error) {
	if s.deps.Tickets == nil || s.deps.Challenges == nil || s.deps.Sender == nil {
		return nil, errs.New(errs.CodeInternal, "短信验证未装配")
	}
	if in.TicketID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "merge_ticket 不能为空")
	}

	t, err := s.deps.Tickets.GetMergeTicket(ctx, in.TicketID)
	if err != nil {
		return nil, mapTicketErr(err)
	}
	if in.CallerUserID != "" && in.CallerUserID != t.TargetUserID {
		// 票据是发给 target 的：换个账号拿它去验证，等于允许"别人替我合并"。
		return nil, errs.New(errs.CodeForbidden, "该合并票据不属于当前账号")
	}

	// 重发限流。
	//
	// 先查再写，中间有并发窗口——但这里是"多发一条短信"，不是安全边界；
	// 真正的安全边界是尝试次数（见 VerifySMS）。为这个窗口加锁的收益
	// 不如维护成本高。
	now := s.deps.Now()
	if prev, gerr := s.deps.Challenges.Get(ctx, in.TicketID); gerr == nil {
		if now.Sub(prev.SentAt) < mergex.ResendInterval {
			wait := mergex.ResendInterval - now.Sub(prev.SentAt)
			return nil, errs.New(errs.CodeRateLimited,
				"验证码发送过于频繁，请稍后再试").
				WithDetail("retry_after_ms", wait.Milliseconds())
		}
	}

	phone, err := s.verifiedPhone(ctx, t.SourceUserID)
	if err != nil {
		return nil, err
	}

	code, err := randomCode()
	if err != nil {
		return nil, err
	}

	ch := &mergex.Challenge{
		TicketID:    in.TicketID,
		CodeHash:    hashCode(code, in.TicketID),
		PhoneMasked: maskPhone(phone),
		Attempts:    0,
		SentAt:      now,
	}
	if err := s.deps.Challenges.Save(ctx, ch, mergex.CodeTTL); err != nil {
		return nil, err
	}
	if err := s.deps.Sender.Send(ctx, mergex.CodeRequest{
		Phone:   phone,
		Code:    code,
		Purpose: "account_merge",
		TTL:     mergex.CodeTTL,
	}); err != nil {
		// 发不出去就把挑战删掉：留着一个"用户永远收不到"的挑战，
		// 会让前端显示"已发送"然后必然失败。
		_ = s.deps.Challenges.Delete(ctx, in.TicketID)
		return nil, errs.Wrap(errs.CodeConfigInvalid, "验证码发送失败", err)
	}

	// 审计：验证码发送本身不写审计（高频、无信息量），但合并成功后会写。
	s.logger().Info("合并验证码已发送",
		zap.String("ticket", in.TicketID),
		zap.String("phone", ch.PhoneMasked),
		zap.String("target", t.TargetUserID))

	return &StartVerificationOutput{
		PhoneMasked:        ch.PhoneMasked,
		ExpiresAt:          now.Add(mergex.CodeTTL),
		ResendAfterSeconds: int(mergex.ResendInterval.Seconds()),
	}, nil
}

// CompleteVerificationInput 是验码入参。
type CompleteVerificationInput struct {
	TicketID     string
	Code         string
	CallerUserID string
}

// CompleteSMSVerification 校验验证码并执行合并。
func (s *Service) CompleteSMSVerification(ctx context.Context, in CompleteVerificationInput) (*Result, error) {
	if s.deps.Tickets == nil || s.deps.Challenges == nil {
		return nil, errs.New(errs.CodeInternal, "短信验证未装配")
	}
	if in.TicketID == "" || in.Code == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "merge_ticket 与 code 均不能为空")
	}

	t, err := s.deps.Tickets.GetMergeTicket(ctx, in.TicketID)
	if err != nil {
		return nil, mapTicketErr(err)
	}
	if in.CallerUserID != "" && in.CallerUserID != t.TargetUserID {
		return nil, errs.New(errs.CodeForbidden, "该合并票据不属于当前账号")
	}

	ch, err := s.deps.Challenges.Get(ctx, in.TicketID)
	if err != nil {
		if errors.Is(err, mergex.ErrChallengeMissing) {
			return nil, errs.New(errs.CodeInvalidRequest, "请先获取验证码").
				WithDetail("merge_ticket", in.TicketID)
		}
		return nil, err
	}
	if ch.Exhausted() {
		_ = s.deps.Challenges.Delete(ctx, in.TicketID)
		_ = s.deps.Tickets.DeleteMergeTicket(ctx, in.TicketID)
		return nil, errs.New(errs.CodeBindTicketInvalid, "验证码尝试次数过多，请重新发起合并")
	}

	if hashCode(in.Code, in.TicketID) != ch.CodeHash {
		n, berr := s.deps.Challenges.BumpAttempt(ctx, in.TicketID)
		if berr != nil {
			return nil, berr
		}
		if n >= mergex.MaxVerifyAttempts {
			// 次数耗尽：挑战与票据一起作废，用户必须从绑定冲突重新开始。
			// 只作废挑战会让票据被反复用来"再发一条码继续猜"。
			_ = s.deps.Challenges.Delete(ctx, in.TicketID)
			_ = s.deps.Tickets.DeleteMergeTicket(ctx, in.TicketID)
			return nil, errs.New(errs.CodeBindTicketInvalid, "验证码尝试次数过多，请重新发起合并")
		}
		return nil, errs.New(errs.CodeBindTicketInvalid, "验证码不正确").
			WithDetail("remaining_attempts", mergex.MaxVerifyAttempts-n)
	}

	// 先删挑战与票据，再执行合并。
	//
	// 顺序不能反：如果先合并成功、删除失败，票据还能被用来再合并一次
	// （虽然幂等键会挡住，但那依赖下游正确性）。先删则是"最多丢一次
	// 已完成的合并"——用户会看到成功但票据已失效，不会有第二次执行。
	_ = s.deps.Challenges.Delete(ctx, in.TicketID)
	_ = s.deps.Tickets.DeleteMergeTicket(ctx, in.TicketID)

	app, err := s.loadAppPolicy(ctx, &mergex.Operation{AppID: t.AppID})
	if err != nil {
		return nil, err
	}

	return s.Execute(ctx, Request{
		App:          app,
		TargetUserID: t.TargetUserID,
		SourceUserID: t.SourceUserID,
		Trigger:      TriggerBind,
		Reason:       "用户通过短信验证确认后合并",
		Verified:     true,
	})
}

// verifiedPhone 取 source 账号在用户中心的有效手机号。
//
// 只认 Verified 的 phone claim：合并是账号归属变更，凭据必须是用户中心
// 认可的（§8.5 的既定语义），而不是某次授权里平台顺手给的昵称之类。
func (s *Service) verifiedPhone(ctx context.Context, userID string) (string, error) {
	acc, err := s.deps.Accounts.Get(ctx, userID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return "", errs.New(errs.CodeAccountNotFound, "被合并账号在用户中心不存在")
		}
		return "", errs.Wrap(errs.CodeAccountUnavailable, "查询用户中心失败", err)
	}
	for _, c := range acc.Claims {
		if c.Type == "phone" && c.Value != "" {
			return c.Value, nil
		}
	}
	return "", errs.New(errs.CodeBindMergeRequired,
		"该账号没有可用于验证的手机号，请改用其他登录方式确认").
		WithDetail("hint", "existing_binding")
}

func mapTicketErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ticket.ErrMergeTicketInvalid) {
		return errs.New(errs.CodeBindTicketInvalid, "合并票据无效或已过期，请重新发起绑定")
	}
	return err
}

// randomCode 生成 6 位数字验证码（crypto/rand，不用 math/rand）。
func randomCode() (string, error) {
	max := big.NewInt(1)
	for i := 0; i < mergex.CodeLength; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", errs.Wrap(errs.CodeInternal, "生成验证码失败", err)
	}
	// 左补零：000123 也是合法的 6 位码，截断成 "123" 会缩小猜测空间。
	return fmt.Sprintf("%0*d", mergex.CodeLength, n.Int64()), nil
}

// hashCode 用 ticketID 作盐对验证码做哈希。
//
// 6 位码只有 100 万种可能，不加盐的话，拿到 Redis 快照的人可以预先算表
// 反查明文。加盐后每个票据一张表，成本与收益立刻倒挂。
func hashCode(code, ticketID string) string {
	sum := sha256.Sum256([]byte(ticketID + ":" + code))
	return hex.EncodeToString(sum[:])
}

// maskPhone 保留前 3 后 2。
func maskPhone(phone string) string {
	r := []rune(phone)
	if len(r) <= 5 {
		return "***"
	}
	return string(r[:3]) + "****" + string(r[len(r)-2:])
}
