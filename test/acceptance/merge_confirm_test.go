// Package acceptance 中的 merge_confirm_test.go：confirm 模式短信验证的真实依赖验收。
//
// 覆盖 §7.5.2 场景 B 的 confirm 分支全链路（除 HTTP 薄壳）：
//
//	签发合并票据 → 发码（验证码只存哈希）→ 提交错误码（限次）→ 提交正确码 → 合并收敛
//
// 为什么必须用真 Redis：验证码挑战与票据都是"读两次、一次性消费"的语义，
// 内存桩无法验证 TTL 与原子递增（BumpAttempt 用的是 Lua 脚本）。
package acceptance

import (
	"context"
	"testing"
	"time"

	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/infrastructure/cache"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
)

// captureSender 捕获发出去的验证码（不真正发短信）。
type captureSender struct {
	code  string
	phone string
	calls int
}

func (c *captureSender) Send(_ context.Context, req mergex.CodeRequest) error {
	c.calls++
	c.code = req.Code
	c.phone = req.Phone
	return nil
}

// newConfirmHarness 准备一个 confirm 模式的合并现场：
// identity 已绑在 source 上，source 在用户中心有手机号。
func newConfirmHarness(t *testing.T) (*harness, *appmerge.Service, *captureSender,
	*identity.Identity, domainaccount.Account, domainaccount.Account) {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()

	stub := h.stubProvider()
	src, err := stub.Create(ctx, domainaccount.CreateRequest{
		IdempotencyKey: "confirm-src",
		Claims: []domainaccount.Claim{
			{Type: "phone", Value: "13800138000", Source: "sms_verified"},
		},
	})
	if err != nil {
		t.Fatalf("创建 source 账号失败: %v", err)
	}
	dst, err := stub.Create(ctx, domainaccount.CreateRequest{IdempotencyKey: "confirm-dst"})
	if err != nil {
		t.Fatalf("创建 target 账号失败: %v", err)
	}

	identityRepo := postgres.NewIdentityRepository(h.app.DB())
	bindingRepo := postgres.NewBindingRepository(h.app.DB())
	idn, err := identityRepo.Upsert(ctx, identity.UpsertInput{
		AppID:         h.appID,
		Platform:      provider.PlatformGenericOAuth2,
		ProviderAppID: testProviderClientID,
		OpenID:        "confirm-openid-" + newAppCode("c"),
		Profile:       map[string]any{},
	})
	if err != nil {
		t.Fatalf("写入 identity 失败: %v", err)
	}
	if _, _, err := bindingRepo.Activate(ctx, binding.ActivateInput{
		AppID: h.appID, ExternalUserID: src.UserID, IdentityID: idn.ID,
		BindSource: binding.SourceExplicit, At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入绑定失败: %v", err)
	}

	sender := &captureSender{}
	svc := appmerge.New(appmerge.Deps{
		Ops:              postgres.NewMergeRepository(h.app.DB()),
		Converger:        postgres.NewMergeConverger(h.app.DB()),
		Accounts:         stub,
		Tickets:          cache.NewTicketStore(h.app.Redis()),
		Challenges:       cache.NewMergeChallengeStore(h.app.Redis()),
		Sender:           sender,
		RemoteIdempotent: true,
	})
	svc.SetAppLookup(func(_ context.Context, appID int64) (*tenant.Application, error) {
		p := tenant.DefaultPolicy()
		p.Merge.Mode = tenant.MergeModeConfirm
		p.Merge.Verification = tenant.VerificationSMS
		return &tenant.Application{ID: appID, AppCode: h.appCode, Policy: p}, nil
	})

	return h, svc, sender, idn, *src, *dst
}

func TestConfirmVerificationHappyPath(t *testing.T) {
	h, svc, sender, idn, src, dst := newConfirmHarness(t)
	ctx := context.Background()
	tickets := cache.NewTicketStore(h.app.Redis())

	// 1) 模拟 bindConflict 在 confirm 模式下签发票据。
	ticketID := "mtk_" + newAppCode("t")
	if err := tickets.SaveMergeTicket(ctx, &ticket.MergeTicket{
		Ticket:       ticketID,
		AppID:        h.appID,
		AppCode:      h.appCode,
		TargetUserID: dst.UserID,
		SourceUserID: src.UserID,
		IdentityID:   idn.ID,
		Platform:     provider.PlatformGenericOAuth2,
		Verification: tenant.VerificationSMS,
		CreatedAt:    time.Now().UTC(),
	}, ticket.TTLMergeTicket); err != nil {
		t.Fatalf("保存合并票据失败: %v", err)
	}

	// 2) 发码。
	out, err := svc.StartSMSVerification(ctx, appmerge.StartVerificationInput{
		TicketID: ticketID, CallerUserID: dst.UserID,
	})
	if err != nil {
		t.Fatalf("发码失败: %v", err)
	}
	if sender.calls != 1 || len(sender.code) != mergex.CodeLength {
		t.Fatalf("应发出 6 位验证码，实际 calls=%d code=%q", sender.calls, sender.code)
	}
	// 响应里只能是掩码。
	if out.PhoneMasked != "138****00" {
		t.Fatalf("响应应为掩码号码，实际 %s", out.PhoneMasked)
	}
	// 挑战里不能有明文码。
	ch, err := cache.NewMergeChallengeStore(h.app.Redis()).Get(ctx, ticketID)
	if err != nil {
		t.Fatalf("读取挑战失败: %v", err)
	}
	if ch.CodeHash == sender.code || ch.CodeHash == "" {
		t.Fatal("挑战必须只存哈希")
	}

	// 3) 先用错误码：应被拒绝但票据仍在。
	if _, err := svc.CompleteSMSVerification(ctx, appmerge.CompleteVerificationInput{
		TicketID: ticketID, Code: "000000", CallerUserID: dst.UserID,
	}); err == nil {
		t.Fatal("错误验证码必须拒绝")
	}
	if _, err := tickets.GetMergeTicket(ctx, ticketID); err != nil {
		t.Fatalf("单次失败不应作废票据: %v", err)
	}

	// 4) 正确码：完成合并。
	res, err := svc.CompleteSMSVerification(ctx, appmerge.CompleteVerificationInput{
		TicketID: ticketID, Code: sender.code, CallerUserID: dst.UserID,
	})
	if err != nil {
		t.Fatalf("验证通过后合并失败: %v", err)
	}
	if res == nil || res.OperationID == 0 {
		t.Fatal("应返回合并操作 ID")
	}

	// 5) 绑定改挂到 target。
	cur, err := postgres.NewBindingRepository(h.app.DB()).FindActiveByIdentity(ctx, h.appID, idn.ID)
	if err != nil {
		t.Fatalf("查询绑定失败: %v", err)
	}
	if cur.ExternalUserID != dst.UserID {
		t.Fatalf("应改挂到 %s，实际 %s", dst.UserID, cur.ExternalUserID)
	}

	// 6) 票据与挑战都已消费：同一个码不可能再用一次。
	if _, err := tickets.GetMergeTicket(ctx, ticketID); err == nil {
		t.Fatal("验证成功后票据必须失效")
	}
	if _, err := cache.NewMergeChallengeStore(h.app.Redis()).Get(ctx, ticketID); err == nil {
		t.Fatal("验证成功后挑战必须失效")
	}
}

// TestConfirmVerificationLocksAfterMaxAttempts：连续输错到上限后票据作废。
func TestConfirmVerificationLocksAfterMaxAttempts(t *testing.T) {
	h, svc, sender, idn, src, dst := newConfirmHarness(t)
	ctx := context.Background()
	tickets := cache.NewTicketStore(h.app.Redis())

	ticketID := "mtk_" + newAppCode("l")
	if err := tickets.SaveMergeTicket(ctx, &ticket.MergeTicket{
		Ticket: ticketID, AppID: h.appID, AppCode: h.appCode,
		TargetUserID: dst.UserID, SourceUserID: src.UserID,
		IdentityID: idn.ID, Platform: provider.PlatformGenericOAuth2,
		Verification: tenant.VerificationSMS, CreatedAt: time.Now().UTC(),
	}, ticket.TTLMergeTicket); err != nil {
		t.Fatalf("保存票据失败: %v", err)
	}
	if _, err := svc.StartSMSVerification(ctx, appmerge.StartVerificationInput{
		TicketID: ticketID, CallerUserID: dst.UserID,
	}); err != nil {
		t.Fatalf("发码失败: %v", err)
	}

	// 故意用一个与真实码不同的码，连试到上限。
	wrong := "000000"
	if wrong == sender.code {
		wrong = "111111"
	}
	for i := 0; i < mergex.MaxVerifyAttempts; i++ {
		_, _ = svc.CompleteSMSVerification(ctx, appmerge.CompleteVerificationInput{
			TicketID: ticketID, Code: wrong, CallerUserID: dst.UserID,
		})
	}

	if _, err := tickets.GetMergeTicket(ctx, ticketID); err == nil {
		t.Fatal("次数耗尽后票据必须作废")
	}

	// 此时即使知道正确码也没用了——票据已不在。
	_, err := svc.CompleteSMSVerification(ctx, appmerge.CompleteVerificationInput{
		TicketID: ticketID, Code: sender.code, CallerUserID: dst.UserID,
	})
	if err == nil {
		t.Fatal("票据作废后正确码也不应通过")
	}

	// 绑定没有被改动。
	cur, err := postgres.NewBindingRepository(h.app.DB()).FindActiveByIdentity(ctx, h.appID, idn.ID)
	if err != nil {
		t.Fatalf("查询绑定失败: %v", err)
	}
	if cur.ExternalUserID != src.UserID {
		t.Fatalf("验证失败期间不得改动绑定，实际已挂到 %s", cur.ExternalUserID)
	}
}
