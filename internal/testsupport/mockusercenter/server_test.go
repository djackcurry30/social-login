package mockusercenter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/infrastructure/account"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/testsupport/mockusercenter"
)

// 这些用例有两个目的：
//
//  1. 证明 mock 确实按契约行事。否则验收测试失败时，分不清是"我方适配层错了"
//     还是"mock 写错了"——排查成本会翻倍。
//  2. 用【真实的 HTTPProvider】去打它，也就是让契约的两个实现互相校验。
//     只测 mock 自己（直接发 HTTP）无法发现"我们对报文的假设"与"mock 的假设"
//     恰好一起错的可能。

// testApp 是默认测试应用。
const testApp = "app_test_001"

func newProvider(t *testing.T, srv *mockusercenter.Server) *account.HTTPProvider {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	p, err := account.NewHTTPProvider(account.HTTPConfig{
		BaseURL: ts.URL,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造 HTTPProvider 失败: %v", err)
	}
	return p
}

// TestErrorCodesMatchContract 守住两份常量表不漂移。
//
// mock 刻意不复用 account 包的常量：复用会让"我方改了码、对端没跟"永远
// 测不出来。代价是可能各自漂移，所以在这里逐条比对。
func TestErrorCodesMatchContract(t *testing.T) {
	pairs := []struct {
		name             string
		mock, production string
	}{
		{"NOT_FOUND", mockusercenter.CodeNotFound, account.CodeUpstreamNotFound},
		{"CLAIM_TAKEN", mockusercenter.CodeClaimTaken, account.CodeUpstreamClaimTaken},
		{"MULTIPLE", mockusercenter.CodeMultiple, account.CodeUpstreamMultiple},
		{"MERGE_REJECTED", mockusercenter.CodeMergeRejected, account.CodeUpstreamMergeRejected},
		{"IDEM_IN_PROGRESS", mockusercenter.CodeIdemInProgress, account.CodeUpstreamIdemInProgress},
		{"CONFLICT", mockusercenter.CodeConflict, account.CodeUpstreamConflict},
		{"APP_UNKNOWN", mockusercenter.CodeAppUnknown, account.CodeUpstreamAppUnknown},
		{"APP_DISABLED", mockusercenter.CodeAppDisabled, account.CodeUpstreamAppDisabled},
	}
	for _, p := range pairs {
		if p.mock != p.production {
			t.Errorf("%s 错误码不一致：mock=%q account=%q", p.name, p.mock, p.production)
		}
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	p := newProvider(t, srv)
	ctx := context.Background()

	req := domainaccount.CreateRequest{
		AppKey:         testApp,
		Claims:         []domainaccount.Claim{{Type: "phone", Value: "13800000001", Source: "wechat_phone"}},
		IdempotencyKey: "first_login:app1:42",
	}
	first, err := p.Create(ctx, req)
	if err != nil {
		t.Fatalf("首次创建失败: %v", err)
	}
	second, err := p.Create(ctx, req)
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if first.UserID != second.UserID {
		t.Fatalf("同一幂等键必须返回同一账号，得到 %q 与 %q", first.UserID, second.UserID)
	}
	if n := srv.Count(); n != 1 {
		t.Fatalf("重放不应新增账号，实际账号数 %d", n)
	}
	// 幂等键必须真的被送到对端——只断言"登录成功"看不出这一点。
	calls := srv.CallsOf(mockusercenter.OpCreate)
	if len(calls) != 2 {
		t.Fatalf("应记录 2 次 Create 调用，实际 %d", len(calls))
	}
	if calls[0].IdempotencyKey != req.IdempotencyKey {
		t.Fatalf("Create 未携带幂等键，实际 %q", calls[0].IdempotencyKey)
	}
	// 应用维度同理：漏带时对端会把它当成全局账号空间。
	if calls[0].AppKey != testApp {
		t.Fatalf("Create 未携带 app_key，实际 %q", calls[0].AppKey)
	}
}

func TestCreateConflictWhenClaimTaken(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	// 先占住这个号码。
	owner := srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000002", Source: "wechat_phone"}})
	p := newProvider(t, srv)

	_, err := p.Create(context.Background(), domainaccount.CreateRequest{
		AppKey:         testApp,
		Claims:         []domainaccount.Claim{{Type: "phone", Value: "13800000002", Source: "wechat_phone"}},
		IdempotencyKey: "k1",
	})
	if code := errs.CodeOf(err); code != errs.CodeBindIdentityTaken {
		t.Fatalf("凭证被占用应映射为 BIND.IDENTITY_TAKEN，实际 %v (%v)", code, err)
	}
	// 冲突之后原持有者不能被动过。
	if acc, ok := srv.Account(owner); !ok || acc.Status != mockusercenter.StatusActive {
		t.Fatalf("拒绝创建不应影响原账号: %+v", acc)
	}
}

func TestCreateNotSupported(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{CreateUnsupported: true})
	p := newProvider(t, srv)
	_, err := p.Create(context.Background(), domainaccount.CreateRequest{
		AppKey: testApp, IdempotencyKey: "k1",
	})
	if code := errs.CodeOf(err); code != errs.CodeAccountNotSupported {
		t.Fatalf("对端不提供创建能力应映射为 ACCOUNT.NOT_SUPPORTED，实际 %v (%v)", code, err)
	}
}

// TestGetByClaimOutcomes 覆盖三种反查结果。
//
// ⚠️ "命中多账号"这一档在 v1.1 里靠错误信封区分，不再只靠 409：
// mock 现在用 ACCOUNT.MULTIPLE，适配层据此返回 ErrMultipleAccounts。
func TestGetByClaimOutcomes(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	p := newProvider(t, srv)
	ctx := context.Background()
	claim := domainaccount.Claim{Type: "phone", Value: "13800000003"}

	if _, err := p.GetByClaim(ctx, testApp, claim); err != domainaccount.ErrNotFound {
		t.Fatalf("无账号持有时应返回 ErrNotFound，实际 %v", err)
	}

	srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000003", Source: "wechat_phone"}})
	acc, err := p.GetByClaim(ctx, testApp, claim)
	if err != nil {
		t.Fatalf("命中单账号应成功，实际 %v", err)
	}
	if len(acc.Claims) != 1 || acc.Claims[0].Value != "13800000003" {
		t.Fatalf("账号凭证不符: %+v", acc.Claims)
	}

	// 注入 multi：对端唯一性被破坏，必须报错而不是挑一个。
	srv.InjectFault(mockusercenter.OpByClaim, mockusercenter.FaultMultiAccount, 0)
	if _, err := p.GetByClaim(ctx, testApp, claim); err != domainaccount.ErrMultipleAccounts {
		t.Fatalf("命中多账号应返回 ErrMultipleAccounts，实际 %v", err)
	}
}

// TestAppIsolation 是 v1.1 契约的核心断言：账号空间按应用隔离。
//
// 没有这条，App2 的用户会登进 App1 的账号。这是数据越权，不是"多应用不方便"。
func TestAppIsolation(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	p := newProvider(t, srv)
	ctx := context.Background()
	const phone = "13900000001"

	a1, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey:         "app_one",
		Claims:         []domainaccount.Claim{{Type: "phone", Value: phone, Source: "wechat_phone"}},
		IdempotencyKey: "k-app1",
	})
	if err != nil {
		t.Fatalf("app_one 建号失败: %v", err)
	}

	// 同一个手机号在另一个应用里必须能建出【另一个】账号，
	// 而不是撞上 app_one 的账号。
	a2, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey:         "app_two",
		Claims:         []domainaccount.Claim{{Type: "phone", Value: phone, Source: "wechat_phone"}},
		IdempotencyKey: "k-app2",
	})
	if err != nil {
		t.Fatalf("app_two 用同一手机号建号应成功（应用隔离），实际 %v", err)
	}
	if a1.UserID == a2.UserID {
		t.Fatalf("两个应用必须各自建号，实际都拿到 %q", a1.UserID)
	}

	// 反查也必须只在本应用内命中。
	got, err := p.GetByClaim(ctx, "app_two", domainaccount.Claim{Type: "phone", Value: phone})
	if err != nil {
		t.Fatalf("app_two 反查应命中自己的账号，实际 %v", err)
	}
	if got.UserID != a2.UserID {
		t.Fatalf("app_two 反查串到了别的应用：期望 %q 实际 %q", a2.UserID, got.UserID)
	}

	// 跨应用按 id 查必须查不到（id 只在应用内唯一）。
	if _, err := p.Get(ctx, "app_two", a1.UserID); err != domainaccount.ErrNotFound {
		t.Fatalf("跨应用按 id 查询应返回 ErrNotFound，实际 %v", err)
	}
}

// TestMergeCrossAppRejected 守住 R3 红线：拒绝跨应用合并。
func TestMergeCrossAppRejected(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	a1 := srv.Seed("app_one", "", nil)
	b2 := srv.Seed("app_two", "", nil)
	p := newProvider(t, srv)

	_, err := p.Merge(context.Background(), domainaccount.MergeRequest{
		AppKey:         "app_one",
		TargetUserID:   a1,
		SourceUserID:   b2,
		IdempotencyKey: "k-cross",
	})
	if err != domainaccount.ErrNotFound {
		t.Fatalf("跨应用合并应被拒绝（对端视为 source 不存在），实际 %v", err)
	}
}

func TestMergeMovesClaimsAndIsIdempotent(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	target := srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000004", Source: "wechat_phone"}})
	source := srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "email", Value: "b@example.com", Source: "apple_email"}})
	p := newProvider(t, srv)
	ctx := context.Background()

	req := domainaccount.MergeRequest{
		AppKey:       testApp,
		TargetUserID: target, SourceUserID: source, IdempotencyKey: "merge:k1", Reason: "test",
	}
	res, err := p.Merge(ctx, req)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if !res.Merged || res.AlreadyMerged {
		t.Fatalf("首次合并应 merged=true already_merged=false，实际 %+v", res)
	}
	if len(res.DiscardedClaims) != 0 {
		t.Fatalf("不同类型凭证应全部迁移，不应丢弃，实际 %+v", res.DiscardedClaims)
	}
	if acc, _ := srv.Account(target); len(acc.Claims) != 2 {
		t.Fatalf("合并后目标账号应有 2 条凭证，实际 %+v", acc.Claims)
	}
	if acc, _ := srv.Account(source); acc.Status != mockusercenter.StatusClosed {
		t.Fatalf("source 应变为 closed，实际 %q", acc.Status)
	}

	// 补偿任务重试：同一幂等键重放，不能再次迁移。
	again, err := p.Merge(ctx, req)
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if again.Merged || !again.AlreadyMerged {
		t.Fatalf("重放应 already_merged=true merged=false，实际 %+v", again)
	}
	if acc, _ := srv.Account(target); len(acc.Claims) != 2 {
		t.Fatalf("重放不得重复迁移凭证，实际 %+v", acc.Claims)
	}
}

// TestMergeDiscardsSameTypeClaim 守住"一个账号每类凭证只能有一条"在合并里的表现。
//
// 双方各有一个手机号时，保留 target 的，source 的撤销并回传，让上层能通知用户。
func TestMergeDiscardsSameTypeClaim(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	target := srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000010", Source: "wechat_phone"}})
	source := srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000011", Source: "alipay_phone"}})
	p := newProvider(t, srv)
	ctx := context.Background()

	res, err := p.Merge(ctx, domainaccount.MergeRequest{
		AppKey:       testApp,
		TargetUserID: target, SourceUserID: source, IdempotencyKey: "merge:same-type",
	})
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if len(res.DiscardedClaims) != 1 || res.DiscardedClaims[0].Value != "13800000011" {
		t.Fatalf("应回传被丢弃的 source 手机号，实际 %+v", res.DiscardedClaims)
	}

	acc, _ := srv.Account(target)
	if len(acc.Claims) != 1 || acc.Claims[0].Value != "13800000010" {
		t.Fatalf("target 应只保留自己的手机号，实际 %+v", acc.Claims)
	}
	// 被丢弃的号码必须释放：否则它永远被这个已关闭的账号占着，
	// 用户拿这个号重新注册会一直撞"凭证被占用"。
	if _, err := p.GetByClaim(ctx, testApp, domainaccount.Claim{Type: "phone", Value: "13800000011"}); err != domainaccount.ErrNotFound {
		t.Fatalf("被丢弃的凭证应被释放，实际 %v", err)
	}
}

func TestMergeRejectsSelfAndMissing(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	uid := srv.Seed(testApp, "", nil)
	p := newProvider(t, srv)
	ctx := context.Background()

	if _, err := p.Merge(ctx, domainaccount.MergeRequest{
		AppKey: testApp, TargetUserID: uid, SourceUserID: uid, IdempotencyKey: "k-self",
	}); errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("target==source 应被识别为参数问题，实际 %v", err)
	}
	if _, err := p.Merge(ctx, domainaccount.MergeRequest{
		AppKey: testApp, TargetUserID: uid, SourceUserID: "nope", IdempotencyKey: "k-404",
	}); err != domainaccount.ErrNotFound {
		t.Fatalf("source 不存在应返回 ErrNotFound，实际 %v", err)
	}
}

func TestFaultInjectionMapsToAccountUnavailable(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		delay   time.Duration
		retry   bool
		wantErr errs.Code
	}{
		{"5xx 可重试", mockusercenter.FaultServerError, 0, true, errs.CodeAccountUnavailable},
		{"429 限流", mockusercenter.FaultRateLimited, 0, true, errs.CodeRateLimited},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := mockusercenter.New(mockusercenter.Config{})
			uid := srv.Seed(testApp, "", nil)
			srv.InjectFault(mockusercenter.OpGet, tc.mode, tc.delay)
			p := newProvider(t, srv)

			_, err := p.Get(context.Background(), testApp, uid)
			if code := errs.CodeOf(err); code != tc.wantErr {
				t.Fatalf("期望 %v，实际 %v (%v)", tc.wantErr, code, err)
			}
			if e, ok := errs.As(err); !ok || e.Retryable != tc.retry {
				t.Fatalf("可重试标记不符: %+v", e)
			}
		})
	}

	t.Run("超时", func(t *testing.T) {
		srv := mockusercenter.New(mockusercenter.Config{})
		uid := srv.Seed(testApp, "", nil)
		// 睡 300ms，客户端超时设 100ms：避免测试等 5 秒。
		srv.InjectFault(mockusercenter.OpGet, mockusercenter.FaultTimeout, 300*time.Millisecond)
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(ts.Close)
		p, err := account.NewHTTPProvider(account.HTTPConfig{BaseURL: ts.URL, Timeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatalf("构造失败: %v", err)
		}

		_, err = p.Get(context.Background(), testApp, uid)
		if code := errs.CodeOf(err); code != errs.CodeAccountUnavailable {
			t.Fatalf("超时应翻成 ACCOUNT.UNAVAILABLE，实际 %v (%v)", code, err)
		}
		if e, _ := errs.As(err); e == nil || !e.Retryable {
			t.Fatalf("超时必须标记可重试")
		}
	})
}

// TestIdempotencyInProgressIsRetryable 是错误信封存在的核心理由。
//
// 同样是 409：
//   - 带 ACCOUNT.CLAIM_TAKEN → 凭证被占用，重试没有意义，调用方要换流程
//   - 带 ACCOUNT.IDEMPOTENCY_IN_PROGRESS → 并发重试的正常现象，等会儿就好
//
// 只看状态码时这两者无法区分，会把"稍等重试"译成"该手机号已被占用"。
func TestIdempotencyInProgressIsRetryable(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	p := newProvider(t, srv)
	srv.InjectFault(mockusercenter.OpCreate, mockusercenter.FaultIdemInProgress, 0)

	_, err := p.Create(context.Background(), domainaccount.CreateRequest{
		AppKey:         testApp,
		Claims:         []domainaccount.Claim{{Type: "phone", Value: "13800000020", Source: "wechat_phone"}},
		IdempotencyKey: "k-in-progress",
	})
	if code := errs.CodeOf(err); code == errs.CodeBindIdentityTaken {
		t.Fatalf("幂等处理中不能被译成'凭证被占用'，实际 %v", err)
	}
	if code := errs.CodeOf(err); code != errs.CodeAccountUnavailable {
		t.Fatalf("应映射 ACCOUNT.UNAVAILABLE，实际 %v (%v)", code, err)
	}
	if e, ok := errs.As(err); !ok || !e.Retryable {
		t.Fatalf("幂等处理中必须可重试，实际 %+v", e)
	}
}

// TestUnregisteredApp 验证 APP.UNKNOWN 的处理。
//
// 不可重试：应用没注册，重试一百次还是没注册。文案必须指向真正的原因，
// 否则运维会去查网络。
func TestUnregisteredApp(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{RequireRegisteredApp: true})
	srv.RegisterApp("app_known")
	p := newProvider(t, srv)
	ctx := context.Background()

	_, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey: "app_typo", IdempotencyKey: "k-unknown",
	})
	if code := errs.CodeOf(err); code != errs.CodeAccountUnavailable {
		t.Fatalf("未注册应用应映射 ACCOUNT.UNAVAILABLE，实际 %v (%v)", code, err)
	}
	if e, ok := errs.As(err); !ok || e.Retryable {
		t.Fatalf("未注册应用不可重试，实际 %+v", e)
	}
	if e, _ := errs.As(err); e != nil && !strings.Contains(e.Message, "注册") {
		t.Fatalf("文案应指向上游注册问题，实际 %q", e.Message)
	}

	// 已注册的应用不受影响。
	if _, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey: "app_known", IdempotencyKey: "k-known",
	}); err != nil {
		t.Fatalf("已注册应用应成功，实际 %v", err)
	}
}

// TestReplaceClaim 覆盖换绑的三条语义。
func TestReplaceClaim(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	uid := srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000030", Source: "wechat_phone"}})
	p := newProvider(t, srv)
	ctx := context.Background()

	// ① 正常换绑：旧号释放、新号生效。
	acc, err := p.ReplaceClaim(ctx, domainaccount.ReplaceClaimRequest{
		AppKey: testApp, UserID: uid,
		Claim: domainaccount.Claim{Type: "phone", Value: "13800000031", Source: "sms"},
	})
	if err != nil {
		t.Fatalf("换绑失败: %v", err)
	}
	if len(acc.Claims) != 1 || acc.Claims[0].Value != "13800000031" {
		t.Fatalf("换绑后应只保留新号，实际 %+v", acc.Claims)
	}
	if _, err := p.GetByClaim(ctx, testApp, domainaccount.Claim{Type: "phone", Value: "13800000030"}); err != domainaccount.ErrNotFound {
		t.Fatalf("旧号应被释放，实际 %v", err)
	}

	// ② 幂等：换成本账号当前已持有的值，不报错。
	again, err := p.ReplaceClaim(ctx, domainaccount.ReplaceClaimRequest{
		AppKey: testApp, UserID: uid,
		Claim: domainaccount.Claim{Type: "phone", Value: "13800000031", Source: "sms"},
	})
	if err != nil {
		t.Fatalf("换成当前值应幂等成功，实际 %v", err)
	}
	if len(again.Claims) != 1 {
		t.Fatalf("幂等换绑不应产生第二条，实际 %+v", again.Claims)
	}

	// ③ 被占用：不动本账号数据。
	srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000032", Source: "wechat_phone"}})
	_, err = p.ReplaceClaim(ctx, domainaccount.ReplaceClaimRequest{
		AppKey: testApp, UserID: uid,
		Claim: domainaccount.Claim{Type: "phone", Value: "13800000032", Source: "sms"},
	})
	if code := errs.CodeOf(err); code != errs.CodeBindIdentityTaken {
		t.Fatalf("换到他人号码应映射 BIND.IDENTITY_TAKEN，实际 %v (%v)", code, err)
	}
	if cur, _ := srv.Account(uid); len(cur.Claims) != 1 || cur.Claims[0].Value != "13800000031" {
		t.Fatalf("失败时原凭证不能被动，实际 %+v", cur.Claims)
	}
}

func TestMultiAccountFault(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	srv.Seed(testApp, "", []mockusercenter.Claim{{Type: "phone", Value: "13800000005", Source: "wechat_phone"}})
	srv.InjectFault(mockusercenter.OpByClaim, mockusercenter.FaultMultiAccount, 0)
	p := newProvider(t, srv)

	_, err := p.GetByClaim(context.Background(), testApp, domainaccount.Claim{Type: "phone", Value: "13800000005"})
	if err != domainaccount.ErrMultipleAccounts {
		t.Fatalf("注入 multi 后应返回 ErrMultipleAccounts，实际 %v", err)
	}
}

func TestTokenRequired(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{Token: "s3cret"})
	uid := srv.Seed(testApp, "", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// 不带 token：401 → ACCOUNT.UNAVAILABLE（4xx 不可重试）。
	noToken, err := account.NewHTTPProvider(account.HTTPConfig{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if _, err := noToken.Get(context.Background(), testApp, uid); errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("缺 token 应失败，实际 %v", err)
	}

	withToken, err := account.NewHTTPProvider(account.HTTPConfig{BaseURL: ts.URL, Token: "s3cret"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if _, err := withToken.Get(context.Background(), testApp, uid); err != nil {
		t.Fatalf("带 token 应成功，实际 %v", err)
	}
}

func TestMissingIdempotencyKeyRejectedAtServer(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// 绕过客户端直接发：验证 mock 自身也在意幂等键（对端实现应同样严格）。
	body := `{"claims":[],"nickname":"","avatar_url":""}`
	resp, err := http.Post(ts.URL+"/v1/apps/"+testApp+"/accounts", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺幂等键应 400，实际 %d", resp.StatusCode)
	}

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["message"] == "" {
		t.Fatalf("错误响应应带 message: %v", out)
	}
	if out["code"] == "" {
		t.Fatalf("错误响应应带 code（契约 v1.1 的错误信封）: %v", out)
	}
}

// TestPathWithoutAppIs404 守住"漏带应用前缀"的失败形态。
//
// 不能是"静默落到某个默认租户"——那会让配置写错表现为数据错乱。
func TestPathWithoutAppIs404(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/accounts/uc-0001")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("无应用前缀的路径应 404，实际 %d", resp.StatusCode)
	}
}
