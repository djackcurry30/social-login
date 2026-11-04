package merge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/account"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- fakes ---

type fakeTicketStore struct {
	ticket  *ticket.MergeTicket
	getErr  error
	deleted []string
	saved   int
}

func (f *fakeTicketStore) SaveContext(context.Context, *ticket.Context, time.Duration) error {
	panic("unexpected SaveContext")
}
func (f *fakeTicketStore) ConsumeContext(context.Context, string) (*ticket.Context, error) {
	panic("unexpected ConsumeContext")
}
func (f *fakeTicketStore) SaveBindTicket(context.Context, *ticket.BindTicket, time.Duration) error {
	panic("unexpected SaveBindTicket")
}
func (f *fakeTicketStore) ConsumeBindTicket(context.Context, string) (*ticket.BindTicket, error) {
	panic("unexpected ConsumeBindTicket")
}
func (f *fakeTicketStore) SaveAuthCode(context.Context, *ticket.AuthCode, time.Duration) error {
	panic("unexpected SaveAuthCode")
}
func (f *fakeTicketStore) ConsumeAuthCode(context.Context, string) (*ticket.AuthCode, error) {
	panic("unexpected ConsumeAuthCode")
}
func (f *fakeTicketStore) SaveMergeTicket(context.Context, *ticket.MergeTicket, time.Duration) error {
	f.saved++
	return nil
}
func (f *fakeTicketStore) GetMergeTicket(context.Context, string) (*ticket.MergeTicket, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.ticket == nil {
		return nil, ticket.ErrMergeTicketInvalid
	}
	return f.ticket, nil
}
func (f *fakeTicketStore) DeleteMergeTicket(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *fakeTicketStore) MarkReplay(context.Context, string, time.Duration) error { return nil }
func (f *fakeTicketStore) SeenReplay(context.Context, string) (bool, error)        { return false, nil }

type fakeChallenges struct {
	item    *mergex.Challenge
	bumps   int
	deletes int
	saved   *mergex.Challenge
}

func (f *fakeChallenges) Save(_ context.Context, c *mergex.Challenge, _ time.Duration) error {
	f.saved = c
	f.item = c
	return nil
}
func (f *fakeChallenges) Get(context.Context, string) (*mergex.Challenge, error) {
	if f.item == nil {
		return nil, mergex.ErrChallengeMissing
	}
	return f.item, nil
}
func (f *fakeChallenges) BumpAttempt(context.Context, string) (int, error) {
	f.bumps++
	f.item.Attempts++
	return f.item.Attempts, nil
}
func (f *fakeChallenges) Delete(context.Context, string) error {
	f.deletes++
	f.item = nil
	return nil
}

type fakeSender struct {
	sent  []mergex.CodeRequest
	err   error
	calls int
}

func (f *fakeSender) Send(_ context.Context, req mergex.CodeRequest) error {
	f.calls++
	f.sent = append(f.sent, req)
	return f.err
}

// newVerifySvc 构造一个带短信验证能力的服务。
func newVerifySvc(t *testing.T) (*Service, *fakeAccountWithPhone, *fakeTicketStore, *fakeChallenges, *fakeSender) {
	t.Helper()
	st := &fakeStore{}
	tk := &fakeTicketStore{ticket: &ticket.MergeTicket{
		Ticket:       "mtk_1",
		AppID:        3,
		AppCode:      "app_test",
		TargetUserID: "user-C",
		SourceUserID: "user-B",
		IdentityID:   9,
		Platform:     "wechat",
		Verification: "sms",
	}}
	ch := &fakeChallenges{}
	sd := &fakeSender{}
	acc := &fakeAccountWithPhone{phone: "13800138000"}

	svc := New(Deps{
		Ops:              st,
		Converger:        &fakeConverger{},
		Accounts:         acc,
		Tickets:          tk,
		Challenges:       ch,
		Sender:           sd,
		RemoteIdempotent: true,
	})
	svc.SetAppLookup(func(context.Context, int64) (*tenant.Application, error) {
		return nil, errors.New("不应走到这里")
	})
	return svc, acc, tk, ch, sd
}

// fakeAccountWithPhone 只实现 Get，返回带 phone claim 的账号。
type fakeAccountWithPhone struct {
	phone string
	err   error
	// lastAppKey 记录收到的应用标识：发码前查手机号必须限定在 ticket 所属应用内，
	// 否则会拿到别的应用里同 id 账号的手机号。
	lastAppKey string
}

func (f *fakeAccountWithPhone) Get(_ context.Context, appKey, _ string) (*account.Account, error) {
	f.lastAppKey = appKey
	if f.err != nil {
		return nil, f.err
	}
	claims := []account.Claim{}
	if f.phone != "" {
		claims = append(claims, account.Claim{Type: "phone", Value: f.phone, Source: "sms_verified"})
	}
	return &account.Account{UserID: "user-B", Status: account.StatusActive, Claims: claims}, nil
}
func (f *fakeAccountWithPhone) GetByClaim(context.Context, string, account.Claim) (*account.Account, error) {
	return nil, account.ErrNotFound
}
func (f *fakeAccountWithPhone) Create(context.Context, account.CreateRequest) (*account.Account, error) {
	return nil, errors.New("not supported")
}
func (f *fakeAccountWithPhone) Merge(context.Context, account.MergeRequest) (*account.MergeResult, error) {
	return &account.MergeResult{Merged: true}, nil
}

// --- 发码 ---

func TestStartSMSRequiresVerifiedPhone(t *testing.T) {
	svc, acc, _, ch, sd := newVerifySvc(t)
	acc.phone = "" // 用户中心没有手机号

	_, err := svc.StartSMSVerification(context.Background(), StartVerificationInput{TicketID: "mtk_1"})
	if err == nil {
		t.Fatal("没有手机号时必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeBindMergeRequired {
		t.Fatalf("应为 BIND.MERGE_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if sd.calls != 0 {
		t.Fatal("没有号码不得发送")
	}
	if ch.saved != nil {
		t.Fatal("没有号码不得保存挑战")
	}
}

func TestStartSMSSendsMaskedCode(t *testing.T) {
	svc, acc, _, ch, sd := newVerifySvc(t)

	out, err := svc.StartSMSVerification(context.Background(), StartVerificationInput{
		TicketID: "mtk_1", CallerUserID: "user-C",
	})
	if err != nil {
		t.Fatalf("发码失败: %v", err)
	}
	if sd.calls != 1 {
		t.Fatalf("应发送 1 条短信，实际 %d", sd.calls)
	}
	if len(sd.sent[0].Code) != mergex.CodeLength {
		t.Fatalf("验证码应为 %d 位，实际 %q", mergex.CodeLength, sd.sent[0].Code)
	}
	if out.PhoneMasked != "138****00" {
		t.Fatalf("出参应为掩码号码，实际 %s", out.PhoneMasked)
	}
	// 挑战里只能有哈希，不能有明文码。
	if ch.saved.CodeHash == "" || ch.saved.CodeHash == sd.sent[0].Code {
		t.Fatal("挑战必须只保存哈希")
	}
	// 查手机号必须限定在 ticket 所属应用内：user_id 只在应用内唯一，
	// 不带应用前缀会拿到别的应用里同 id 账号的手机号并发码。
	if acc.lastAppKey != "app_test" {
		t.Fatalf("应按票据所属应用查询，实际 appKey=%q", acc.lastAppKey)
	}
}

func TestStartSMSRateLimited(t *testing.T) {
	svc, _, _, ch, sd := newVerifySvc(t)
	ch.item = &mergex.Challenge{TicketID: "mtk_1", SentAt: time.Now()}

	_, err := svc.StartSMSVerification(context.Background(), StartVerificationInput{TicketID: "mtk_1"})
	if err == nil {
		t.Fatal("60 秒内重发必须被限流")
	}
	if errs.CodeOf(err) != errs.CodeRateLimited {
		t.Fatalf("应为 RATE.LIMITED，实际 %v", errs.CodeOf(err))
	}
	if sd.calls != 0 {
		t.Fatal("被限流不得发送")
	}
}

func TestStartSMSRejectsForeignCaller(t *testing.T) {
	svc, _, _, _, _ := newVerifySvc(t)
	// 票据属于 user-C，换个账号拿它发码等于允许"别人替我合并"。
	_, err := svc.StartSMSVerification(context.Background(), StartVerificationInput{
		TicketID: "mtk_1", CallerUserID: "user-X",
	})
	if err == nil {
		t.Fatal("票据归属不匹配必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeForbidden {
		t.Fatalf("应为 403，实际 %v", errs.CodeOf(err))
	}
}

// --- 验码 ---

func TestVerifyRejectsWrongCode(t *testing.T) {
	svc, _, _, ch, _ := newVerifySvc(t)
	ch.item = &mergex.Challenge{TicketID: "mtk_1", CodeHash: hashCode("123456", "mtk_1")}

	_, err := svc.CompleteSMSVerification(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_1", Code: "000000", CallerUserID: "user-C",
	})
	if err == nil {
		t.Fatal("错误验证码必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeBindTicketInvalid {
		t.Fatalf("应为 BIND.TICKET_INVALID，实际 %v", errs.CodeOf(err))
	}
	if ch.bumps != 1 {
		t.Fatalf("应累加尝试次数，实际 %d", ch.bumps)
	}
}

func TestVerifyLocksAfterMaxAttempts(t *testing.T) {
	svc, _, tk, ch, _ := newVerifySvc(t)
	ch.item = &mergex.Challenge{
		TicketID: "mtk_1", CodeHash: hashCode("123456", "mtk_1"),
		Attempts: mergex.MaxVerifyAttempts - 1,
	}

	_, err := svc.CompleteSMSVerification(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_1", Code: "000000", CallerUserID: "user-C",
	})
	if err == nil {
		t.Fatal("最后一次错误必须锁死")
	}
	// 次数耗尽后票据与挑战都要作废：只删挑战会让票据被反复用来"再发一条码继续猜"。
	if len(tk.deleted) != 1 {
		t.Fatal("次数耗尽必须删除合票据")
	}
}

func TestVerifyWithoutChallenge(t *testing.T) {
	svc, _, _, _, _ := newVerifySvc(t)
	_, err := svc.CompleteSMSVerification(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_1", Code: "123456",
	})
	if err == nil {
		t.Fatal("未发码就验码必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestVerifyInvalidTicket(t *testing.T) {
	svc, _, tk, _, _ := newVerifySvc(t)
	tk.getErr = ticket.ErrMergeTicketInvalid
	_, err := svc.CompleteSMSVerification(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_x", Code: "123456",
	})
	if errs.CodeOf(err) != errs.CodeBindTicketInvalid {
		t.Fatalf("应为 BIND.TICKET_INVALID，实际 %v", errs.CodeOf(err))
	}
}

// TestVerifySuccessConsumesTicket：验证码正确时票据与挑战都要被消费掉。
//
// 这里不深入断言合并结果（那条链路由 service_test 与集成测试覆盖），
// 只确认"一次性"这件事成立——否则同一个码可以被重复使用。
func TestVerifySuccessConsumesTicket(t *testing.T) {
	svc, _, tk, ch, _ := newVerifySvc(t)
	ch.item = &mergex.Challenge{TicketID: "mtk_1", CodeHash: hashCode("123456", "mtk_1")}
	// 让合并链路在"应用查询"处失败，从而只验证到消费票据这一步。
	svc.SetAppLookup(func(context.Context, int64) (*tenant.Application, error) {
		return nil, errs.New(errs.CodeInternal, "测试桩：应用查询失败")
	})

	_, err := svc.CompleteSMSVerification(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_1", Code: "123456", CallerUserID: "user-C",
	})
	if err == nil {
		t.Fatal("应用查询失败时整体应报错")
	}
	// 关键：票据与挑战在合并之前就被删掉了，重复提交不可能成功第二次。
	if len(tk.deleted) != 1 {
		t.Fatal("验证成功后应删除合并票据")
	}
	if ch.deletes != 1 {
		t.Fatal("验证成功后应删除验证码挑战")
	}
}

// --- existing_binding（C3）---

// newExistingBindingSvc 构造一个"票据要求 existing_binding"的服务。
func newExistingBindingSvc(t *testing.T, verification string) (*Service, *fakeTicketStore) {
	t.Helper()
	st := &fakeStore{}
	tk := &fakeTicketStore{ticket: &ticket.MergeTicket{
		Ticket:       "mtk_1",
		AppID:        3,
		AppCode:      "app_test",
		TargetUserID: "user-C",
		SourceUserID: "user-B",
		Verification: verification,
	}}
	svc := New(Deps{
		Ops:              st,
		Converger:        &fakeConverger{},
		Accounts:         &fakeAccountWithPhone{phone: "13800138000"},
		Tickets:          tk,
		RemoteIdempotent: true,
	})
	svc.SetAppLookup(func(context.Context, int64) (*tenant.Application, error) {
		p := tenant.DefaultPolicy()
		p.Merge.Mode = tenant.MergeModeConfirm
		p.Merge.Verification = verification
		return &tenant.Application{ID: 3, AppCode: "app_test", Policy: p}, nil
	})
	return svc, tk
}

// TestExistingBindingProofSatisfiesConfirm：verification=existing_binding 时，
// 持有 source 会话即可合并，不需要短信。
func TestExistingBindingProofSatisfiesConfirm(t *testing.T) {
	svc, _ := newExistingBindingSvc(t, tenant.VerificationExistingBinding)

	res, err := svc.CompleteExistingBinding(context.Background(), CompleteVerificationInput{
		TicketID:     "mtk_1",
		CallerUserID: "user-B", // source 本人的会话
	})
	if err != nil {
		t.Fatalf("应允许合并: %v", err)
	}
	if res == nil || res.OperationID != 42 {
		t.Fatalf("合并结果不符: %+v", res)
	}
}

// TestExistingBindingRejectsTargetSession：拿 target 自己的会话来验证毫无意义，
// 必须拒绝——否则"任意已登录用户都能并走别人的账号"。
func TestExistingBindingRejectsTargetSession(t *testing.T) {
	svc, _ := newExistingBindingSvc(t, tenant.VerificationExistingBinding)

	_, err := svc.CompleteExistingBinding(context.Background(), CompleteVerificationInput{
		TicketID:     "mtk_1",
		CallerUserID: "user-C", // target
	})
	if err == nil {
		t.Fatal("target 会话不能作为 source 的控制权证据")
	}
	if e := errs.From(err); e == nil || e.Code != errs.CodeForbidden {
		t.Fatalf("应为 FORBIDDEN，实际 %v", err)
	}
}

// TestExistingBindingRequiresToken：没有会话就不该走这条路。
func TestExistingBindingRequiresToken(t *testing.T) {
	svc, _ := newExistingBindingSvc(t, tenant.VerificationExistingBinding)
	_, err := svc.CompleteExistingBinding(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_1",
	})
	if err == nil {
		t.Fatal("缺少调用者身份必须拒绝")
	}
}

// TestExistingBindingRejectedWhenPolicyIsSMS：策略要求短信时，
// 会话证据不能替代——否则等于让应用的配置失效。
func TestExistingBindingRejectedWhenPolicyIsSMS(t *testing.T) {
	svc, _ := newExistingBindingSvc(t, tenant.VerificationSMS)
	_, err := svc.CompleteExistingBinding(context.Background(), CompleteVerificationInput{
		TicketID: "mtk_1", CallerUserID: "user-B",
	})
	if err == nil {
		t.Fatal("策略要求短信时必须拒绝会话验证")
	}
}

// TestSMSNotSentWhenPolicyIsExistingBinding：existing_binding 下不应发短信
// （用户收到一条永远用不上的验证码，且产生费用）。
func TestSMSNotSentWhenPolicyIsExistingBinding(t *testing.T) {
	svc, tk := newExistingBindingSvc(t, tenant.VerificationExistingBinding)
	tk.ticket.TargetUserID = "user-C"
	sd := &fakeSender{}
	svc.deps.Sender = sd
	svc.deps.Challenges = &fakeChallenges{}

	_, err := svc.StartSMSVerification(context.Background(), StartVerificationInput{
		TicketID: "mtk_1", CallerUserID: "user-C",
	})
	if err == nil {
		t.Fatal("existing_binding 策略下不应允许发码")
	}
	if sd.calls != 0 {
		t.Fatalf("不应调用短信通道，实际 %d 次", sd.calls)
	}
}

// TestStrictNeedsBothProofs：strict 要求两种证据同时具备。
func TestStrictNeedsBothProofs(t *testing.T) {
	svc, _ := newExistingBindingSvc(t, tenant.VerificationStrict)
	r := Request{
		App:          appWithMode(tenant.MergeModeConfirm),
		TargetUserID: "user-C",
		SourceUserID: "user-B",
		Trigger:      TriggerBind,
	}
	r.App.Policy.Merge.Verification = tenant.VerificationStrict

	r.Proof = Proof{ExistingBinding: true}
	if _, err := svc.Execute(context.Background(), r); !errors.Is(err, ErrNeedVerification) {
		t.Fatalf("只有会话证据时应要求继续验证，实际 %v", err)
	}

	r.Proof = Proof{SMS: true, ExistingBinding: true}
	if _, err := svc.Execute(context.Background(), r); err != nil {
		t.Fatalf("两种证据齐备应允许合并: %v", err)
	}
}
