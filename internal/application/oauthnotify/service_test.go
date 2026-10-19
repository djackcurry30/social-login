package oauthnotify

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	domainbinding "github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/identitysource"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- 假实现 ---

type fakeTenant struct {
	app *tenant.Application
	cfg *tenant.ProviderConfig
}

func (f *fakeTenant) Application(_ context.Context, code string) (*tenant.Application, error) {
	if f.app == nil || f.app.AppCode != code {
		return nil, errs.New(errs.CodeUnauthorized, "app 不存在")
	}
	return f.app, nil
}

func (f *fakeTenant) Channel(_ context.Context, appID int64, platform, scene, configKey string) (*tenantconfig.Channel, error) {
	if f.cfg == nil {
		return nil, errs.New(errs.CodeProviderNotFound, "渠道未配置")
	}
	cfg := *f.cfg
	cfg.ConfigKey = configKey
	return &tenantconfig.Channel{
		Config: &cfg,
		Creds:  provider.Credentials{ProviderAppID: cfg.ProviderAppID},
	}, nil
}

// fakeSource 同时实现 Source / CallbackCapability / CallbackVerifier / CallbackParser。
//
// 每个能力都可以单独关掉，用于验证"缺能力时必须拒绝"这条安全红线。
type fakeSource struct {
	supportsVerify bool
	supportsParse  bool
	verifyErr      error
	event          *provider.CallbackEvent
	parseErr       error
	// seenAudience 记录编排层注入的 Audience，用于断言 aud 比对依赖它。
	seenAudience string
}

func (f *fakeSource) Kind() identitysource.Kind            { return identitysource.KindProvider }
func (f *fakeSource) Key() string                          { return "apple:app" }
func (f *fakeSource) Metadata() provider.Metadata          { return provider.Metadata{Platform: "apple", Scene: "app"} }
func (f *fakeSource) BeginAuth(context.Context, provider.AuthorizeRequest) (*provider.AuthorizeResult, error) {
	return nil, nil
}
func (f *fakeSource) Authenticate(context.Context, provider.ExchangeRequest) (*provider.ExternalUser, *provider.TokenSet, error) {
	return nil, nil, nil
}
func (f *fakeSource) Revoke(context.Context, provider.UnbindRequest) error { return nil }

func (f *fakeSource) SupportsCallbackVerify() bool { return f.supportsVerify }
func (f *fakeSource) SupportsCallbackParse() bool  { return f.supportsParse }

func (f *fakeSource) VerifyCallback(_ context.Context, raw *provider.CallbackPayload) error {
	f.seenAudience = raw.Audience
	if !f.supportsVerify {
		// 关键：未实现验签时返回 nil —— 这正是 notify 入口不能靠 nil 判断的原因。
		return nil
	}
	return f.verifyErr
}

func (f *fakeSource) ParseCallback(context.Context, *provider.CallbackPayload) (*provider.CallbackEvent, error) {
	return f.event, f.parseErr
}

type fakeRegistry struct{ src identitysource.Source }

func (r *fakeRegistry) Lookup(string, string) (identitysource.Source, error) { return r.src, nil }

type fakeIdentities struct {
	idn *identity.Identity
	err error
}

func (f *fakeIdentities) Upsert(context.Context, identity.UpsertInput) (*identity.Identity, error) {
	return f.idn, f.err
}
func (f *fakeIdentities) FindByOpenID(_ context.Context, q identity.FindQuery) (*identity.Identity, error) {
	if f.idn != nil && f.idn.OpenID == q.OpenID {
		return f.idn, nil
	}
	return nil, identity.ErrNotFound
}
func (f *fakeIdentities) FindByID(context.Context, int64, int64) (*identity.Identity, error) {
	return f.idn, f.err
}

type fakeBindings struct {
	binding   *domainbinding.Binding
	remaining int
	unboundID int64
	unbindErr error
}

func (f *fakeBindings) FindActiveByIdentity(context.Context, int64, int64) (*domainbinding.Binding, error) {
	if f.binding == nil {
		return nil, domainbinding.ErrNotFound
	}
	return f.binding, nil
}
func (f *fakeBindings) ListActiveByExternalUser(context.Context, int64, string) ([]domainbinding.Binding, error) {
	return nil, nil
}
func (f *fakeBindings) Activate(context.Context, domainbinding.ActivateInput) (*domainbinding.Binding, bool, error) {
	return nil, false, nil
}
func (f *fakeBindings) Unbind(_ context.Context, _, identityID int64, _ time.Time) error {
	if f.unbindErr != nil {
		return f.unbindErr
	}
	f.unboundID = identityID
	return nil
}
func (f *fakeBindings) CountActive(context.Context, int64, string) (int, error) {
	return f.remaining, nil
}

type fakeAudit struct{ events []*audit.Event }

func (f *fakeAudit) Write(_ context.Context, e *audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

// --- 测试装置 ---

func newApp() *tenant.Application {
	return &tenant.Application{
		ID:          7,
		AppCode:     "biz_a",
		Status:      1,
		AccountMode: tenant.AccountModeRemote,
	}
}

func newCfg() *tenant.ProviderConfig {
	return &tenant.ProviderConfig{
		ID:            11,
		AppID:         7,
		Platform:      provider.PlatformApple,
		Scene:         provider.SceneApp,
		ProviderAppID: "com.example.ios",
		Env:           "prod",
		Status:        1,
	}
}

func newIDN() *identity.Identity {
	return &identity.Identity{
		ID:            31,
		AppID:         7,
		Platform:      provider.PlatformApple,
		ProviderAppID: "com.example.ios",
		OpenID:        "001234.abcdef",
		IdentityKey:   "001234.abcdef",
	}
}

func newBinding() *domainbinding.Binding {
	return &domainbinding.Binding{
		ID:             41,
		AppID:          7,
		ExternalUserID: "u_888",
		IdentityID:     31,
		Status:         domainbinding.StatusActive,
	}
}

type fixture struct {
	svc       *Service
	src       *fakeSource
	idents    *fakeIdentities
	binds     *fakeBindings
	audit     *fakeAudit
	tenantBox *fakeTenant
}

func newFixture(ev *provider.CallbackEvent) *fixture {
	src := &fakeSource{supportsVerify: true, supportsParse: true, event: ev}
	f := &fixture{
		src:       src,
		idents:    &fakeIdentities{idn: newIDN()},
		binds:     &fakeBindings{binding: newBinding(), remaining: 1},
		audit:     &fakeAudit{},
		tenantBox: &fakeTenant{app: newApp(), cfg: newCfg()},
	}
	f.svc = New(Deps{
		Tenant:     f.tenantBox,
		Sources:    &fakeRegistry{src: src},
		Identities: f.idents,
		Bindings:   f.binds,
		Audit:      f.audit,
	})
	return f
}

func input() Input {
	return Input{
		AppCode:  "biz_a",
		Platform: provider.PlatformApple,
		Scene:    provider.SceneApp,
		Raw: &provider.CallbackPayload{
			Platform: provider.PlatformApple,
			Scene:    provider.SceneApp,
			Body:     []byte("hdr.payload.sig"),
		},
	}
}

// --- 用例 ---

func TestConsentRevokedUnbinds(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	out, err := f.svc.Handle(context.Background(), input())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !out.Handled {
		t.Fatalf("期望 handled=true，实际 reason=%s", out.Reason)
	}
	if f.binds.unboundID != 31 {
		t.Fatalf("期望解绑 identity_id=31，实际=%d", f.binds.unboundID)
	}
	if out.ExternalUserID != "u_888" {
		t.Fatalf("期望回填 external_user_id，实际=%q", out.ExternalUserID)
	}
	if len(f.audit.events) != 1 || f.audit.events[0].Action != audit.ActionUnbind {
		t.Fatalf("期望写入一条 unbind 审计，实际=%+v", f.audit.events)
	}
}

// TestAudienceInjectedFromChannelConfig 断言编排层把渠道配置里的
// ProviderAppID 作为 aud 传给适配器——缺了这一步，任何别家 App 的通知
// 都可以被转发到我们的端点并触发解绑。
func TestAudienceInjectedFromChannelConfig(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	if _, err := f.svc.Handle(context.Background(), input()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if f.src.seenAudience != "com.example.ios" {
		t.Fatalf("期望注入 aud=com.example.ios，实际=%q", f.src.seenAudience)
	}
}

// TestRejectsWhenVerifyNotImplemented 是核心安全用例：
// 适配器没实现验签时，VerifyCallback 会返回 nil（宽容语义），
// notify 入口必须靠能力探测拦住，不能把 nil 当成"验签通过"。
func TestRejectsWhenVerifyNotImplemented(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	f.src.supportsVerify = false
	_, err := f.svc.Handle(context.Background(), input())
	if err == nil {
		t.Fatal("渠道未实现验签时必须拒绝处理")
	}
	if errs.CodeOf(err) != errs.CodeProviderNotSupported {
		t.Fatalf("期望 CodeProviderNotSupported，实际=%s", errs.CodeOf(err))
	}
	if f.binds.unboundID != 0 {
		t.Fatal("验签能力缺失时不得产生任何状态变更")
	}
}

func TestRejectsWhenVerifyFails(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	f.src.verifyErr = errs.New(errs.CodeAuthInvalidState, "验签失败")
	if _, err := f.svc.Handle(context.Background(), input()); err == nil {
		t.Fatal("验签失败必须拒绝")
	}
	if f.binds.unboundID != 0 {
		t.Fatal("验签失败时不得产生状态变更")
	}
	if len(f.audit.events) != 0 {
		t.Fatal("验签失败不应写业务审计（属于安全事件，走日志告警）")
	}
}

// TestIdempotentWhenAlreadyUnbound：平台会重复投递通知，
// 已解绑必须回"成功但未处理"，否则平台会永远重投。
func TestIdempotentWhenAlreadyUnbound(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	f.binds.binding = nil // FindActiveByIdentity 返回 ErrNotFound
	out, err := f.svc.Handle(context.Background(), input())
	if err != nil {
		t.Fatalf("重复投递不应报错: %v", err)
	}
	if out.Handled || out.Reason != "binding_already_unbound" {
		t.Fatalf("期望 handled=false/reason=binding_already_unbound，实际=%+v", out)
	}
}

// TestIdentityNotFoundIsNotError：用户可能从未在本应用登录，
// 平台仍会推通知（如账号删除）。回 error 会造成无限重投。
func TestIdentityNotFoundIsNotError(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventAccountDelete,
		Platform: provider.PlatformApple,
		OpenID:   "not-ours",
	})
	out, err := f.svc.Handle(context.Background(), input())
	if err != nil {
		t.Fatalf("身份不存在不应报错: %v", err)
	}
	if out.Handled || out.Reason != "identity_not_found" {
		t.Fatalf("期望 reason=identity_not_found，实际=%+v", out)
	}
}

// TestZeroBindingStillUnbinds：平台撤销是权威来源，
// 即使这是最后一个登录方式也必须照做，同时把"零绑定"写进审计供业务侧介入。
func TestZeroBindingStillUnbinds(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	f.binds.remaining = 0
	out, err := f.svc.Handle(context.Background(), input())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !out.Handled {
		t.Fatal("最后一个登录方式被平台撤销时仍必须解绑")
	}
	if f.binds.unboundID != 31 {
		t.Fatal("期望已解绑")
	}
	got := f.audit.events[0].Detail
	if got["zero_binding"] != true {
		t.Fatalf("期望审计标记 zero_binding=true，实际=%v", got["zero_binding"])
	}
}

// TestEmailDisabledKeepsBinding：邮箱停用不解除绑定，但必须留痕。
func TestEmailDisabledKeepsBinding(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventEmailDisabled,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	out, err := f.svc.Handle(context.Background(), input())
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if out.Handled {
		t.Fatal("email_disabled 不应改变绑定状态")
	}
	if f.binds.unboundID != 0 {
		t.Fatal("email_disabled 不得解绑")
	}
	if len(f.audit.events) != 1 {
		t.Fatalf("email_disabled 必须留痕，实际审计条数=%d", len(f.audit.events))
	}
}

// TestUnknownEventDoesNotFail：平台新增事件类型时宁可"收到但不处理"，
// 也不能回 5xx 让自己的端点被判定为故障。
func TestUnknownEventDoesNotFail(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventUnknown,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	out, err := f.svc.Handle(context.Background(), input())
	if err != nil {
		t.Fatalf("未知事件不应报错: %v", err)
	}
	if out.Reason != "unknown_event" {
		t.Fatalf("期望 reason=unknown_event，实际=%q", out.Reason)
	}
	if len(f.audit.events) != 1 {
		t.Fatal("未知事件必须留痕")
	}
}

// TestHandlePropagatesParseError：平台改字段导致解析失败属于兼容性问题，
// 必须暴露出来（4xx/5xx），不能静默成功——否则我们永远不知道通知丢了。
func TestHandlePropagatesParseError(t *testing.T) {
	f := newFixture(nil)
	f.src.parseErr = errs.New(errs.CodeAuthInvalidState, "events 缺失")
	if _, err := f.svc.Handle(context.Background(), input()); err == nil {
		t.Fatal("解析失败必须向上返回")
	}
}

// TestHandleRejectsMissingAppID：通知地址必须携带 app_id，
// 否则无法定位渠道凭据，也就无法验签——必须直接拒绝而不是"猜"。
func TestHandleRejectsMissingAppID(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{Type: provider.CallbackEventUnknown})
	in := input()
	in.AppCode = ""
	_, err := f.svc.Handle(context.Background(), in)
	if err == nil {
		t.Fatal("缺少 app_id 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("期望 CodeInvalidRequest，实际=%s", errs.CodeOf(err))
	}
}

// TestHandleRejectsEmptyBody 保护"空报文不得进入验签"这条底线。
func TestHandleRejectsEmptyBody(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{Type: provider.CallbackEventUnknown})
	in := input()
	in.Raw = nil
	if _, err := f.svc.Handle(context.Background(), in); err == nil {
		t.Fatal("空报文必须拒绝")
	}
}

// TestUnbindRepoErrorPropagates：数据库故障必须冒泡成 5xx，
// 让平台重投——静默成功会让通知永久丢失。
func TestUnbindRepoErrorPropagates(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:     provider.CallbackEventConsentRevoked,
		Platform: provider.PlatformApple,
		OpenID:   "001234.abcdef",
	})
	f.binds.unbindErr = errors.New("db down")
	if _, err := f.svc.Handle(context.Background(), input()); err == nil {
		t.Fatal("仓储故障必须冒泡")
	}
}

// TestAuditDetailIsSerializable 保证审计 detail 一定能落库（JSONB 列）。
func TestAuditDetailIsSerializable(t *testing.T) {
	f := newFixture(&provider.CallbackEvent{
		Type:       provider.CallbackEventConsentRevoked,
		Platform:   provider.PlatformApple,
		OpenID:     "001234.abcdef",
		OccurredAt: time.Unix(1700000000, 0).UTC(),
	})
	if _, err := f.svc.Handle(context.Background(), input()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if _, err := json.Marshal(f.audit.events[0].Detail); err != nil {
		t.Fatalf("审计 detail 不可序列化: %v", err)
	}
}
