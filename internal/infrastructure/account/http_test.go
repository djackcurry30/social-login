package account

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// fakeCenter 是一个最小的用户中心，用于验证客户端契约。
//
// 用 httptest 而不是打桩 Provider 接口：这里要验的正是"HTTP 报文与状态码
// 到领域语义的映射"，跳过 HTTP 层就等于没测。
type fakeCenter struct {
	srv      *httptest.Server
	lastIdem string
	lastPath string
	lastBody map[string]any
	// reply 由每个用例设置。
	reply func(w http.ResponseWriter, r *http.Request)
}

const testAppKey = "app_web_portal"

func newFakeCenter(t *testing.T) *fakeCenter {
	t.Helper()
	f := &fakeCenter{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastPath = r.URL.Path
		f.lastIdem = r.Header.Get(IdempotencyHeader)
		f.lastBody = nil
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				_ = json.Unmarshal(raw, &f.lastBody)
			}
		}
		if f.reply == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.reply(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCenter) provider(t *testing.T, timeout time.Duration) *HTTPProvider {
	t.Helper()
	p, err := NewHTTPProvider(HTTPConfig{BaseURL: f.srv.URL, Timeout: timeout})
	if err != nil {
		t.Fatalf("构造 provider 失败: %v", err)
	}
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeEnvelope 按契约 v1.1 的错误信封返回。
func writeEnvelope(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorEnvelope{Code: code, Message: msg})
}

// accountsPath 是测试里期望的路径前缀。
func accountsPath(appKey string) string { return "/v1/apps/" + appKey + "/accounts" }

// --- 配置校验 ---

func TestNewHTTPProviderRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  HTTPConfig
	}{
		{"空 base_url", HTTPConfig{}},
		{"缺 scheme", HTTPConfig{BaseURL: "uc.internal"}},
		{"错误 scheme", HTTPConfig{BaseURL: "ftp://uc.internal"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewHTTPProvider(c.cfg)
			if errs.CodeOf(err) != errs.CodeConfigInvalid {
				t.Fatalf("应为 CONFIG.INVALID，实际 %v", errs.CodeOf(err))
			}
		})
	}
}

// 末尾斜杠不该产生 //accounts 这种路径。
func TestNewHTTPProviderTrimsTrailingSlash(t *testing.T) {
	p, err := NewHTTPProvider(HTTPConfig{BaseURL: "https://uc.internal/"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if p.baseURL != "https://uc.internal" {
		t.Fatalf("baseURL 未裁掉尾部斜杠: %q", p.baseURL)
	}
}

// --- 应用维度 ---

// TestPathsCarryAppKey 断言每个端点都带应用前缀。
//
// 这是 v1.1 的核心：漏掉它，用户中心只能有一个全局账号空间。
func TestPathsCarryAppKey(t *testing.T) {
	cases := []struct {
		name string
		want string
		call func(p *HTTPProvider) error
	}{
		{
			name: "Get",
			want: accountsPath(testAppKey) + "/u-1",
			call: func(p *HTTPProvider) error {
				_, err := p.Get(context.Background(), testAppKey, "u-1")
				return err
			},
		},
		{
			name: "GetByClaim",
			want: accountsPath(testAppKey) + "/by-claim",
			call: func(p *HTTPProvider) error {
				_, err := p.GetByClaim(context.Background(), testAppKey,
					domainaccount.Claim{Type: "phone", Value: "13800000000"})
				return err
			},
		},
		{
			name: "Create",
			want: accountsPath(testAppKey),
			call: func(p *HTTPProvider) error {
				_, err := p.Create(context.Background(), domainaccount.CreateRequest{
					AppKey: testAppKey, IdempotencyKey: "k1",
				})
				return err
			},
		},
		{
			name: "Merge",
			want: accountsPath(testAppKey) + "/merge",
			call: func(p *HTTPProvider) error {
				_, err := p.Merge(context.Background(), domainaccount.MergeRequest{
					AppKey: testAppKey, TargetUserID: "a", SourceUserID: "b", IdempotencyKey: "k1",
				})
				return err
			},
		},
		{
			name: "ReplaceClaim",
			want: accountsPath(testAppKey) + "/u-1/claims/phone",
			call: func(p *HTTPProvider) error {
				_, err := p.ReplaceClaim(context.Background(), domainaccount.ReplaceClaimRequest{
					AppKey: testAppKey, UserID: "u-1",
					Claim: domainaccount.Claim{Type: "phone", Value: "13900000000"},
				})
				return err
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeCenter(t)
			f.reply = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
			_ = c.call(f.provider(t, time.Second))
			if f.lastPath != c.want {
				t.Fatalf("路径不符\n期望 %s\n实际 %s", c.want, f.lastPath)
			}
		})
	}
}

// TestRequireAppKeyLocally 断言空 appKey 在本地就被拦掉。
//
// 不拦的后果：拼出 /v1/apps//accounts，对端 404，我们译成"账号不存在"——
// 而真相是调用方少传了个参数。空租户是那种"不报错、只查错人"的错误。
func TestRequireAppKeyLocally(t *testing.T) {
	f := newFakeCenter(t)
	p := f.provider(t, time.Second)
	ctx := context.Background()

	if _, err := p.Get(ctx, "", "u-1"); errs.CodeOf(err) != errs.CodeInternal {
		t.Fatalf("空 appKey 应本地拒绝，实际 %v", err)
	}
	if _, err := p.GetByClaim(ctx, "  ", domainaccount.Claim{Type: "phone", Value: "1"}); errs.CodeOf(err) != errs.CodeInternal {
		t.Fatalf("空 appKey 应本地拒绝，实际 %v", err)
	}
	if _, err := p.Create(ctx, domainaccount.CreateRequest{IdempotencyKey: "k"}); errs.CodeOf(err) != errs.CodeInternal {
		t.Fatalf("空 appKey 应本地拒绝，实际 %v", err)
	}
	if f.lastPath != "" {
		t.Fatalf("空 appKey 时不应发出请求，实际打到 %s", f.lastPath)
	}
}

// --- Get ---

func TestGetDecodesAccount(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, accountDTO{
			UserID: "u-1", Status: "active",
			Claims: []claimDTO{{Type: "phone", Value: "13800000000", Source: "wechat_phone"}},
			Extra:  map[string]any{"nickname": "张三"},
		})
	}
	acc, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if acc.UserID != "u-1" || acc.Status != domainaccount.StatusActive {
		t.Fatalf("账号解析不符: %+v", acc)
	}
	if len(acc.Claims) != 1 || acc.Claims[0].Value != "13800000000" {
		t.Fatalf("凭证解析不符: %+v", acc.Claims)
	}
}

func TestGetNotFound(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusNotFound, CodeUpstreamNotFound, "account not found")
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-missing")
	if err != domainaccount.ErrNotFound {
		t.Fatalf("应返回 ErrNotFound，实际 %v", err)
	}
}

// 缺 user_id 的响应必须被拒绝：否则业务层会把它当成"账号状态非 active"
// 静默跳过归并，排障方向完全错。
func TestGetRejectsAccountWithoutUserID(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, accountDTO{Status: "active"})
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
}

func TestGetRejectsUnknownStatus(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, accountDTO{UserID: "u-1", Status: "banned"})
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("未知状态应拒绝，实际 %v", errs.CodeOf(err))
	}
}

// --- GetByClaim ---

func TestGetByClaimSendsQueryAndMapsMultiple(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("type"); got != "phone" {
			t.Errorf("type 参数不符: %s", got)
		}
		if got := r.URL.Query().Get("value"); got != "13800000000" {
			t.Errorf("value 参数不符: %s", got)
		}
		writeEnvelope(w, http.StatusConflict, CodeUpstreamMultiple, "multiple accounts matched")
	}
	_, err := f.provider(t, time.Second).GetByClaim(context.Background(), testAppKey,
		domainaccount.Claim{Type: "phone", Value: "13800000000"})
	if err != domainaccount.ErrMultipleAccounts {
		t.Fatalf("409 + ACCOUNT.MULTIPLE 应映射为 ErrMultipleAccounts，实际 %v", err)
	}
}

// --- Create ---

func TestCreateSendsIdempotencyKey(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("方法不符: %s", r.Method)
		}
		writeJSON(w, http.StatusCreated, accountDTO{UserID: "u-new", Status: "active"})
	}
	acc, err := f.provider(t, time.Second).Create(context.Background(), domainaccount.CreateRequest{
		AppKey:         testAppKey,
		Claims:         []domainaccount.Claim{{Type: "phone", Value: "13800000000", Source: "wechat_phone"}},
		IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if acc.UserID != "u-new" {
		t.Fatalf("账号解析不符: %+v", acc)
	}
	// 幂等键是 P0-4 的落地点：漏了这个头，对端就无法去重。
	if f.lastIdem != "idem-1" {
		t.Fatalf("必须带 Idempotency-Key，实际 %q", f.lastIdem)
	}
	if f.lastBody["claims"] == nil {
		t.Fatalf("请求体应携带 claims: %+v", f.lastBody)
	}
}

func TestCreateRequiresIdempotencyKey(t *testing.T) {
	f := newFakeCenter(t)
	_, err := f.provider(t, time.Second).Create(context.Background(),
		domainaccount.CreateRequest{AppKey: testAppKey})
	if errs.CodeOf(err) != errs.CodeInternal {
		t.Fatalf("缺幂等键应为 INTERNAL.ERROR，实际 %v", errs.CodeOf(err))
	}
	if f.lastPath != "" {
		t.Fatal("缺幂等键时不应发出请求")
	}
}

func TestCreateNotSupported(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		f := newFakeCenter(t)
		st := status
		// 契约：不提供该能力时【不带 code】。
		f.reply = func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, st, map[string]any{"error": "not supported"})
		}
		_, err := f.provider(t, time.Second).Create(context.Background(), domainaccount.CreateRequest{
			AppKey: testAppKey, IdempotencyKey: "idem-1",
		})
		if errs.CodeOf(err) != errs.CodeAccountNotSupported {
			t.Fatalf("%d 应映射为 ACCOUNT.NOT_SUPPORTED，实际 %v", st, errs.CodeOf(err))
		}
	}
}

// TestCreate404WithCodeIsNotSupported 守住 404 的双重含义。
//
// 404 有两种：路由不存在（= 不提供该能力），和资源不存在（= 应用未注册）。
// 判错方向很糟：本该提示"应用没注册"，却让业务方去改 on_unbound_login 配置。
// 判据是"有没有错误码"——带码说明对端认识这个请求。
func TestCreate404WithCodeIsNotSupported(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusNotFound, CodeUpstreamAppUnknown, "app not registered")
	}
	_, err := f.provider(t, time.Second).Create(context.Background(), domainaccount.CreateRequest{
		AppKey: testAppKey, IdempotencyKey: "k1",
	})
	if errs.CodeOf(err) == errs.CodeAccountNotSupported {
		t.Fatal("带错误码的 404 不能被当成'对端不提供创建能力'")
	}
	if e, ok := errs.As(err); !ok || !strings.Contains(e.Message, "注册") {
		t.Fatalf("应提示应用未注册，实际 %+v", e)
	}
}

func TestCreateConflictMapsToIdentityTaken(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusConflict, CodeUpstreamClaimTaken, "phone taken")
	}
	_, err := f.provider(t, time.Second).Create(context.Background(), domainaccount.CreateRequest{
		AppKey:         testAppKey,
		Claims:         []domainaccount.Claim{{Type: "phone", Value: "13800000000"}},
		IdempotencyKey: "idem-1",
	})
	if errs.CodeOf(err) != errs.CodeBindIdentityTaken {
		t.Fatalf("ACCOUNT.CLAIM_TAKEN 应映射为 BIND.IDENTITY_TAKEN，实际 %v", errs.CodeOf(err))
	}
}

// --- Merge ---

func TestMergeSendsIdempotencyAndParsesResult(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mergeResultDTO{
			Merged:        false,
			AlreadyMerged: true,
			RemoteRef:     map[string]any{"ticket": "m-1"},
		})
	}
	res, err := f.provider(t, time.Second).Merge(context.Background(), domainaccount.MergeRequest{
		AppKey:       testAppKey,
		TargetUserID: "u-a", SourceUserID: "u-b",
		IdempotencyKey: "merge-1", Reason: "用户主动绑定",
	})
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if !res.AlreadyMerged || res.Merged {
		t.Fatalf("幂等命中应表现为 already_merged: %+v", res)
	}
	if f.lastIdem != "merge-1" {
		t.Fatalf("必须带 Idempotency-Key，实际 %q", f.lastIdem)
	}
	if f.lastBody["target_user_id"] != "u-a" || f.lastBody["source_user_id"] != "u-b" {
		t.Fatalf("请求体不符: %+v", f.lastBody)
	}
}

// TestMergeParsesDiscardedClaims 断言被丢弃的凭证会回传给上层。
//
// 不回传的话，用户对"我另一个手机号去哪了"完全无感知，客服也查不出来。
func TestMergeParsesDiscardedClaims(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mergeResultDTO{
			Merged: true,
			DiscardedClaims: []claimDTO{
				{Type: "phone", Value: "13800000011", Source: "alipay_phone"},
			},
		})
	}
	res, err := f.provider(t, time.Second).Merge(context.Background(), domainaccount.MergeRequest{
		AppKey: testAppKey, TargetUserID: "a", SourceUserID: "b", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if len(res.DiscardedClaims) != 1 || res.DiscardedClaims[0].Value != "13800000011" {
		t.Fatalf("未解析 discarded_claims: %+v", res.DiscardedClaims)
	}
}

func TestMergeRequiresIdempotencyKey(t *testing.T) {
	f := newFakeCenter(t)
	_, err := f.provider(t, time.Second).Merge(context.Background(), domainaccount.MergeRequest{
		AppKey: testAppKey, TargetUserID: "u-a", SourceUserID: "u-b",
	})
	if errs.CodeOf(err) != errs.CodeInternal {
		t.Fatalf("缺幂等键应为 INTERNAL.ERROR，实际 %v", errs.CodeOf(err))
	}
}

// --- 错误信封 ---

// TestEnvelopeIdemInProgressIsRetryable 是信封存在的主要理由。
//
// 同样是 409 + Create：CLAIM_TAKEN 要换流程，IDEMPOTENCY_IN_PROGRESS 要重试。
// 只看状态码根本分不开。
func TestEnvelopeIdemInProgressIsRetryable(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusConflict, CodeUpstreamIdemInProgress, "another request in flight")
	}
	_, err := f.provider(t, time.Second).Create(context.Background(), domainaccount.CreateRequest{
		AppKey: testAppKey, IdempotencyKey: "k1",
	})
	if errs.CodeOf(err) == errs.CodeBindIdentityTaken {
		t.Fatal("幂等处理中不能被译成'凭证被占用'")
	}
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if !errs.Retryable(err) {
		t.Fatal("幂等处理中必须可重试")
	}
}

// TestRaw409IsNotGuessed 断言"没有错误码的 409 不猜具体原因"。
//
// 猜错比不猜更糟：把"数据脏"说成"凭证被占用"，会让调用方去做一件
// 完全不相关的事。
func TestRaw409IsNotGuessed(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusConflict) }
	_, err := f.provider(t, time.Second).Create(context.Background(), domainaccount.CreateRequest{
		AppKey:         testAppKey,
		Claims:         []domainaccount.Claim{{Type: "phone", Value: "13800000000"}},
		IdempotencyKey: "k1",
	})
	if errs.CodeOf(err) == errs.CodeBindIdentityTaken {
		t.Fatal("无错误码的 409 不应被猜成'凭证被占用'")
	}
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if errs.Retryable(err) {
		t.Fatal("无码的 409 无法判定原因，不应标记可重试")
	}
}

// Test5xxBeatsEnvelopeCode 断言 5xx 优先于信封。
//
// 上游故障时对端可能返回任意 code（甚至来自网关的错误页）。
// 把 5xx 译成不可重试，等于把一次抖动变成用户的一次登录失败。
func Test5xxBeatsEnvelopeCode(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusInternalServerError, CodeUpstreamClaimTaken, "boom")
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("5xx 应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if !errs.Retryable(err) {
		t.Fatal("5xx 必须可重试，即使信封里写了别的码")
	}
}

// TestEnvelopeAppUnknownNotRetryable 验证"应用未注册"的判断。
//
// 不可重试：重试一百次还是没注册。文案要指向真正的原因。
func TestEnvelopeAppUnknownNotRetryable(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusBadRequest, CodeUpstreamAppUnknown, "app not registered")
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if errs.Retryable(err) {
		t.Fatal("未注册应用不可重试")
	}
	if e, ok := errs.As(err); !ok || !strings.Contains(e.Message, "注册") {
		t.Fatalf("文案应指向上游注册问题，实际 %+v", e)
	}
	if e, ok := errs.As(err); !ok || e.Details["upstream_code"] != CodeUpstreamAppUnknown {
		t.Fatalf("应保留对端错误码便于排查: %+v", e)
	}
}

// --- ReplaceClaim ---

func TestReplaceClaimSendsBodyAndDecodesAccount(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("方法不符: %s", r.Method)
		}
		writeJSON(w, http.StatusOK, accountDTO{
			UserID: "u-1", Status: "active",
			Claims: []claimDTO{{Type: "phone", Value: "13900000000", Source: "sms"}},
		})
	}
	acc, err := f.provider(t, time.Second).ReplaceClaim(context.Background(), domainaccount.ReplaceClaimRequest{
		AppKey: testAppKey, UserID: "u-1",
		Claim: domainaccount.Claim{Type: "phone", Value: "13900000000", Source: "sms"},
	})
	if err != nil {
		t.Fatalf("换绑失败: %v", err)
	}
	if acc.Claims[0].Value != "13900000000" {
		t.Fatalf("换绑结果不符: %+v", acc.Claims)
	}
	if f.lastBody["value"] != "13900000000" || f.lastBody["source"] != "sms" {
		t.Fatalf("请求体不符: %+v", f.lastBody)
	}
}

func TestReplaceClaimTakenMapsToIdentityTaken(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusConflict, CodeUpstreamClaimTaken, "taken")
	}
	_, err := f.provider(t, time.Second).ReplaceClaim(context.Background(), domainaccount.ReplaceClaimRequest{
		AppKey: testAppKey, UserID: "u-1",
		Claim: domainaccount.Claim{Type: "phone", Value: "13900000000"},
	})
	if errs.CodeOf(err) != errs.CodeBindIdentityTaken {
		t.Fatalf("应为 BIND.IDENTITY_TAKEN，实际 %v", errs.CodeOf(err))
	}
}

// --- 错误归一化 ---

// 用户中心 5xx 必须报 ACCOUNT.UNAVAILABLE（可重试），而不是 PROVIDER.*。
// 排障方向完全不同：前者查用户中心，后者会去查微信/支付宝。
func TestUpstream5xxMapsToAccountUnavailable(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream boom", http.StatusBadGateway)
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if !errs.Retryable(err) {
		t.Fatal("5xx 应标记为可重试")
	}
	if e, ok := errs.As(err); !ok || e.Details["status"] != http.StatusBadGateway {
		t.Fatalf("应带 upstream status 便于排障: %+v", e)
	}
}

func TestUpstreamTimeoutMapsToAccountUnavailable(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}
	// 超时设短一点，避免测试变慢。
	_, err := f.provider(t, 80*time.Millisecond).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("超时应归为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if !errs.Retryable(err) {
		t.Fatal("超时应标记为可重试（重试由上层决定，本层不重试）")
	}
}

// 4xx（非特判）说明契约不符，归为不可重试的 ACCOUNT.UNAVAILABLE。
func TestUpstream4xxIsNotRetryable(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"bad"}`, http.StatusBadRequest)
	}
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", errs.CodeOf(err))
	}
	if errs.Retryable(err) {
		t.Fatal("4xx 不应标记为可重试")
	}
	if e, ok := errs.As(err); !ok || !strings.Contains(e.Details["upstream_error"].(string), "bad") {
		t.Fatalf("应保留对端错误片段: %+v", e)
	}
}

func TestGetRejectsEmptyUserID(t *testing.T) {
	f := newFakeCenter(t)
	_, err := f.provider(t, time.Second).Get(context.Background(), testAppKey, "  ")
	if errs.CodeOf(err) != errs.CodeInternal {
		t.Fatalf("空 user_id 应为 INTERNAL.ERROR，实际 %v", errs.CodeOf(err))
	}
	if f.lastPath != "" {
		t.Fatal("空 user_id 不应发出请求")
	}
}

// --- 注销（Close）---

// 注销走内部接口前缀，不是业务契约的 /v1。
//
// 这条断言看似琐碎，但它守的是一个已经发生过的故障：路径写成 /v1/... 时，
// 对端返回 404，而 404 与"账号不存在"同码——注销于是"成功"了，
// 本地数据清空、对端账号仍在。
func TestCloseUsesInternalPath(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("注销应为 POST，实际 %s", r.Method)
		}
		writeJSON(w, http.StatusOK, map[string]string{"user_id": "u-1", "status": "closed"})
	}
	if err := f.provider(t, time.Second).Close(context.Background(), testAppKey, "u-1"); err != nil {
		t.Fatalf("注销应成功: %v", err)
	}
	want := "/internal/v1/apps/" + testAppKey + "/accounts/u-1/close"
	if f.lastPath != want {
		t.Fatalf("路径应为 %s，实际 %s", want, f.lastPath)
	}
}

// 带信封的 404 表示"账号本就不存在"，按幂等成功处理。
func TestCloseTreatsEnvelopedNotFoundAsSuccess(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusNotFound, CodeUpstreamNotFound, "account not found")
	}
	if err := f.provider(t, time.Second).Close(context.Background(), testAppKey, "u-1"); err != nil {
		t.Fatalf("账号不存在应视为已注销: %v", err)
	}
}

// 裸 404 必须报错。
//
// 它可能来自路径写错、base_url 少前缀、网关没转发、对端版本落后。
// 把这些当成"已注销"，用户会得到一句 200 和一份还在的账号数据。
func TestCloseRejectsBareNotFound(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // 无信封的裸 404
	}
	err := f.provider(t, time.Second).Close(context.Background(), testAppKey, "u-1")
	if err == nil {
		t.Fatal("裸 404 不能被当成注销成功")
	}
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %s", errs.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "未提供注销接口") {
		t.Fatalf("文案应指向真正原因（对端没有该接口），实际: %v", err)
	}
}

// 5xx 可重试：这类失败重试一次往往就好了。
func TestCloseMapsServerErrorAsRetryable(t *testing.T) {
	f := newFakeCenter(t)
	f.reply = func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusServiceUnavailable, "PROVIDER.UNAVAILABLE", "down")
	}
	err := f.provider(t, time.Second).Close(context.Background(), testAppKey, "u-1")
	if errs.CodeOf(err) != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %s", errs.CodeOf(err))
	}
	if !errs.Retryable(err) {
		t.Fatalf("5xx 应标记为可重试，实际 %v", err)
	}
}
