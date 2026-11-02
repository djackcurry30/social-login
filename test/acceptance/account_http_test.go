// 本文件是"用户中心 HTTP 适配层"的端到端验收。
//
// 背景：用户中心尚未开始建设，`account.provider=http` 这条路径此前只有
// infrastructure/account/http_test.go 的片段级单测（httptest 假端点）。
// 单测能证明"报文映射对"，证明不了：
//
//   - 真实登录流程里 Create 是不是在正确的时点被调用、幂等键是不是真的带上了；
//   - 建出来的账号 user_id 会不会真的被用于写绑定（而不是又用回了三方 open_id）；
//   - 对端 5xx / 不提供 Create 时，用户看到的到底是什么，本地有没有留下半截数据。
//
// 这些是"接上真实用户中心那天"最容易出问题的地方，而它们与对端内部实现无关，
// 现在就能验。载体是 internal/testsupport/mockusercenter（契约的可执行版本）。
//
// ⚠️ 这里验的是【我方适配层 + 编排】。对端自身的强一致读、幂等实现、容量与延迟
// 不在覆盖范围内，见 docs/user-center-integration.md 的"不能由 mock 替代的事项"。
package acceptance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/bootstrap"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/testsupport/mockusercenter"
)

// newUserCenter 起一个假用户中心，并返回一个把它接进装配的 harness。
//
// 策略固定为 auto_create：这是唯一会调用 AccountProvider.Create 的分支
// （need_register 把建号责任交给业务方，走不到用户中心）。
func newUserCenter(t *testing.T, uc *mockusercenter.Server) *harness {
	t.Helper()
	srv := httptest.NewServer(uc.Handler())
	t.Cleanup(srv.Close)

	return newHarnessOpts(t, harnessOptions{
		Config: func(c *bootstrap.Config) {
			c.Account.Provider = "http"
			c.Account.HTTP.BaseURL = srv.URL
			// 与生产默认值一致（3s）；测试里再短一点，避免故障注入时等太久。
			c.Account.HTTP.Timeout = 2 * time.Second
			// 注册同步默认开启（生产由 viper 默认值给 true）。这里显式打开，
			// 是因为 harness 直接构造 Config 结构体，不走 viper 的默认值——
			// 不开的话 AppSync 为 nil，与生产行为不一致。
			c.Account.Sync.Enabled = true
		},
		Policy: func(p *tenant.Policy) {
			p.OnUnboundLogin = tenant.OnUnboundAutoCreate
		},
	})
}

// loginOnce 走完 authorize → 三方授权 → 回调，返回回调响应与解析后的 JSON。
//
// 与 harness.authorizeAndCallback 的区别：后者要求回调必定 302（带 Location），
// 而失败路径（对端不可用、配置不支持）会返回 5xx JSON。验收失败路径时就
// 必须能拿到状态码与报文，否则只能看到"未返回 Location"这种没有信息量的断言。
func (h *harness) loginOnce(t *testing.T) (*http.Response, map[string]any, string) {
	t.Helper()

	q := url.Values{}
	q.Set("app_id", h.appCode)
	q.Set("platform", provider.PlatformGenericOAuth2)
	q.Set("scene", provider.SceneWeb)
	q.Set("mode", provider.ModeLogin)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("state", "uc-state-1")
	q.Set("response_mode", "json")

	authResp := h.getNoRedirect(h.serverURL + "/v1/authorize?" + q.Encode())
	body, _ := io.ReadAll(authResp.Body)
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize 期望 200，实际 %d：%s", authResp.StatusCode, body)
	}
	var ar struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(body, &ar); err != nil || ar.RedirectURL == "" {
		t.Fatalf("解析 authorize 响应失败: %v (%s)", err, body)
	}

	pr := h.getNoRedirect(ar.RedirectURL)
	callbackURL := pr.Header.Get("Location")
	pr.Body.Close()
	if callbackURL == "" {
		t.Fatalf("自建 OAuth2 服务未返回回跳地址")
	}

	cb := h.getNoRedirect(callbackURL)
	loc := cb.Header.Get("Location")
	raw, _ := io.ReadAll(cb.Body)
	cb.Body.Close()

	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return cb, out, loc
}

// TestHTTPAccountProviderAutoCreate 是"用户中心路径"的主验收。
func TestHTTPAccountProviderAutoCreate(t *testing.T) {
	uc := mockusercenter.New(mockusercenter.Config{})
	h := newUserCenter(t, uc)

	cb, out, loc := h.loginOnce(t)
	if cb.StatusCode != http.StatusFound {
		t.Fatalf("首次登录应 302 回到业务方，实际 %d：%v", cb.StatusCode, out)
	}
	q := mustQuery(t, loc)
	if errCode := q.Get("error"); errCode != "" {
		t.Fatalf("登录失败: %s（Location=%s）", errCode, loc)
	}
	code := q.Get("code")
	if code == "" {
		t.Fatalf("应返回 auth_code（Location=%s）", loc)
	}

	// ① 用户中心必须收到一次 Create，且带幂等键。
	calls := uc.CallsOf(mockusercenter.OpCreate)
	if len(calls) != 1 {
		t.Fatalf("首次登录应调用一次 Create，实际 %d 次: %+v", len(calls), calls)
	}
	if calls[0].IdempotencyKey == "" {
		t.Fatal("Create 必须携带幂等键（P0-4：没有它重试会建出重复账号）")
	}
	if calls[0].Status != http.StatusOK && calls[0].Status != http.StatusCreated {
		t.Fatalf("Create 未成功，对端记录：%+v", calls[0])
	}
	// 应用维度必须真的传下去（v1.1）：漏了它，用户中心只有一个全局账号空间，
	// 另一个应用的同号用户会登进这个账号。这里断言的是"适配层没把它丢掉"，
	// 与对端怎么用无关。
	if calls[0].AppKey != h.appCode {
		t.Fatalf("Create 必须携带 app_code，期望 %q 实际 %q", h.appCode, calls[0].AppKey)
	}

	// ② 账号建在用户中心，本侧不落账号表（约束 C4）。
	if n := uc.Count(); n != 1 {
		t.Fatalf("用户中心应有 1 个账号，实际 %d", n)
	}
	accounts := uc.Accounts()
	ucUserID := accounts[0].UserID

	// ③ 关键：令牌的 sub 必须是【用户中心的 user_id】，不是三方 open_id。
	//    写错这一处，后续每一次合并、每一次回源核对都会查不到人。
	resp, tok := h.postJSON("/v1/token", nil, map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     h.appCode,
		"client_secret": testAppSecret,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("换令牌失败 %d：%v", resp.StatusCode, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("未返回 access_token: %v", tok)
	}
	resp, info := h.postJSON("/v1/introspect", h.appHeaders(), map[string]any{"token": access})
	if resp.StatusCode != http.StatusOK || info["active"] != true {
		t.Fatalf("introspect 应 active=true，实际 %d：%v", resp.StatusCode, info)
	}
	if sub, _ := info["sub"].(string); sub != ucUserID {
		t.Fatalf("令牌 sub 必须是用户中心账号 %q，实际 %q", ucUserID, sub)
	}

	// ④ 二次登录：已有活跃绑定，不应再调 Create。
	cb2, out2, loc2 := h.loginOnce(t)
	if cb2.StatusCode != http.StatusFound {
		t.Fatalf("二次登录应成功，实际 %d：%v", cb2.StatusCode, out2)
	}
	if mustQuery(t, loc2).Get("code") == "" {
		t.Fatalf("二次登录应直接返回 auth_code（Location=%s）", loc2)
	}
	if n := len(uc.CallsOf(mockusercenter.OpCreate)); n != 1 {
		t.Fatalf("二次登录不得重复建号，Create 调用累计 %d 次", n)
	}
	if n := uc.Count(); n != 1 {
		t.Fatalf("用户中心账号数应保持 1，实际 %d", n)
	}
}

// TestHTTPAccountProviderCreateUnsupported 验证"对端不提供建号能力"的降级。
//
// 这种情况在真实联调里很常见：账号由别的系统创建，用户中心不开放写入。
// 契约允许对端用 404/405/501 表达，我方必须给出【可操作的】错误。
func TestHTTPAccountProviderCreateUnsupported(t *testing.T) {
	uc := mockusercenter.New(mockusercenter.Config{CreateUnsupported: true})
	h := newUserCenter(t, uc)

	code, q := h.loginError(t)
	if code != "AUTH.INVALID_CONFIG" {
		t.Fatalf("期望 AUTH.INVALID_CONFIG，实际 %q（%s）", code, q.Encode())
	}
	// 文案必须告诉运维【改哪个配置】。只说"登录失败"，现场只能去猜。
	if desc := q.Get("error_description"); !strings.Contains(desc, "need_register") {
		t.Fatalf("错误描述应提示改成 need_register，实际 %q", desc)
	}
	if n := uc.Count(); n != 0 {
		t.Fatalf("失败时不应留下账号，实际 %d", n)
	}
	if n := len(uc.CallsOf(mockusercenter.OpCreate)); n != 1 {
		t.Fatalf("应恰好尝试一次 Create（不重试，C6），实际 %d 次", n)
	}
}

// TestHTTPAccountProviderUnavailableFailsFast 验证对端故障时的行为。
//
// 架构 §6.2：用户中心不可用时登录链路必须【快速失败】——无法确认账号归属时
// 不能猜一个进去。同时验证"失败不留半截数据"：故障恢复后重新登录应一次成功，
// 且用户中心只有一个账号。
func TestHTTPAccountProviderUnavailableFailsFast(t *testing.T) {
	uc := mockusercenter.New(mockusercenter.Config{})
	h := newUserCenter(t, uc)

	uc.InjectFault(mockusercenter.OpCreate, mockusercenter.FaultServerError, 0)

	code, q := h.loginError(t)
	if code != "ACCOUNT.UNAVAILABLE" {
		t.Fatalf("错误码必须是 ACCOUNT.UNAVAILABLE（不能是 PROVIDER.*），实际 %q", code)
	}
	// 上游 5xx 是"现在不行、等会再试"，接入方据此决定是否重试。
	if r := q.Get("retryable"); r != "true" {
		t.Fatalf("上游 5xx 必须 retryable=true，实际 %q", r)
	}
	// 文案里要出现"用户中心"，否则排障的人会去查微信/支付宝。
	if desc := q.Get("error_description"); !strings.Contains(desc, "用户中心") {
		t.Fatalf("错误描述应指明是用户中心，实际 %q", desc)
	}

	// 故障恢复后重新登录：应当一次成功，证明前面没有留下半截绑定。
	uc.ClearFaults()
	_, out, loc := h.loginOnce(t)
	if out != nil {
		t.Fatalf("恢复后应 302 回跳，实际 JSON：%v", out)
	}
	if mustQuery(t, loc).Get("code") == "" {
		t.Fatalf("恢复后应返回 auth_code（Location=%s）", loc)
	}
	if n := uc.Count(); n != 1 {
		t.Fatalf("用户中心应只有 1 个账号，实际 %d", n)
	}
}

// TestHTTPAccountProviderRateLimited 验证对端 429 的映射。
//
// 429 与 5xx 的处理不同：它不是"对端挂了"，而是"我们超配额"。
// 混成同一个码，限流告警会被当成故障告警处理，进而触发无意义的值班升级。
func TestHTTPAccountProviderRateLimited(t *testing.T) {
	uc := mockusercenter.New(mockusercenter.Config{})
	h := newUserCenter(t, uc)

	uc.InjectFault(mockusercenter.OpCreate, mockusercenter.FaultRateLimited, 0)

	code, q := h.loginError(t)
	if code != "RATE.LIMITED" {
		t.Fatalf("对端 429 应映射 RATE.LIMITED，实际 %q", code)
	}
	if r := q.Get("retryable"); r != "true" {
		t.Fatalf("限流应 retryable=true（稍后重试有意义），实际 %q", r)
	}
	if n := uc.Count(); n != 0 {
		t.Fatalf("限流时不应建号，实际 %d", n)
	}
}

// TestHTTPAccountProviderAppNotRegistered 验证"应用未同步到用户中心"的降级。
//
// 这是 §2.6 里"不做懒注册"的代价，也是它唯一会被用户感知到的地方：
// 应用没同步过去时，该应用所有登录都会失败。文案必须指向"注册同步"，
// 否则运维看到 ACCOUNT.UNAVAILABLE 会去查用户中心是不是挂了。
func TestHTTPAccountProviderAppNotRegistered(t *testing.T) {
	// 要求应用已注册，但一个都没注册：任何 app_code 都会得到 APP.UNKNOWN。
	uc := mockusercenter.New(mockusercenter.Config{RequireRegisteredApp: true})
	h := newUserCenter(t, uc)

	code, q := h.loginError(t)
	if code != "ACCOUNT.UNAVAILABLE" {
		t.Fatalf("应用未注册应映射 ACCOUNT.UNAVAILABLE，实际 %q", code)
	}
	// 不可重试：重试一百次还是没注册。
	// 注意回跳约定：只有可重试时才带 retryable=true，不可重试时该参数缺席
	// （见 authflow/redirectError）。所以这里断言"没有 true"，不是"等于 false"。
	if r := q.Get("retryable"); r == "true" {
		t.Fatalf("应用未注册不可重试，实际 retryable=%q", r)
	}
	if desc := q.Get("error_description"); !strings.Contains(desc, "注册") {
		t.Fatalf("文案应指向注册同步，实际 %q", desc)
	}
	if n := uc.Count(); n != 0 {
		t.Fatalf("失败时不应建号，实际 %d", n)
	}
}

// loginError 断言本次登录【失败】，并返回回跳地址里的 error 与完整 query。
//
// 失败形态是"302 回跳业务方 + error/error_description/retryable"，
// 不是 5xx 页面（见 handler/oauth.go 的 Callback）：用户看到的是业务方
// 统一的错误提示，而不是我们的内部信息。因此失败用例不能断言状态码。
func (h *harness) loginError(t *testing.T) (string, url.Values) {
	t.Helper()
	cb, out, loc := h.loginOnce(t)
	if out != nil && len(out) > 0 {
		t.Fatalf("失败应回跳业务方而不是返回 JSON：status=%d %v", cb.StatusCode, out)
	}
	if cb.StatusCode != http.StatusFound || loc == "" {
		t.Fatalf("失败应 302 回跳，实际 status=%d loc=%q", cb.StatusCode, loc)
	}
	q := mustQuery(t, loc)
	code := q.Get("error")
	if code == "" {
		t.Fatalf("回跳地址必须带 error 参数，实际 %s", loc)
	}
	if q.Get("state") != "uc-state-1" {
		t.Fatalf("业务侧 state 必须原样回传，实际 %s", loc)
	}
	return code, q
}

// TestAppRegistrationReconcileUnlocksLogin 验收"应用注册是登录前置条件"。
//
// 这是 §2.6 的完整语义，也是用户中心上线后最可能踩的第一个坑：应用没同步
// 过去时，该应用【所有】登录都会 400 APP.UNKNOWN。这条用例把三段连起来：
//
//	未注册 → 登录失败（错误指向注册，不是"用户中心挂了"）
//	跑一轮对账 → 对端收到 app_key（值等于本地 app_code）
//	再登录 → 成功，且本地记录了同步时间
//
// 对账用 AppSync().Reconcile 主动触发，而不是等 5 分钟定时器——验的是同一段
// 代码，生产里由"启动即对账 + 定时对账"驱动。
func TestAppRegistrationReconcileUnlocksLogin(t *testing.T) {
	// 要求已注册，且初始一个都没注册：任何 app_code 都会被拒。
	uc := mockusercenter.New(mockusercenter.Config{RequireRegisteredApp: true})
	h := newUserCenter(t, uc)

	if h.app.AppSync() == nil {
		t.Fatal("provider=http 时应装配注册同步服务")
	}

	// 1) 未注册：登录失败。
	code, q := h.loginError(t)
	if code != "ACCOUNT.UNAVAILABLE" {
		t.Fatalf("未注册应用应登录失败（ACCOUNT.UNAVAILABLE），实际 %q", code)
	}
	if desc := q.Get("error_description"); !strings.Contains(desc, "注册") {
		t.Fatalf("文案应指向注册同步，实际 %q", desc)
	}

	// 2) 对账：把本地应用注册到对端。
	//
	// 先记下更新时间：同步每 5 分钟跑一次，若它顺手刷新 updated_at，管理端
	// 列表里所有应用的"更新时间"会一直变，运维会以为配置被人改过。
	beforeSync, err := h.db.FindByAppCode(context.Background(), h.appCode)
	if err != nil {
		t.Fatalf("读取应用失败: %v", err)
	}

	rep, err := h.app.AppSync().Reconcile(context.Background())
	if err != nil {
		t.Fatalf("对账失败: %v", err)
	}
	if rep.Succeeded < 1 || rep.Failed != 0 {
		t.Fatalf("对账应至少成功一个应用，实际 %+v", rep)
	}

	// 对端收到的 app_key 必须是本地 app_code——两边用不同的键时，
	// 注册"成功"但登录仍然 400，而且极难看出问题在哪。
	reg, ok := uc.AppRegistration(h.appCode)
	if !ok {
		t.Fatalf("对端未收到应用 %q", h.appCode)
	}
	if reg.Status != mockusercenter.StatusActive {
		t.Fatalf("启用应用应注册为 active，实际 %q", reg.Status)
	}

	// 3) 再登录：应当一次成功。
	_, out, loc := h.loginOnce(t)
	if out != nil {
		t.Fatalf("注册后应 302 回跳，实际 JSON：%v", out)
	}
	if mustQuery(t, loc).Get("code") == "" {
		t.Fatalf("注册后应返回 auth_code（Location=%s）", loc)
	}

	// 4) 本地要留下同步时间：否则管理端会一直显示"未同步"，
	//    运维无法区分"没同步过"和"同步了但后来对端出问题"。
	stored, err := h.db.FindByAppCode(context.Background(), h.appCode)
	if err != nil {
		t.Fatalf("读取应用失败: %v", err)
	}
	if stored.AccountSync.SyncedAt == nil {
		t.Fatal("应记录 uc_synced_at")
	}
	if stored.AccountSync.LastError != "" {
		t.Fatalf("成功时不应留错误，实际 %q", stored.AccountSync.LastError)
	}
	// 同步不得动 updated_at（GORM 的 Updates 会自动写它，必须用 UpdateColumns）。
	if !stored.UpdatedAt.Equal(beforeSync.UpdatedAt) {
		t.Fatalf("同步不应改 updated_at：%s → %s（管理端的\"更新时间\"会每 5 分钟自己变）",
			beforeSync.UpdatedAt, stored.UpdatedAt)
	}
}
