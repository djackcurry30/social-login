package mockusercenter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/testsupport/mockusercenter"
)

// 这一组用例验证"应用注册必须先于登录"这条契约，以及注册本身的幂等性。
//
// 它们同时充当对端的参考实现说明：真实用户中心照这几条语义实现即可。

// TestRegisterAppUnlocksLogin 验证"未注册 → 注册 → 可用"的完整转变。
//
// 这条路径就是 §2.6 的全部意义：应用没同步过去时，该应用的登录会
// 400 APP.UNKNOWN；同步之后立刻可用，中间不需要重启任何一侧。
func TestRegisterAppUnlocksLogin(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{RequireRegisteredApp: true})
	p := newProvider(t, srv)
	ctx := context.Background()

	// 注册前：建号必须失败，且错误要指向"未注册"而不是"用户中心挂了"。
	_, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey: testApp, IdempotencyKey: "k1",
		Claims: []domainaccount.Claim{{Type: "phone", Value: "13800000001", Source: "wechat_phone"}},
	})
	if err == nil {
		t.Fatal("未注册的应用不应能建号")
	}
	if code := errs.CodeOf(err); code != errs.CodeAccountUnavailable {
		t.Fatalf("应为 ACCOUNT.UNAVAILABLE，实际 %v", code)
	}
	if !strings.Contains(err.Error(), "注册") {
		t.Fatalf("错误文案应指向注册同步，实际 %q", err.Error())
	}

	// 注册（走真实 HTTP 适配层，而不是控制面方法）。
	if err := p.RegisterApp(ctx, domainaccount.AppRegistration{
		AppKey: testApp, Name: "测试应用", Status: domainaccount.AppStatusActive,
	}); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	// 注册后：同一个请求应当成功。
	acc, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey: testApp, IdempotencyKey: "k1",
		Claims: []domainaccount.Claim{{Type: "phone", Value: "13800000001", Source: "wechat_phone"}},
	})
	if err != nil {
		t.Fatalf("注册后应能建号: %v", err)
	}
	if acc.UserID == "" {
		t.Fatal("应返回 user_id")
	}
}

// TestRegisterAppIsIdempotentUpsert 验证重复注册只更新、不新建。
//
// 对账任务每 5 分钟重放全部应用。不幂等的实现会造出重复租户，而重复租户
// 在账号侧的表现是"用户被随机分到其中一份，另一半数据永远查不到"。
func TestRegisterAppIsIdempotentUpsert(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	p := newProvider(t, srv)
	ctx := context.Background()

	reg := domainaccount.AppRegistration{
		AppKey: testApp, Name: "第一次", Status: domainaccount.AppStatusActive,
	}
	if err := p.RegisterApp(ctx, reg); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}

	reg.Name = "改过的名字"
	reg.Status = domainaccount.AppStatusDisabled
	if err := p.RegisterApp(ctx, reg); err != nil {
		t.Fatalf("重复注册应成功（幂等）: %v", err)
	}

	if n := srv.RegisteredAppCount(); n != 1 {
		t.Fatalf("重复注册不应新增租户，实际 %d 个", n)
	}
	got, ok := srv.AppRegistration(testApp)
	if !ok {
		t.Fatal("应能查到注册信息")
	}
	if got.Name != "改过的名字" || got.Status != mockusercenter.StatusDisabled {
		t.Fatalf("第二次注册应覆盖名称与状态，实际 %+v", got)
	}

	// 两次调用都要被记录：验证"对账确实每次都发了请求"。
	if calls := srv.CallsOf(mockusercenter.OpRegister); len(calls) != 2 {
		t.Fatalf("应记录两次注册调用，实际 %d", len(calls))
	}
}

// TestRegisterAppRejectsBadPayload 验证对端的入参校验。
//
// 真实对端也应该拒：缺 status 时若默认成 active，一个已停用的应用会被
// 重新启用，而"停用"通常是安全或合规原因。
func TestRegisterAppRejectsBadPayload(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	cases := []struct {
		name string
		body string
	}{
		{"缺 app_key", `{"status":"active"}`},
		{"缺 status", `{"app_key":"app_x"}`},
		{"status 非法", `{"app_key":"app_x","status":"enabled"}`},
		{"报文不是 JSON", `not-json`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/internal/v1/apps", "application/json",
				strings.NewReader(c.body))
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("应返回 400，实际 %d", resp.StatusCode)
			}
		})
	}
	if n := srv.RegisteredAppCount(); n != 0 {
		t.Fatalf("非法请求不应注册出应用，实际 %d 个", n)
	}
}

// TestRegisterAppRejectsGET 验证方法校验。
//
// 405 且不带错误码：与"资源不存在"区分开，也让适配层知道不是能力缺失。
func TestRegisterAppRejectsGET(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/internal/v1/apps")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("应返回 405，实际 %d", resp.StatusCode)
	}
}

// TestRegisteredAppDisabledStillServed 明确记录一个【有意为之】的边界。
//
// §12.3 还没定"停用应用后用户中心是否也拒绝"。在契约确定前，假对端按
// "了解状态但不据此拦截"行事：停用的应用仍然可以建号/查号。
//
// 把它写成用例而不是留空，是为了让这个决定显式可见——将来真要做拦截时，
// 这条用例会红，红的地方就是需要改的地方。
func TestRegisteredAppDisabledStillServed(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{RequireRegisteredApp: true})
	p := newProvider(t, srv)
	ctx := context.Background()

	if err := p.RegisterApp(ctx, domainaccount.AppRegistration{
		AppKey: testApp, Status: domainaccount.AppStatusDisabled,
	}); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	// 仍然可以建号：本服务侧会先按 applications.status 拒绝，对端不重复拦。
	if _, err := p.Create(ctx, domainaccount.CreateRequest{
		AppKey: testApp, IdempotencyKey: "k-disabled",
	}); err != nil {
		t.Fatalf("当前契约下停用应用仍可建号（拦截在本服务侧）: %v", err)
	}
}

// TestRegisterAppFaultIsRetryable 验证注册失败时的降级。
//
// 注册失败 = 该应用的最新状态没同步过去。对账必须能重试，所以错误要可重试；
// 而失败时绝不能留下半截租户（否则下一轮会认为自己"已经同步过"）。
func TestRegisterAppFaultIsRetryable(t *testing.T) {
	srv := mockusercenter.New(mockusercenter.Config{})
	p := newProvider(t, srv)
	srv.InjectFault(mockusercenter.OpRegister, mockusercenter.FaultServerError, 0)

	err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		AppKey: testApp, Status: domainaccount.AppStatusActive,
	})
	if code := errs.CodeOf(err); code != errs.CodeAccountUnavailable {
		t.Fatalf("对端 5xx 应译成 ACCOUNT.UNAVAILABLE，实际 %v", code)
	}
	if e, ok := errs.As(err); !ok || !e.Retryable {
		t.Fatal("对端 5xx 必须可重试，否则对账永远不会自愈")
	}
	if _, ok := srv.AppRegistration(testApp); ok {
		t.Fatal("失败时不应留下租户记录")
	}
}
