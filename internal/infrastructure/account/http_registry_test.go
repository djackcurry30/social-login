package account

import (
	"context"
	"net/http"
	"testing"
	"time"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// TestRegisterAppSendsContract 验证注册报文的形状。
//
// 断言的是"对端会收到什么"，而不是"我方内部状态"——这个端点是跨服务契约，
// 唯一有意义的事实就是线上字节。
func TestRegisterAppSendsContract(t *testing.T) {
	c := newFakeCenter(t)
	c.reply = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"app_key": testAppKey})
	}
	p := c.provider(t, time.Second)

	err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		AppKey:         testAppKey,
		Name:           "门户",
		Status:         domainaccount.AppStatusActive,
		LocalUpdatedAt: time.Unix(1_700_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("注册应成功: %v", err)
	}

	// 注册端点【不在】应用前缀下：它本身就是"声明一个应用存在"。
	if c.lastPath != registryPath {
		t.Fatalf("路径应为 %q，实际 %q", registryPath, c.lastPath)
	}
	if got := c.lastBody["app_key"]; got != testAppKey {
		t.Fatalf("app_key 不符：%v", got)
	}
	if got := c.lastBody["status"]; got != string(domainaccount.AppStatusActive) {
		t.Fatalf("status 应为 active，实际 %v", got)
	}
	if got := c.lastBody["name"]; got != "门户" {
		t.Fatalf("name 不符：%v", got)
	}
	if _, ok := c.lastBody["updated_at"]; !ok {
		t.Fatal("应带上 updated_at（供对端判断谁更新）")
	}
}

// TestRegisterAppDisabledStatus 验证停用状态会如实传给对端。
//
// 只改本地而不告知对端时，对端会继续认为该应用可用，"本地停了、对端能用"
// 会同时成立。
func TestRegisterAppDisabledStatus(t *testing.T) {
	c := newFakeCenter(t)
	c.reply = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	p := c.provider(t, time.Second)

	if err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		AppKey: testAppKey, Status: domainaccount.AppStatusDisabled,
	}); err != nil {
		t.Fatalf("204 也应视为成功: %v", err)
	}
	if got := c.lastBody["status"]; got != string(domainaccount.AppStatusDisabled) {
		t.Fatalf("status 应为 disabled，实际 %v", got)
	}
}

// TestRegisterAppRejectsEmptyAppKeyLocally 验证空 app_key 在本地被拦。
//
// 空 app_key 打到对端会在它的租户表里造出一条空记录，或按别的语义路由；
// 这是装配问题，应该在这里就暴露，且不该产生一次网络调用。
func TestRegisterAppRejectsEmptyAppKeyLocally(t *testing.T) {
	c := newFakeCenter(t)
	p := c.provider(t, time.Second)

	err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		Status: domainaccount.AppStatusActive,
	})
	if code := errs.CodeOf(err); code != errs.CodeInternal {
		t.Fatalf("应为 INTERNAL（装配问题），实际 %v", code)
	}
	if c.lastPath != "" {
		t.Fatal("空 app_key 不应发出请求")
	}
}

// TestRegisterAppRejectsEmptyStatusLocally 验证缺状态时不发请求。
//
// 不默认成 active：默认启用会让一个已停用的应用在对端被重新启用，
// 而"停用"通常是安全或合规原因。
func TestRegisterAppRejectsEmptyStatusLocally(t *testing.T) {
	c := newFakeCenter(t)
	p := c.provider(t, time.Second)

	if err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		AppKey: testAppKey,
	}); err == nil {
		t.Fatal("缺状态应报错")
	}
	if c.lastPath != "" {
		t.Fatal("缺状态不应发出请求")
	}
}

// TestRegisterApp5xxIsRetryable 验证上游故障被译成可重试。
//
// 可重试这个标记决定了对账下一轮是否值得再试；译成不可重试等于把一次
// 对端抖动变成"这个应用永久不可用"。
func TestRegisterApp5xxIsRetryable(t *testing.T) {
	c := newFakeCenter(t)
	c.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}
	p := c.provider(t, time.Second)

	err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		AppKey: testAppKey, Status: domainaccount.AppStatusActive,
	})
	if code := errs.CodeOf(err); code != errs.CodeAccountUnavailable {
		t.Fatalf("5xx 应译成 ACCOUNT.UNAVAILABLE，实际 %v", code)
	}
	if e, ok := errs.As(err); !ok || !e.Retryable {
		t.Fatal("5xx 必须可重试，否则对账不会重试")
	}
}

// TestRegisterApp400IsNotRetryable 验证报文错误不被当成抖动。
//
// 400 说明我方发的东西对端不认识（例如 status 取值不在枚举里），
// 重试一百次也一样；把它标成可重试只会让对账日志永远有一条红。
func TestRegisterApp400IsNotRetryable(t *testing.T) {
	c := newFakeCenter(t)
	c.reply = func(w http.ResponseWriter, _ *http.Request) {
		writeEnvelope(w, http.StatusBadRequest, "INVALID.REQUEST", "status must be active|disabled")
	}
	p := c.provider(t, time.Second)

	err := p.RegisterApp(context.Background(), domainaccount.AppRegistration{
		AppKey: testAppKey, Status: domainaccount.AppStatusActive,
	})
	if err == nil {
		t.Fatal("400 应报错")
	}
	if e, ok := errs.As(err); ok && e.Retryable {
		t.Fatal("400 不应可重试")
	}
}

// TestRegisterAppReplaysEveryTime 验证不会本地"记住已同步"而跳过调用。
//
// 全量重放是对端数据漂移（被回滚 / 被清理）的唯一自愈手段。如果本地做了
// "同步过就不再发"的优化，这类漂移就永远修不回来，而现象是"管理端显示
// 已同步，登录却 400 APP.UNKNOWN"。
func TestRegisterAppReplaysEveryTime(t *testing.T) {
	c := newFakeCenter(t)
	calls := 0
	c.reply = func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}
	p := c.provider(t, time.Second)

	reg := domainaccount.AppRegistration{AppKey: testAppKey, Status: domainaccount.AppStatusActive}
	for i := 0; i < 3; i++ {
		if err := p.RegisterApp(context.Background(), reg); err != nil {
			t.Fatalf("第 %d 次注册失败: %v", i+1, err)
		}
	}
	if calls != 3 {
		t.Fatalf("每次都应真的调用对端，实际 %d 次", calls)
	}
}
