// 本文件是"真实用户中心"的联调验收。
//
// 与 account_http_test.go 的分工：
//
//	那边用 internal/testsupport/mockusercenter 验"我方适配层 + 编排"，
//	它快、可注入故障、能断言对端收到了什么，但它证明不了对端自身的行为。
//
//	这里把 account.provider 指向【真实用户中心】，验的是最后一段：
//	一次真实登录能不能建出真实账号，建出来的 user_id 会不会真的被用于写绑定。
//	这是 §10 P0 判据第 2 条。
//
// 未设置 TEST_USER_CENTER_URL 时跳过——它需要一个已部署、已注册应用的
// 用户中心，不是 `go test ./...` 的默认依赖。
//
// 跑法：
//
//	TEST_USER_CENTER_URL=http://127.0.0.1:8099 \
//	TEST_USER_CENTER_TOKEN=dev-usercenter-token \
//	TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:15432/social_login?sslmode=disable' \
//	TEST_REDIS_ADDR=127.0.0.1:16379 \
//	go test ./test/acceptance/ -run TestRealUserCenter -v
package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/bootstrap"
	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	infraaccount "github.com/djackcurry30/social-login/internal/infrastructure/account"
)

// realUserCenter 读取真实用户中心的连接信息，未配置时跳过。
func realUserCenter(t *testing.T) (base, token string) {
	t.Helper()
	base = os.Getenv("TEST_USER_CENTER_URL")
	if base == "" {
		t.Skip("未设置 TEST_USER_CENTER_URL，跳过真实用户中心联调")
	}
	return base, os.Getenv("TEST_USER_CENTER_TOKEN")
}

// newRealUserCenterHarness 让 social-login 指向真实用户中心。
func newRealUserCenterHarness(t *testing.T, base, token string) *harness {
	t.Helper()
	return newHarnessOpts(t, harnessOptions{
		Config: func(c *bootstrap.Config) {
			c.Account.Provider = "http"
			c.Account.HTTP.BaseURL = base
			c.Account.HTTP.Token = token
			c.Account.HTTP.Timeout = 3 * time.Second
			// 注册同步保持开启：生产就是这么跑的，关掉等于测一个不存在的形态。
			c.Account.Sync.Enabled = true
		},
		Policy: func(p *tenant.Policy) {
			p.OnUnboundLogin = tenant.OnUnboundAutoCreate
		},
	})
}

// registerAppInUC 在用户中心注册应用（等价于管理端建应用后的同步调用）。
//
// 测试里直接调内部接口，是因为 harness 用仓储直接写库、绕过了管理端的
// 建应用流程；而"应用必须已注册"是登录的硬前提（§2.6）。
func registerAppInUC(t *testing.T, base, token, appKey string) {
	t.Helper()

	body, _ := json.Marshal(map[string]string{
		"app_key": appKey, "name": "acceptance", "status": "active",
	})
	req, err := http.NewRequest(http.MethodPost, base+"/internal/v1/apps", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("构造注册请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("注册应用到用户中心失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("注册应用返回 %d（应为 200）", resp.StatusCode)
	}
}

// TestRealUserCenterLogin 是"接上真实用户中心"的主验收。
//
// 断言链是完整的：登录 302 → 本地写了绑定 → 绑定里的 user_id 在用户中心
// 真的能查到且是 active。只断言"登录成功"是不够的：stub 模式也能成功，
// 区别正是"账号到底落在哪里"。
func TestRealUserCenterLogin(t *testing.T) {
	base, token := realUserCenter(t)

	h := newRealUserCenterHarness(t, base, token)
	registerAppInUC(t, base, token, h.appCode)

	cb, out, loc := h.loginOnce(t)
	if cb.StatusCode != http.StatusFound {
		t.Fatalf("首次登录应 302 回跳，实际 %d：%v", cb.StatusCode, out)
	}
	q := mustQuery(t, loc)
	if errCode := q.Get("error"); errCode != "" {
		t.Fatalf("登录失败: %s（%s）", errCode, q.Get("error_description"))
	}

	// 绑定里记的必须是用户中心返回的 user_id。
	//
	// 不按 bind_source 过滤：来源取值（login / auto_create / explicit）是
	// social-login 的内部枚举，会随流程调整；这里要验的是"绑定指向 UC 的 id"，
	// 绑死一个来源值只会让用例在无关改动时变红。
	var userID string
	err := h.app.DB().Raw(
		`SELECT external_user_id FROM oauth_bindings
		  WHERE app_id = ? AND status = 'active'
		  ORDER BY id DESC LIMIT 1`, h.appID).Scan(&userID).Error
	if err != nil {
		t.Fatalf("查询绑定失败: %v", err)
	}
	if userID == "" {
		t.Fatal("登录成功但没有写绑定：账号可能只存在于用户中心，业务方拿不到 user_id")
	}

	// 再用适配层按 id 回查用户中心，确认这个 id 真实存在。
	p, err := infraaccount.NewHTTPProvider(infraaccount.HTTPConfig{
		BaseURL: base, Token: token, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造用户中心客户端失败: %v", err)
	}
	acc, err := p.Get(context.Background(), h.appCode, userID)
	if err != nil {
		t.Fatalf("在用户中心查不到绑定里的 user_id %s: %v", userID, err)
	}
	if acc.Status != domainaccount.StatusActive {
		t.Fatalf("新账号状态应为 active，实际 %s", acc.Status)
	}
}

// TestRealUserCenterUnregisteredAppBlocksLogin 应用未在用户中心注册时，
// 登录必须失败而不是"静默建到别的地方"。
//
// 这条比"能登录"更值得验：注册同步失败是运维最可能遇到的状态
// （建应用时用户中心正好不可用），而它的表现如果只是"用户数据看起来丢了"，
// 排查会从账号一路查到网络。
func TestRealUserCenterUnregisteredAppBlocksLogin(t *testing.T) {
	base, token := realUserCenter(t)

	// 故意不注册 h.appCode。
	h := newRealUserCenterHarness(t, base, token)

	cb, out, loc := h.loginOnce(t)
	if cb.StatusCode == http.StatusFound {
		if q := mustQuery(t, loc); q.Get("error") == "" {
			t.Fatal("应用未在用户中心注册，登录却成功了")
		}
		return
	}
	// 失败也可能直接以 5xx JSON 返回（取决于失败发生在哪个阶段）。
	if out["error"] == nil && out["code"] == nil {
		t.Fatalf("未注册应用的登录失败形态不可识别: status=%d body=%v", cb.StatusCode, out)
	}
}
