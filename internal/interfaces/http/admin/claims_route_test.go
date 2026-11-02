// Package admin 中的 claims_route_test.go：J 组路由注册的守卫测试。
//
// 只验证"路由在不在、方法对不对"，不发起请求——真正的读写行为在
// adminidentity 的单测与 scripts/acceptance-claims.sh 里覆盖。
//
// 这条测试的价值在于挡住一类很容易漏的问题：新加的 handler 写好了、
// 用例也测了，但 mount.go 里忘了注册（或者路径拼错成 /claim）。
// 那种情况下所有单测都是绿的，线上却是 404。
package admin

import (
	"net/http"
	"testing"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminidentity"
)

func TestRouter_ClaimRoutesRegistered(t *testing.T) {
	// 只装 J 组依赖：其余组不注册，路由表更干净。
	// nil 的 authn 依赖不会在注册阶段被调用。
	r := NewRouter(Deps{
		Logger:        zap.NewNop(),
		AdminIdentity: adminidentity.New(adminidentity.Deps{}),
	})

	want := map[string]bool{
		http.MethodGet + " /admin/v1/claims":             false,
		http.MethodGet + " /admin/v1/claims/mismatches":  false,
		http.MethodPost + " /admin/v1/claims/:id/revoke": false,
	}
	for _, rt := range r.Routes() {
		key := rt.Method + " " + rt.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Fatalf("J 组路由未注册: %s", k)
		}
	}
}
