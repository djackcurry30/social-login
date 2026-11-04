package adminmw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/domain/admin"
)

// 这组用例覆盖 Require 的三档判定：有没有权限 → 该权限是否带应用范围 →
// 请求里指明的应用是否在范围内。三处任一写错，结果要么是越权（看不见的
// 数据泄漏），要么是所有受限管理员全部 403（功能不可用）。

func principalWith(u *admin.User) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(CtxKeyPrincipal, &admin.Principal{User: u})
		c.Next()
	}
}

func scopeRouter(u *admin.User) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(principalWith(u))

	// 与生产路由形状一致：appId 在路径里 / app_id 在查询里 / 都没有。
	//
	// 故意用 binding:write 做受限示例：基础角色 viewer 没有这项权限，
	// 只能来自单应用 grant——这正是 ScopeFor 判定"受限"的场景。
	// （app:read 来自基础角色，永远是全局的，拿它测范围会测不出东西。）
	r.GET("/admin/v1/apps", Require("app:read"), ok)
	r.GET("/admin/v1/apps/:appId", Require("app:read"), ok)
	r.GET("/admin/v1/bindings", Require("binding:write"), ok)
	r.GET("/admin/v1/global-overview", Require("binding:write"), ok)
	r.DELETE("/admin/v1/bindings/:id", Require("binding:write"), ok)
	return r
}

func ok(c *gin.Context) { c.String(http.StatusOK, "ok") }

func hit(r *gin.Engine, method, target string) int {
	req := httptest.NewRequest(method, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func scopedOperator(id int64) *admin.User {
	app := id
	return &admin.User{
		ID: 1, Role: admin.RoleViewer, Status: 1,
		Grants: []admin.Grant{{Role: admin.RoleOperator, ScopeAppID: &app}},
	}
}

func TestRequireGlobalAdminUnrestricted(t *testing.T) {
	r := scopeRouter(&admin.User{ID: 1, Role: admin.RoleSuperAdmin, Status: 1})
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/admin/v1/apps/999"},
		{http.MethodGet, "/admin/v1/bindings?app_id=999"},
		{http.MethodGet, "/admin/v1/global-overview"},
		{http.MethodDelete, "/admin/v1/bindings/5"},
	} {
		if code := hit(r, tc.method, tc.target); code != http.StatusOK {
			t.Errorf("%s %s 期望 200，实际 %d", tc.method, tc.target, code)
		}
	}
}

func TestRequireScopedPathParamEnforced(t *testing.T) {
	// 受限的是 binding:write；app:read 仍来自基础角色，所以对任何应用都放行。
	// 这条同时验证"同一个人的不同权限有不同范围"这件事真的成立。
	r := scopeRouter(scopedOperator(7))
	if code := hit(r, http.MethodGet, "/admin/v1/apps/8"); code != http.StatusOK {
		t.Fatalf("基础角色的 app:read 应全局放行，实际 %d", code)
	}
}

func TestRequireScopedQueryEnforced(t *testing.T) {
	r := scopeRouter(scopedOperator(7))
	if code := hit(r, http.MethodGet, "/admin/v1/bindings?app_id=7"); code != http.StatusOK {
		t.Fatalf("范围内应放行，实际 %d", code)
	}
	if code := hit(r, http.MethodGet, "/admin/v1/bindings?app_id=8"); code != http.StatusNotFound {
		t.Fatalf("越界应 404（不泄露应用是否存在），实际 %d", code)
	}
	if code := hit(r, http.MethodGet, "/admin/v1/bindings"); code != http.StatusForbidden {
		t.Fatalf("受限管理员不指定 app_id 应 403，实际 %d", code)
	}
}

func TestRequireScopedDeniesGlobalViews(t *testing.T) {
	// 全局聚合视图（看板）对受限管理员关闭：它天然跨应用，无法过滤一部分。
	r := scopeRouter(scopedOperator(7))
	if code := hit(r, http.MethodGet, "/admin/v1/global-overview"); code != http.StatusForbidden {
		t.Fatalf("全局看板应拒绝受限管理员，实际 %d", code)
	}
	// 应用列表是白名单：handler 内部按范围过滤。
	if code := hit(r, http.MethodGet, "/admin/v1/apps"); code != http.StatusOK {
		t.Fatalf("应用列表应放行（由 handler 过滤），实际 %d", code)
	}
}

func TestRequireScopedIdAddressedRoute(t *testing.T) {
	// /bindings/:id 没有应用上下文：受限管理员即使声明了范围内 app_id，
	// 也不能凭 id 操作——服务层会再用 RestrictApp 收窄（见 adminidentity）。
	// 中间件这一层的职责只是"没有应用上下文就拒绝"。
	r := scopeRouter(scopedOperator(7))
	if code := hit(r, http.MethodDelete, "/admin/v1/bindings/5"); code != http.StatusForbidden {
		t.Fatalf("无应用上下文应 403，实际 %d", code)
	}
}

func TestRequireMissingPermissionStillForbidden(t *testing.T) {
	// 权限不足必须在范围判定之前就拒绝：否则"受限"会被误当成"没权限"的
	// 替代解释，排障时会往错的方向查。
	r := scopeRouter(&admin.User{ID: 1, Role: admin.RoleViewer, Status: 1})
	if code := hit(r, http.MethodDelete, "/admin/v1/bindings/5?app_id=7"); code != http.StatusForbidden {
		t.Fatalf("缺少 binding:write 应 403，实际 %d", code)
	}
}
