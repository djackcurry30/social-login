package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
)

// TestScopeAppIDs 守住"不受限"与"受限但范围为空"的区别。
//
// 这两种情况在 Go 里都可能表现为空切片，但语义完全相反：
// 前者是"看全部"，后者是"一个都不许看"。混为一谈的结果是不报错的越权。
func TestScopeAppIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		set        bool
		ids        []int64
		restricted bool
		wantNil    bool
		wantLen    int
	}{
		{name: "无中间件上下文 → 视为不受限", set: false, wantNil: true},
		{name: "全局管理员", set: true, ids: nil, restricted: false, wantNil: true},
		{name: "受限：两个应用", set: true, ids: []int64{3, 7}, restricted: true, wantLen: 2},
		{name: "受限：范围为空 → 空切片而非 nil", set: true, ids: nil, restricted: true, wantNil: false, wantLen: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/admin/v1/identities", nil)
			if tc.set {
				c.Set(adminmw.CtxKeyScopeAppIDs, tc.ids)
				c.Set(adminmw.CtxKeyScopeRestricted, tc.restricted)
			}
			got := scopeAppIDs(c)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("应为 nil，实际 %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("受限管理员不能返回 nil：下游会当成\"不过滤\"")
			}
			if len(got) != tc.wantLen {
				t.Fatalf("范围长度应为 %d，实际 %v", tc.wantLen, got)
			}
		})
	}
}
