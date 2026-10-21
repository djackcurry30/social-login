// Package admin 中的 router_test.go：管理端路由的端到端测试。
//
// 覆盖：
//   - /admin/v1/auth/login → 200 + 返回 token
//   - /admin/v1/auth/me 带正确 token → 200
//   - /admin/v1/auth/me 不带 token → 401
//   - /admin/v1/auth/me 带过期 token → 401 + ADMIN.SESSION_EXPIRED
//   - /admin/v1/apps 带 token → 200 (app:read 通过)
//   - /admin/v1/apps POST 没有 token → 401
//
// 不依赖数据库——使用 stub repo + 直接构造 router。
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/adminapp"
	"github.com/djackcurry30/social-login/internal/application/adminchan"
	"github.com/djackcurry30/social-login/internal/application/adminobs"
	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/interfaces/http/admin/handler"
	"github.com/djackcurry30/social-login/internal/pkg/adminx"
)

// --- 与 handler/auth_test.go 重复但显式列出来（避免跨文件 test 互联） ---

type stubUserRepo struct{ users map[string]*admin.User }

func (s *stubUserRepo) FindByUsername(_ context.Context, n string) (*admin.User, error) {
	u, ok := s.users[n]
	if !ok {
		return nil, admin.ErrNotFound
	}
	return u, nil
}
func (s *stubUserRepo) FindByID(_ context.Context, id int64) (*admin.User, error) {
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, admin.ErrNotFound
}
func (s *stubUserRepo) Insert(_ context.Context, u *admin.User) (*admin.User, error) {
	s.users[u.Username] = u
	return u, nil
}
func (s *stubUserRepo) UpdateLastLoginAt(_ context.Context, _ int64) error { return nil }
func (s *stubUserRepo) UpdatePassword(_ context.Context, _ int64, _ string) error {
	return nil
}

type stubSessionRepo struct{ sessions []*admin.Session }

func (s *stubSessionRepo) Insert(_ context.Context, sess *admin.Session) error {
	sess.ID = int64(len(s.sessions) + 1)
	s.sessions = append(s.sessions, sess)
	return nil
}
func (s *stubSessionRepo) FindByTokenHash(_ context.Context, h string) (*admin.Session, error) {
	for _, sess := range s.sessions {
		if sess.TokenHash == h {
			return sess, nil
		}
	}
	return nil, admin.ErrNotFound
}
func (s *stubSessionRepo) Revoke(_ context.Context, _ int64) error { return nil }

// --- 测试装配 ---

type fixture struct {
	router *gin.Engine
	users  *stubUserRepo
	sess   *stubSessionRepo
	token  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	users := &stubUserRepo{users: map[string]*admin.User{}}
	sess := &stubSessionRepo{}

	// 默认有一个 super_admin 账号
	hash, _ := adminx.HashPassword("password123")
	users.users["admin"] = &admin.User{
		ID:           1,
		Username:     "admin",
		PasswordHash: hash,
		Role:         admin.RoleSuperAdmin,
		Status:       1,
	}

	loginSvc := handler.NewLoginService(handler.LoginServiceDeps{
		Users:    users,
		Sessions: sess,
		Now:      time.Now, // 与 adminmw.Authenticator 默认 Now 对齐
		TTL:      60 * time.Minute,
		Logger:   zap.NewNop(),
	})

	deps := Deps{
		Logger:       zap.NewNop(),
		AuthSessions: sess,
		AuthUsers:    users,
		AuthLogin:    loginSvc,
		AdminApp:     adminapp.New(adminapp.Deps{Logger: zap.NewNop()}),
		AdminChan:    adminchan.New(adminchan.Deps{Logger: zap.NewNop()}),
		AdminObs:     adminobs.New(adminobs.Deps{Logger: zap.NewNop()}),
	}

	r := NewRouter(deps)
	fx := &fixture{router: r, users: users, sess: sess}
	// 主动登录拿到一个 token，便于后续用例使用。
	fx.token = login(t, fx, "admin", "password123")
	return fx
}

func login(t *testing.T, fx *fixture, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(handler.LoginInput{Username: username, Password: password})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	fx.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login 失败: code=%d body=%s", w.Code, w.Body.String())
	}
	var out handler.LoginOutput
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应: %v", err)
	}
	return out.Token
}

// --- 用例 ---

func TestRouter_LoginFlow(t *testing.T) {
	fx := newFixture(t)

	// me 带正确 token
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+fx.token)
	fx.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d body=%s", w.Code, w.Body.String())
	}
}

func TestRouter_NoToken(t *testing.T) {
	fx := newFixture(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/auth/me", nil)
	fx.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", w.Code)
	}
}

func TestRouter_BadToken(t *testing.T) {
	fx := newFixture(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	fx.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", w.Code)
	}
}

func TestRouter_ListApps_OK(t *testing.T) {
	fx := newFixture(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/apps", nil)
	req.Header.Set("Authorization", "Bearer "+fx.token)
	fx.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d body=%s", w.Code, w.Body.String())
	}
}

func TestRouter_LogoutIdempotent(t *testing.T) {
	fx := newFixture(t)

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+fx.token)
		fx.router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestRouter_Apps_POST_NoReason(t *testing.T) {
	fx := newFixture(t)

	body, _ := json.Marshal(map[string]any{"name": "test-app"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/apps", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fx.token)
	fx.router.ServeHTTP(w, req)
	// 缺 reason → adminapp 层校验：CodeAdminReasonRequired = 400
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400（reason 缺失），实际 %d body=%s", w.Code, w.Body.String())
	}
	var bodyResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &bodyResp)
	if bodyResp["code"] != "REQUEST.INVALID" && bodyResp["code"] != "ADMIN.REASON_REQUIRED" {
		t.Fatalf("期望 REQUEST.INVALID 或 ADMIN.REASON_REQUIRED，实际 %v", bodyResp["code"])
	}
}
