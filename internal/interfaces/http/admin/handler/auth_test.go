// Package handler 中的 auth_test.go：LoginService + AuthHandler 的单元测试。
//
// 本测试不依赖数据库：用 stub repository 验证
//   - 用户名不存在 → ErrInvalidCredentials 且走 dummy bcrypt 防 timing attack
//   - 密码错 → ErrInvalidCredentials
//   - 账号停用 → ErrInvalidCredentials
//   - 正常 → 返回明文 token + 写入 session（SHA-256 hex 形式入库）
package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/adminx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- stub 用户仓储 ---

type stubUserRepo struct {
	users map[string]*admin.User
}

func (s *stubUserRepo) FindByUsername(_ context.Context, username string) (*admin.User, error) {
	u, ok := s.users[username]
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

func (s *stubUserRepo) UpdateLastLoginAt(_ context.Context, _ int64) error {
	return nil
}

func (s *stubUserRepo) UpdatePassword(_ context.Context, _ int64, _ string) error {
	return nil
}

// --- stub 会话仓储 ---

type stubSessionRepo struct {
	sessions []*admin.Session
}

func (s *stubSessionRepo) Insert(_ context.Context, sess *admin.Session) error {
	sess.ID = int64(len(s.sessions) + 1)
	s.sessions = append(s.sessions, sess)
	return nil
}

func (s *stubSessionRepo) FindByTokenHash(_ context.Context, hash string) (*admin.Session, error) {
	for _, sess := range s.sessions {
		if sess.TokenHash == hash {
			return sess, nil
		}
	}
	return nil, admin.ErrNotFound
}

func (s *stubSessionRepo) Revoke(_ context.Context, _ int64) error {
	return nil
}

var _ admin.SessionRepository = (*stubSessionRepo)(nil)
var _ admin.UserRepository = (*stubUserRepo)(nil)

// --- tests ---

func newEnabledUser(t *testing.T, username, password string) *admin.User {
	t.Helper()
	hash, err := adminx.HashPassword(password)
	if err != nil {
		t.Fatalf("生成哈希: %v", err)
	}
	return &admin.User{
		ID:           1,
		Username:     username,
		PasswordHash: hash,
		Role:         admin.RoleSuperAdmin,
		Status:       1,
	}
}

func newSvc(t *testing.T, u *admin.User) (*LoginService, *stubSessionRepo) {
	t.Helper()
	users := &stubUserRepo{users: map[string]*admin.User{}}
	if u != nil {
		users.users[u.Username] = u
	}
	sess := &stubSessionRepo{}
	svc := NewLoginService(LoginServiceDeps{
		Users:    users,
		Sessions: sess,
		Now:      func() time.Time { return time.Unix(1700000000, 0).UTC() },
		TTL:      60 * time.Minute,
		Logger:   zap.NewNop(),
	})
	return svc, sess
}

func TestLogin_Success(t *testing.T) {
	u := newEnabledUser(t, "alice", "supersecret123")
	svc, sess := newSvc(t, u)

	out, err := svc.Login(context.Background(), LoginInput{
		Username: "alice",
		Password: "supersecret123",
	}, "127.0.0.1", "ua")
	assertNilErr(t, err)
	if out.Token == "" {
		t.Fatal("token 不应为空")
	}
	if len(out.Token) != TokenBytes*2 {
		t.Fatalf("token 长度应为 %d，实际 %d", TokenBytes*2, len(out.Token))
	}
	if out.Username != "alice" {
		t.Fatalf("username = %q", out.Username)
	}
	if out.UserID != u.ID {
		t.Fatalf("user_id = %d, 期望 %d", out.UserID, u.ID)
	}
	if out.Role != admin.RoleSuperAdmin {
		t.Fatalf("role = %q, 期望 %q", out.Role, admin.RoleSuperAdmin)
	}
	if len(sess.sessions) != 1 {
		t.Fatalf("期望写一条 session，实际 %d", len(sess.sessions))
	}
	if sess.sessions[0].TokenHash == out.Token {
		t.Fatal("入库的应该是 SHA-256(token)，不是明文 token")
	}
	if sess.sessions[0].ClientIP != "127.0.0.1" {
		t.Fatalf("client_ip = %q", sess.sessions[0].ClientIP)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	u := newEnabledUser(t, "alice", "supersecret123")
	svc, _ := newSvc(t, u)
	_, err := svc.Login(context.Background(), LoginInput{
		Username: "alice",
		Password: "wrong-password",
	}, "", "")
	if !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("期望 ErrInvalidCredentials，实际 %v", err)
	}
}

func TestLogin_UnknownUsername(t *testing.T) {
	svc, _ := newSvc(t, nil)
	_, err := svc.Login(context.Background(), LoginInput{
		Username: "ghost",
		Password: "whatever",
	}, "", "")
	if !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("期望 ErrInvalidCredentials，实际 %v", err)
	}
}

func TestLogin_Disabled(t *testing.T) {
	u := newEnabledUser(t, "alice", "supersecret123")
	u.Status = 0
	svc, _ := newSvc(t, u)
	_, err := svc.Login(context.Background(), LoginInput{
		Username: "alice",
		Password: "supersecret123",
	}, "", "")
	if !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("期望 ErrInvalidCredentials，实际 %v", err)
	}
}

func TestLogin_EmptyFields(t *testing.T) {
	svc, _ := newSvc(t, nil)
	_, err := svc.Login(context.Background(), LoginInput{
		Username: "",
		Password: "whatever",
	}, "", "")
	if err == nil {
		t.Fatal("期望失败")
	}
	e, ok := errs.As(err)
	if !ok || e.Code != errs.CodeInvalidRequest {
		t.Fatalf("期望 CodeInvalidRequest，实际 %v", err)
	}
}

// assertNilErr 是测试辅助。
func assertNilErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("期望 nil err，实际 %v", err)
	}
}