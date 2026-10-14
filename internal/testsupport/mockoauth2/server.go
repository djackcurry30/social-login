// Package mockoauth2 是一个最小可用的 OAuth2 提供方实现。
//
// 它同时服务两个目的：
//
//  1. 作为第一期验收的载体——架构 §13 的验收标准是"接入一个自建 OAuth2 测试服务，
//     走通完整登录链路"。用第三方平台做验收会让测试依赖外网与真实凭据，
//     既慢又不可重复。
//  2. 作为通用 OAuth2 适配器的"抽象是否泄漏"检验：只有当适配器完全靠配置
//     接进来，才说明 Provider SPI 没有偷偷假设某个平台的行为。
//
// ⚠️ 它没有任何安全设计（不做 PKCE 校验、不做 state 校验、令牌是明文 UUID）。
// 【仅限测试与本地联调】，绝不可用于任何生产场景。
package mockoauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/alex/social-login/internal/pkg/ids"
)

// Profile 是 mock 用户的信息。
type Profile struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone_number"`
	Picture string `json:"picture"`
}

// Config 是 mock 服务配置。
type Config struct {
	// ClientID / ClientSecret 是它认可的客户端凭据。
	ClientID     string
	ClientSecret string
	// DefaultProfile 是未通过 login_hint 指定用户时返回的资料。
	DefaultProfile Profile
}

// Server 是一个内存态 OAuth2 提供方。
type Server struct {
	cfg Config

	mu        sync.Mutex
	codes     map[string]Profile
	tokens    map[string]Profile
	refreshes map[string]Profile
	// IssuedCodes 记录已发放的授权码，供测试断言"重放会被拒绝"。
	IssuedCodes []string
}

// New 构造 mock 服务。
func New(cfg Config) *Server {
	if cfg.ClientID == "" {
		cfg.ClientID = "mock-client"
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = "mock-secret"
	}
	if cfg.DefaultProfile.Subject == "" {
		cfg.DefaultProfile = Profile{
			Subject: "mock-user-1",
			Name:    "Mock User",
			Email:   "mock@example.com",
			Picture: "https://example.com/avatar.png",
		}
	}
	return &Server{
		cfg:       cfg,
		codes:     make(map[string]Profile),
		tokens:    make(map[string]Profile),
		refreshes: make(map[string]Profile),
	}
}

// Handler 返回 HTTP 路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/oauth/userinfo", s.handleUserInfo)
	return mux
}

// handleAuthorize 直接完成"用户点了同意"的动作并回跳，不做任何交互。
//
// 支持两个非标准参数，方便测试构造场景：
//
//	login_hint  —— 指定本次授权对应的用户标识（等价于"换个账号登录"）
//	mock_phone  —— 指定平台返回的手机号（用于验证手机号归并链路）
//	mock_email  —— 同上，邮箱
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != s.cfg.ClientID {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	state := q.Get("state")

	profile := s.cfg.DefaultProfile
	if hint := q.Get("login_hint"); hint != "" {
		profile.Subject = hint
		profile.Name = "用户 " + hint
	}
	if p := q.Get("mock_phone"); p != "" {
		profile.Phone = p
	}
	if e := q.Get("mock_email"); e != "" {
		profile.Email = e
	}

	code := ids.New("mcode")
	s.mu.Lock()
	s.codes[code] = profile
	s.IssuedCodes = append(s.IssuedCodes, code)
	s.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	out := target.Query()
	out.Set("code", code)
	if state != "" {
		out.Set("state", state)
	}
	target.RawQuery = out.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// handleToken 实现 authorization_code 与 refresh_token 两种授权类型。
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	clientID, clientSecret := s.clientCredentials(r)
	if clientID != s.cfg.ClientID || clientSecret != s.cfg.ClientSecret {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "客户端凭据错误")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		s.mu.Lock()
		profile, ok := s.codes[code]
		if ok {
			// 一次性：用过即删，重放会得到 invalid_grant——
			// 这正是本服务"对三方调用不做重试"（约束 C6）要防的场景。
			delete(s.codes, code)
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "授权码无效或已被使用")
			return
		}
		s.issue(w, profile)

	case "refresh_token":
		refresh := r.PostForm.Get("refresh_token")
		s.mu.Lock()
		profile, ok := s.refreshes[refresh]
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "refresh_token 无效")
			return
		}
		s.issue(w, profile)

	default:
		writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "不支持的授权类型")
	}
}

func (s *Server) issue(w http.ResponseWriter, profile Profile) {
	access := ids.New("mat")
	refresh := ids.New("mrt")
	s.mu.Lock()
	s.tokens[access] = profile
	s.refreshes[refresh] = profile
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int((2 * time.Hour).Seconds()),
		RefreshToken: refresh,
		Scope:        "openid profile",
	})
}

// handleUserInfo 返回用户资料。
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	s.mu.Lock()
	profile, ok := s.tokens[token]
	s.mu.Unlock()
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid_token", "access_token 无效")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(profile)
}

// SetSubject 修改默认用户，便于串行构造多个身份的场景。
func (s *Server) SetSubject(subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.DefaultProfile.Subject = subject
}

func (s *Server) clientCredentials(r *http.Request) (string, string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) {
		return h[len(prefix):]
	}
	return ""
}

func writeJSONError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
