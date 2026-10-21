// Package handler 是管理端（/admin/v1/*）的 HTTP handler 集合。
//
// 职责严格按架构 §3 与 §15.6 限定：
//   - 只做协议转换、参数绑定、错误包装
//   - 业务规则一律在 application 层（adminapp / adminchan / adminobs）
//   - 鉴权与 RBAC 一律交给 adminmw 中间件，本包不再做 role 判断
//
// 与业务端 handler 的关键差异：
//   - 主体不是 app+user，而是 admin.Principal（由 adminmw 写入上下文）
//   - 所有高危操作走 adminapp / adminchan 的 Reason 字段强制校验
//   - 错误码 ADMIN.* 与业务端 RESP.* 互不重叠，便于双端日志分流
package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/adminx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// 公共参数
const (
	// TokenBytes 是签发的会话 token 长度（字节），编码后 64 字符 hex。
	//
	// 选 32 字节的理由：与 OAuth2 access_token 同档（一般 32~64 字节），
	// 熵 256 bit 足够防猜测；admin.SessionToken 用 SHA-256(token) 入库，
	// 库里的 token_hash 也是 64 hex 字符串，对齐后便于跨服务验证（未来 SSO）。
	TokenBytes = 32

	// DefaultSessionTTL 是登录会话的有效期。
	//
	// 12 小时是 §15.3 默认值——管理端用户是运维/客服，频次低但每次操作耗时长，
	// 太短（1h）会让客服每天重新登录；太长（7d）又增加凭据泄露的暴露面。
	DefaultSessionTTL = 12 * time.Hour
)

// dummyBcryptHash 是 timing-attack 防御用的固定 bcrypt 哈希。
//
// 必须满足：① 长度合法（60 字符）、② cost 合法能被 CompareHashAndPassword 接受。
// 这里用一次 bcrypt 预生成，cost=12 ⇒ 单次 ~250ms，与正常登录路径对齐。
//
// 为什么不用 hash 库的 zero value：bcrypt.CompareHashAndPassword 对 zero value 会直接
// 报"无效哈希长度"，调用很快，会泄露"账户不存在"的快速路径。
var dummyBcryptHash = mustGenerateDummyHash()

func mustGenerateDummyHash() string {
	// 这里只能 inline：不能在 init 之外再依赖导入。
	// 用一个固定明文（永远不会被匹配）的 bcrypt 哈希。
	const placeholderPlain = "timing-attack-defense-do-not-use"
	h, err := adminx.HashPassword(placeholderPlain)
	if err != nil {
		// HashPassword 失败基本只可能是密码长度不对——我们写死了 38 字符，不会出现。
		panic("admin handler: 初始化 dummy bcrypt hash 失败: " + err.Error())
	}
	return h
}

// --- LoginService：登录/会话生命周期 ---

// LoginServiceDeps 是 LoginService 的依赖。
type LoginServiceDeps struct {
	Users    admin.UserRepository
	Sessions admin.SessionRepository
	// Now 可注入；nil 时用 time.Now().UTC()。
	Now func() time.Time
	// TTL 可注入；0 时用 DefaultSessionTTL。
	TTL time.Duration
	// Logger 用于失败审计与可观测。
	Logger *zap.Logger
}

// LoginService 是登录用例服务的入口。
//
// 设计要点：
//   - 用 adminx.VerifyPassword 做密码校验，bcrypt(cost=12) 已是业内推荐
//   - 生成 32 字节随机 token，存 SHA-256(token) 到 admin_sessions.token_hash
//   - 明文 token 只通过响应下发一次，客户端负责持久化
//   - 用户名不存在 / 密码错 / 账号停用统一返回 ErrInvalidCredentials，防枚举
type LoginService struct {
	deps LoginServiceDeps
}

// NewLoginService 构造登录服务。
func NewLoginService(d LoginServiceDeps) *LoginService {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.TTL == 0 {
		d.TTL = DefaultSessionTTL
	}
	return &LoginService{deps: d}
}

// LoginInput 是 POST /admin/v1/auth/login 的入参。
type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginOutput 是登录成功的出参。
//
// Token 是【明文】，调用方需把它放到 cookie（HttpOnly+Secure+SameSite=Strict）
// 或 LocalStorage（若 web 端另有防护）。后续请求头 Authorization: Bearer <token>。
type LoginOutput struct {
	Token     string     `json:"token"`
	UserID    int64      `json:"user_id"`
	Username  string     `json:"username"`
	Role      admin.Role `json:"role"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// Login 登录：账号密码校验通过后签发会话。
//
// 失败统一映射为 errs.CodeUnauthorized，不暴露"用户名不存在"或"密码错"细节。
func (s *LoginService) Login(ctx context.Context, in LoginInput, clientIP, userAgent string) (*LoginOutput, error) {
	if strings.TrimSpace(in.Username) == "" || in.Password == "" {
		// 这里是【参数校验】层的失败，可以明确告诉客户端"字段为空"；
		// 而下面的"账号存在但密码错"则统一模糊。
		return nil, errs.New(errs.CodeInvalidRequest, "username / password 必填")
	}
	u, err := s.deps.Users.FindByUsername(ctx, in.Username)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			// 故意走一遍 bcrypt 防 timing attack。
			// 即使用户不存在也要"验证密码"，让两端耗时对齐；
			// dummy hash 是预生成好的 bcrypt 串，cost=12 ⇒ ~250ms。
			_ = adminx.VerifyPassword(dummyBcryptHash, in.Password)
			if s.deps.Logger != nil {
				s.deps.Logger.Warn("管理端登录失败：账号不存在",
					zap.String("username", in.Username),
					zap.String("client_ip", clientIP))
			}
			return nil, admin.ErrInvalidCredentials
		}
		return nil, err
	}
	if !u.Enabled() {
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("管理端登录失败：账号已停用",
				zap.String("username", u.Username),
				zap.String("client_ip", clientIP))
		}
		return nil, admin.ErrInvalidCredentials
	}
	if err := adminx.VerifyPassword(u.PasswordHash, in.Password); err != nil {
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("管理端登录失败：密码错",
				zap.String("username", u.Username),
				zap.String("client_ip", clientIP))
		}
		return nil, admin.ErrInvalidCredentials
	}

	// 通过：签发 token，写库，更新 last_login_at。
	token, err := generateSessionToken()
	if err != nil {
		return nil, err
	}
	now := s.deps.Now()
	sess := &admin.Session{
		UserID:    u.ID,
		TokenHash: sha256HexToken(token),
		ClientIP:  clientIP,
		UserAgent: userAgent,
		ExpiresAt: now.Add(s.deps.TTL),
	}
	if err := s.deps.Sessions.Insert(ctx, sess); err != nil {
		return nil, err
	}
	if err := s.deps.Users.UpdateLastLoginAt(ctx, u.ID); err != nil {
		// 不阻塞登录返回，只记 warn——last_login_at 是一次近似指标。
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("更新 last_login_at 失败",
				zap.Int64("user_id", u.ID),
				zap.Error(err))
		}
	}
	return &LoginOutput{
		Token:     token,
		UserID:    u.ID,
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: sess.ExpiresAt,
	}, nil
}

// Logout 注销当前会话。
//
// 失败已经过期/已撤销也按成功处理——撤销操作是幂等的。
func (s *LoginService) Logout(ctx context.Context, principal *admin.Principal) error {
	if principal == nil || principal.Session == nil {
		return nil
	}
	// 即使 revoke 失败（已被其他请求撤销过、过期），也不算错。
	_ = s.deps.Sessions.Revoke(ctx, principal.Session.ID)
	return nil
}

// --- AuthHandler：路由薄壳 ---

// AuthHandler 把 LoginService 包成 gin handler。
type AuthHandler struct {
	svc    *LoginService
	logger *zap.Logger
}

// NewAuthHandler 构造 AuthHandler。
func NewAuthHandler(svc *LoginService, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, logger: logger}
}

// Login POST /admin/v1/auth/login。
//
// 成功 200 + LoginOutput；失败统一 401（参见 adminmw 的防枚举策略）。
func (h *AuthHandler) Login(c *gin.Context) {
	var in LoginInput
	if !httputil.BindJSON(c, &in, h.logger) {
		return
	}
	out, err := h.svc.Login(c.Request.Context(), in,
		c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		// 内部错误 → 500；账号密码错 / 账号停用 → 401 不区分。
		if errors.Is(err, admin.ErrInvalidCredentials) {
			httputil.Fail(c, h.logger,
				errs.New(errs.CodeUnauthorized, "账号或密码错误"))
			return
		}
		httputil.Fail(c, h.logger, err)
		return
	}
	httputil.OK(c, http.StatusOK, out)
}

// Me GET /admin/v1/auth/me。
//
// 仅返回必要信息（不返回 password_hash、不返回 token_hash），
// 供前端做"我的账号"页 + 顶部用户信息条。
func (h *AuthHandler) Me(c *gin.Context) {
	p := adminmw.Principal(c)
	if p == nil || p.User == nil {
		httputil.Fail(c, h.logger,
			errs.New(errs.CodeUnauthorized, "未认证"))
		return
	}
	httputil.OK(c, http.StatusOK, gin.H{
		"user_id":            p.User.ID,
		"username":           p.User.Username,
		"display_name":       p.User.DisplayName,
		"role":               p.User.Role,
		"last_login_at":      p.User.LastLoginAt,
		"session_expires_at": p.Session.ExpiresAt,
	})
}

// Logout POST /admin/v1/auth/logout。
//
// 永远返回 200——撤销失败（已被其他请求撤销过）也算成功。
func (h *AuthHandler) Logout(c *gin.Context) {
	p := adminmw.Principal(c)
	if err := h.svc.Logout(c.Request.Context(), p); err != nil {
		// 即使有内部错误，从用户角度"我已经登出"这件事成立
		//（token 在中间件下次也会被判断为已撤销）；只记日志。
		if h.logger != nil {
			h.logger.Warn("管理端登出异常", zap.Error(err))
		}
	}
	httputil.OK(c, http.StatusOK, gin.H{"ok": true})
}

// --- helpers ---

// generateSessionToken 生成 32 字节随机 token 并 hex 编码。
func generateSessionToken() (string, error) {
	var b [TokenBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errs.Wrap(errs.CodeInternal, "生成会话 token 失败", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// sha256HexToken 计算 SHA-256 hex 摘要。
//
// 必须与 adminmw.sha256Hex 保持完全一致——adminmw 鉴权时也会算同样的摘要。
// 切勿换算法，否则会让所有已签发的 session 失效。
func sha256HexToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
