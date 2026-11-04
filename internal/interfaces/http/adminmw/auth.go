// Package adminmw 提供管理端（/admin/v1/*）的鉴权与 RBAC 中间件。
//
// 设计依据：架构 §15.2 明确管理端鉴权与业务端完全分离：
//   - 鉴权：Bearer Token + RBAC，与 appId/appSecret 完全无关
//   - 网络：内网/VPN/IP 白名单（本期不做网关层配置，由部署侧保证）
//   - 限流：按管理员账号，本期不做（rate limit 留给 P2 adminmw.RateLimit）
//
// 之所以单独成包（而不是放进 internal/interfaces/http/middleware）：
// 1. 业务端 middleware 不需要任何 admin 概念
// 2. 编译期隔离：adminmw 引 admin.* 不会污染业务端
// 3. 业务端已声明"管理端不重复实现业务逻辑，见 §15.2"，本包同样不引业务仓储
package adminmw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/interfaces/http/httputil"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

const (
	// HeaderAuthorization 是 HTTP 标准的 Authorization 头。
	HeaderAuthorization = "Authorization"
	// BearerPrefix 是 Authorization 头的 Bearer 前缀。
	BearerPrefix = "Bearer "

	// CtxKeyPrincipal 是写入 gin.Context 的主体键。
	CtxKeyPrincipal = "admin.principal"
)

// SessionLookup 是 admin.SessionRepository 的最小子集（避免循环引用）。
//
// 业务实现（postgres.AdminSessionRepository）满足此接口；测试可用桩。
type SessionLookup interface {
	FindByTokenHash(ctx context.Context, tokenHash string) (*admin.Session, error)
}

// UserLookup 是 admin.UserRepository 的最小子集。
type UserLookup interface {
	FindByID(ctx context.Context, id int64) (*admin.User, error)
}

// Authenticator 是 admin 鉴权依赖（注入）。
type Authenticator struct {
	Sessions SessionLookup
	Users    UserLookup
	Logger   *zap.Logger
	// Now 可注入；nil 时用 time.Now().UTC()。
	Now func() time.Time
}

// Authenticate 是入口中间件：解析 Authorization: Bearer → 查 session → 查 user → 写入 principal。
//
// 失败原因统一返 CodeUnauthorized，不区分"用户不存在"与"token 无效"（避免枚举）。
// 过期 / 已撤销 用专门 code（CodeAdminSessionExpired / CodeAdminSessionRevoked），
// 因为这两种是【可恢复】的（重新登录就行），客户端需要据此给用户明确提示。
func (a *Authenticator) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader(HeaderAuthorization)
		if !strings.HasPrefix(header, BearerPrefix) {
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeUnauthorized, "缺少 Bearer Token"))
			return
		}
		token := strings.TrimPrefix(header, BearerPrefix)
		if token == "" {
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeUnauthorized, "Bearer Token 为空"))
			return
		}
		tokenHash := sha256Hex(token)
		ctx := c.Request.Context()
		sess, err := a.Sessions.FindByTokenHash(ctx, tokenHash)
		if err != nil {
			// 包括 ErrNotFound
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeUnauthorized, "Token 无效"))
			return
		}
		now := a.now()
		if sess.Revoked() {
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeAdminSessionRevoked, "Token 已被撤销"))
			return
		}
		if sess.Expired(now) {
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeAdminSessionExpired, "Token 已过期"))
			return
		}
		user, err := a.Users.FindByID(ctx, sess.UserID)
		if err != nil {
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeUnauthorized, "Token 关联的账号不存在"))
			return
		}
		if !user.Enabled() {
			httputil.Fail(c, a.Logger,
				errs.New(errs.CodeForbidden, "账号已停用"))
			return
		}
		c.Set(CtxKeyPrincipal, &admin.Principal{User: user, Session: sess})
		c.Next()
	}
}

// scopeExemptRoutes 是"受限管理员在没有应用上下文时也允许访问"的路由白名单。
//
// 键是 "方法 路由模板"。只放三件事：
//   - 看自己是谁（前端据此渲染菜单与作用域）
//   - 登出
//   - 应用列表（handler 内部按 scope 过滤，见 adminapp.ListApps）
//
// 其他所有不带应用上下文的接口（全局聚合看板、渠道健康、签名密钥、管理员
// 名单…）对受限管理员一律拒绝：这些数据天然跨应用，无法"过滤一部分"，
// 而返回全局数据等于把隔离破了。
var scopeExemptRoutes = map[string]struct{}{
	"GET /admin/v1/auth/me":      {},
	"POST /admin/v1/auth/logout": {},
	"GET /admin/v1/apps":         {},
}

// Require 是 RBAC 中间件工厂：要求当前主体拥有 perm 权限，且（若权限带应用
// 范围）目标应用在范围内。
//
// 用法：api.GET("/apps/:appId", adminmw.Require("app:read"), h.Get)
//
// 三档判定，顺序不能换：
//
//  1. 有没有权限（Can：基础角色 ∪ 生效 grants）；
//  2. 该权限是否带应用范围（ScopeFor）。不带就直接放行——绝大多数管理员
//     的基础角色是全局的，不能让"某人还挂着一条单应用授权"反而缩小他的视野；
//  3. 带范围时，请求里必须指明应用且命中：路径参数 appId 优先，其次查询参数
//     app_id。两者都没有则看白名单，不在白名单就拒绝。
//
// 越界返回 404 而不是 403：403 等于告诉对方"这个 app_id 存在，只是你不能看"，
// 对受限管理员来说应用 id 本身就是不该泄露的信息。
func Require(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := c.Get(CtxKeyPrincipal)
		if !ok {
			httputil.Fail(c, nil, errs.New(errs.CodeUnauthorized, "未认证"))
			return
		}
		principal, ok := p.(*admin.Principal)
		if !ok || principal == nil || principal.User == nil {
			httputil.Fail(c, nil, errs.New(errs.CodeUnauthorized, "未认证"))
			return
		}
		// 用 Can 而不是 Role.Has：K 组的附加授权（grants）也参与判定，
		// 否则"临时加 operator"这类授权等于没生效。
		if !principal.User.Can(perm) {
			httputil.Fail(c, nil, errs.New(errs.CodeForbidden,
				"权限不足: "+perm).
				WithDetail("required", perm).
				WithDetail("role", string(principal.User.Role)))
			return
		}

		ids, restricted := principal.User.ScopeFor(perm)
		if !restricted {
			c.Next()
			return
		}

		// ① 路径里的 appId（/apps/:appId/**）
		if raw := c.Param("appId"); raw != "" {
			if !appInScope(ids, raw) {
				failAppOutOfScope(c, raw)
				return
			}
			c.Next()
			return
		}
		// ② 查询参数 app_id（C/D/E/G/H/J 组的列表与操作）
		if raw := c.Query("app_id"); raw != "" {
			if !appInScope(ids, raw) {
				failAppOutOfScope(c, raw)
				return
			}
			c.Next()
			return
		}
		// ③ 没有应用上下文：只有白名单允许。
		if _, ok := scopeExemptRoutes[c.Request.Method+" "+c.FullPath()]; ok {
			c.Next()
			return
		}
		httputil.Fail(c, nil, errs.New(errs.CodeForbidden,
			"当前账号的应用范围受限，必须指定 app_id 才能访问该接口").
			WithDetail("scope", "app").
			WithDetail("allowed_app_ids", ids))
	}
}

// appInScope 判断 appID 字符串是否在允许列表里。
//
// 解析失败一律当作越界：非法 app_id 不该因为"解析不出数字"而被放过。
func appInScope(ids []int64, raw string) bool {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false
	}
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func failAppOutOfScope(c *gin.Context, raw string) {
	httputil.Fail(c, nil, errs.New(errs.CodeNotFound, "应用不存在").
		WithDetail("app_id", raw))
}

// Principal 从 gin.Context 取出已认证的管理员。
//
// handler 应通过这个 helper 而不是直接 Get 上下文 key（封装变化）。
func Principal(c *gin.Context) *admin.Principal {
	if v, ok := c.Get(CtxKeyPrincipal); ok {
		if p, ok := v.(*admin.Principal); ok {
			return p
		}
	}
	return nil
}

// sha256Hex 返回 hex(SHA-256(input))。
//
// admin_session.token_hash 列就是 SHA-256 字符串，必须与这里一致。
// 切勿换算法——会让所有已签发的 session 失效。
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// now 返回当前时间（便于测试注入）。
func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}
