package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/alex/social-login/internal/interfaces/http/httputil"
	"github.com/alex/social-login/internal/pkg/errs"
)

// JWKS 处理 GET /v1/jwks：暴露签名公钥集。
//
// 这个端点是"业务方本地验签"能否成立的前提（修正 P0-2）。
// 没有它，业务方只能每次调 /v1/introspect，那"零网络开销"就是空话。
func (h *Handler) JWKS(c *gin.Context) {
	if h.deps.Signer == nil {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "签名密钥未初始化"))
		return
	}
	body, err := h.deps.Signer.JWKS()
	if err != nil {
		httputil.Fail(c, h.logger(), err)
		return
	}
	// 允许长时间缓存：公钥轮换是低频事件，且轮换时必须"新旧同时发布"，
	// 因此缓存的旧公钥在过渡期内仍然是正确且必要的。
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}

// Discovery 处理 GET /.well-known/openid-configuration。
//
// 当前只发布最小元数据（issuer / jwks_uri / 支持的算法），目的是让业务方的
// JWT 库能"零配置"找到公钥。完整的 OIDC Provider 语义（标准 /userinfo 响应、
// id_token 完整规范）尚未对齐，属于架构记录在案的遗留项 E2。
func (h *Handler) Discovery(c *gin.Context) {
	if h.deps.Issuer == "" {
		httputil.Fail(c, h.logger(), errs.New(errs.CodeInternal, "issuer 未配置"))
		return
	}
	issuer := trimRight(h.deps.Issuer)
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/v1/jwks",
		"authorization_endpoint":                issuer + "/v1/authorize",
		"token_endpoint":                        issuer + "/v1/token",
		"introspection_endpoint":                issuer + "/v1/introspect",
		"revocation_endpoint":                   issuer + "/v1/revoke",
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		// 明确声明这不是完整 OIDC Provider，避免接入方按完整规范对接后踩坑。
		"x-oidc-completeness": "partial: jwks 与 discovery 已实现，userinfo 语义与 id_token 规范未对齐",
	})
}

func trimRight(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
