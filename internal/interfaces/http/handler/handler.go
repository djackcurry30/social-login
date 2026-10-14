// Package handler 是业务端 HTTP 处理器。
//
// 职责边界（架构 §3）：只做协议转换、参数校验与响应编码，业务规则一律在
// application 层。这里唯一"越界"的部分是接入方身份校验，它本身就属于接入职责。
package handler

import (
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/application/authflow"
	"github.com/djackcurry30/social-login/internal/application/binding"
	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/application/token"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
	"github.com/djackcurry30/social-login/internal/pkg/jwtkit"
)

// Deps 是处理器依赖。
type Deps struct {
	Tenant   *tenantconfig.Service
	AuthFlow *authflow.Service
	Tokens   *token.Service
	Bindings *binding.Service
	Signer   *jwtkit.Signer
	// SecretHasher 用于校验 /v1/token 请求体里携带的 client_secret
	// （该接口不挂 AppAuth 中间件，见 token.go 的说明）。
	SecretHasher *crypto.AppSecretHasher
	// Issuer 是 OIDC Discovery 中对外声明的 issuer。
	Issuer string
	// Version 供健康检查与元数据暴露。
	Version string
	// Health 是就绪探针要探测的下游依赖。
	Health HealthDeps
	Logger *zap.Logger
}

// Handler 聚合全部业务端处理器。
type Handler struct {
	deps Deps
}

// New 构造处理器。
func New(deps Deps) *Handler { return &Handler{deps: deps} }

// logger 统一取日志器，避免每处都判空。
func (h *Handler) logger() *zap.Logger {
	if h.deps.Logger == nil {
		return zap.NewNop()
	}
	return h.deps.Logger
}
