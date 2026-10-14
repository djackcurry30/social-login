// Package jwtkit 负责本服务 access_token / id_token 的 ES256 签发与 JWKS 发布。
//
// 设计依据（架构 §8.1 / §8.3）：
//   - 业务方本地验签，因此必须暴露 /v1/jwks（P0-2）。
//   - 密钥轮换四步：新密钥上线 → JWKS 同时发布新旧 → 等旧 token 过期 → 下线旧密钥。
//     顺序不可颠倒，否则旧 token 全部验签失败。因此 Signer 支持"多把公钥并存、
//     仅一把用于签名"的状态。
//   - 私钥不入库、不进仓库：从配置或 KMS 加载；开发环境允许启动时临时生成。
package jwtkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/ids"
)

// Claims 是本服务签发的 JWT 载荷（架构 §8.1）。
//
// sub 直接用业务方账号标识（约束 C4：remote 模式下本服务不持有账号）。
type Claims struct {
	jwt.RegisteredClaims
	// Scope 取值：openid profile / identity_only（未注册分支）。
	Scope string `json:"scope,omitempty"`
	// AMR 是认证方式列表，如 ["wechat:mini_program"]，供业务方做风控。
	AMR []string `json:"amr,omitempty"`
}

// Key 是一把签名密钥。Private 为 nil 表示只发布公钥（轮换过渡期的旧密钥）。
type Key struct {
	KID     string
	Private *ecdsa.PrivateKey
}

// Signer 负责签发与发布公钥。
//
// 并发安全：keys 在构造后只读，因此无需加锁；构造完成后签名路径无锁。
type Signer struct {
	issuer string
	ttl    time.Duration

	signing *Key                        // 当前用于签名的密钥
	pubKeys map[string]*ecdsa.PublicKey // kid → 公钥（含旧密钥，用于验签与 JWKS 发布）
	order   []string                    // 保持发布顺序，便于测试与排查

	mu sync.RWMutex // 仅供未来热轮换使用；当前只读路径不触发
}

// Options 是 Signer 的构造参数。
type Options struct {
	// Issuer 是 JWT 的 iss，形如 https://auth.example.com。
	Issuer string
	// TTL 是 access_token 有效期，默认 15 分钟。
	TTL time.Duration
	// Keys 是密钥列表。第一个用于签名，其余仅发布公钥。
	// 为空时（开发环境）自动生成一把临时密钥。
	Keys []Key
	// DevGeneratedKID 在自动生成密钥时使用的 kid。
	DevGeneratedKID string
}

// NewSigner 构造签名器。
func NewSigner(opts Options) (*Signer, error) {
	if opts.Issuer == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "JWT issuer 未配置")
	}
	if opts.TTL <= 0 {
		opts.TTL = 15 * time.Minute
	}
	keys := opts.Keys
	if len(keys) == 0 {
		kid := opts.DevGeneratedKID
		if kid == "" {
			kid = "dev-" + ids.ULID()[:8]
		}
		k, err := GenerateKey(kid)
		if err != nil {
			return nil, err
		}
		keys = []Key{k}
	}

	s := &Signer{
		issuer:  opts.Issuer,
		ttl:     opts.TTL,
		pubKeys: make(map[string]*ecdsa.PublicKey, len(keys)),
		order:   make([]string, 0, len(keys)),
	}
	for i, k := range keys {
		if k.KID == "" {
			return nil, errs.New(errs.CodeAuthInvalidConfig, "签名密钥缺少 kid")
		}
		if _, dup := s.pubKeys[k.KID]; dup {
			return nil, errs.Newf(errs.CodeAuthInvalidConfig, "签名密钥 kid 重复: %s", k.KID)
		}
		var pub *ecdsa.PublicKey
		if k.Private != nil {
			pub = &k.Private.PublicKey
		} else if p := publicKeyOf(k); p != nil {
			pub = p
		}
		if pub == nil {
			return nil, errs.Newf(errs.CodeAuthInvalidConfig, "密钥 %s 既无私钥也无公钥", k.KID)
		}
		s.pubKeys[k.KID] = pub
		s.order = append(s.order, k.KID)
		if i == 0 && k.Private != nil {
			s.signing = &k
		}
	}
	if s.signing == nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "第一把密钥必须带私钥（用于签名）")
	}
	return s, nil
}

// publicKeyOf 从 Key 中提取公钥。
//
// 说明：当前 Key 结构只携带私钥；仅发布公钥的场景由 NewSigner 从私钥推导。
// 保留此挂钩是为了将来支持"只加载公钥"的密钥（如从 KMS 公钥接口拉取）。
func publicKeyOf(_ Key) *ecdsa.PublicKey { return nil }

// Issuer 返回配置的 iss。
func (s *Signer) Issuer() string { return s.issuer }

// TTL 返回 access_token 有效期。
func (s *Signer) TTL() time.Duration { return s.ttl }

// ActiveKID 返回当前用于签名的 kid。
//
// 调用方（管理端密钥轮换接口）需要在 retire 旧密钥前确认"不存在用该 kid 签发
// 且未过期的 token"，依据就是这个值。
func (s *Signer) ActiveKID() string {
	if s.signing == nil {
		return ""
	}
	return s.signing.KID
}

// Kids 返回 JWKS 中当前发布的全部 kid。
func (s *Signer) Kids() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// IssueInput 是签发一次令牌的入参。
type IssueInput struct {
	// Subject 是业务方账号标识（约束 C4）。
	Subject string
	// Audience 是消费方 app_id（app_code）。
	Audience string
	// Scope 取值 openid profile / identity_only。
	Scope string
	// AMR 是认证方式，如 wechat:mini_program。
	AMR []string
	// TTL 覆盖默认有效期，0 表示用默认。
	TTL time.Duration
}

// Issue 签发一个 ES256 JWT。
func (s *Signer) Issue(in IssueInput) (token string, claims *Claims, err error) {
	if in.Subject == "" {
		return "", nil, errs.New(errs.CodeInternal, "签发令牌缺少 subject")
	}
	if in.Audience == "" {
		return "", nil, errs.New(errs.CodeInternal, "签发令牌缺少 audience")
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.ttl
	}
	now := time.Now()
	claims = &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   in.Subject,
			Audience:  jwt.ClaimStrings{in.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        ids.New(ids.PrefixJTI),
		},
		Scope: in.Scope,
		AMR:   in.AMR,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = s.signing.KID
	signed, err := tok.SignedString(s.signing.Private)
	if err != nil {
		return "", nil, errs.Wrap(errs.CodeInternal, "签发令牌失败", err)
	}
	return signed, claims, nil
}

// Parse 本地验签并解析令牌。供 /v1/introspect 与内部校验使用。
//
// 注意：本地验签【不检查 jti 黑名单】（架构 §8.4）。高危撤销场景需要额外
// 调用 RevocationChecker，由上层组合。
func (s *Signer) Parse(tokenStr string) (*Claims, error) {
	if tokenStr == "" {
		return nil, errs.New(errs.CodeTokenInvalid, "令牌为空")
	}
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := s.pubKeys[kid]
		if !ok {
			return nil, fmt.Errorf("未知 kid: %s", kid)
		}
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("非预期的签名算法: %v", t.Header["alg"])
		}
		return pub, nil
	},
		jwt.WithIssuer(s.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return claims, errs.Wrap(errs.CodeTokenExpired, "令牌已过期", err)
		}
		return nil, errs.Wrap(errs.CodeTokenInvalid, "令牌校验失败", err)
	}
	return claims, nil
}

// --- JWKS ---

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// JWKS 返回公钥集 JSON（仅公钥，绝不含私钥材料）。
func (s *Signer) JWKS() ([]byte, error) {
	doc := jwksDoc{Keys: make([]jwk, 0, len(s.order))}
	for _, kid := range s.order {
		pub := s.pubKeys[kid]
		if pub == nil {
			continue
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		doc.Keys = append(doc.Keys, jwk{
			Kty: "EC",
			Crv: curveName(pub.Curve),
			X:   base64.RawURLEncoding.EncodeToString(padBytes(pub.X, size)),
			Y:   base64.RawURLEncoding.EncodeToString(padBytes(pub.Y, size)),
			Kid: kid,
			Use: "sig",
			Alg: "ES256",
		})
	}
	return json.Marshal(doc)
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "P-256"
	}
}

func padBytes(v *big.Int, size int) []byte {
	if v == nil {
		return make([]byte, size)
	}
	b := v.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// --- 密钥生成与加载 ---

// GenerateKey 生成一把 P-256 密钥。
func GenerateKey(kid string) (Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, errs.Wrap(errs.CodeInternal, "生成签名密钥失败", err)
	}
	return Key{KID: kid, Private: priv}, nil
}

// LoadPrivateKeyPEM 从 PEM 文件加载私钥。文件权限应为 0600 且不入版本库。
func LoadPrivateKeyPEM(path, kid string) (Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Key{}, errs.Wrap(errs.CodeAuthInvalidConfig, "读取签名密钥失败", err).
			WithDetail("path", path)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return Key{}, errs.New(errs.CodeAuthInvalidConfig, "签名密钥不是合法的 PEM").
			WithDetail("path", path)
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return Key{KID: kid, Private: key}, nil
	}
	generic, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Key{}, errs.Wrap(errs.CodeAuthInvalidConfig, "解析签名私钥失败", err).
			WithDetail("path", path)
	}
	ec, ok := generic.(*ecdsa.PrivateKey)
	if !ok {
		return Key{}, errs.New(errs.CodeAuthInvalidConfig, "签名私钥不是 ECDSA 类型").
			WithDetail("path", path)
	}
	return Key{KID: kid, Private: ec}, nil
}
