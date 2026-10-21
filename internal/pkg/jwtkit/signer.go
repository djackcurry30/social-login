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

// Key 是一把签名密钥。
//
// Private 为 nil 时通过 Public 只发布公钥——这是轮换过渡期的旧密钥的正确形态：
// 它已经不需要再签名，但业务方还在用它的公钥验旧 token，因此必须继续出现在
// JWKS 里。**旧密钥不该继续持有私钥**：持有多余私钥只会扩大泄漏面。
type Key struct {
	KID     string
	Private *ecdsa.PrivateKey
	// Public 在 Private 为 nil 时使用（仅发布公钥的密钥）。
	Public *ecdsa.PublicKey
	// CreatedAt 是该密钥开始发布的时刻。
	CreatedAt time.Time
	// DemotedAt 是它停止签名的时刻（零值表示仍在签名）。
	// retire 的前置校验用它推算"是否还有用这把 kid 签发且未过期的 token"。
	DemotedAt time.Time
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
	// meta 记录每把密钥的发布/降级时刻，用于 retire 的前置校验。
	meta map[string]*keyMeta

	// mu 保护 signing / pubKeys / order / meta。
	//
	// 早期版本这里是"构造后只读、无需加锁"，但 F 组支持运行期轮换
	// （rotate / retire 会改这三者），签名与验签是热路径，必须保护。
	mu sync.RWMutex
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
		meta:    make(map[string]*keyMeta, len(keys)),
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
		} else if k.Public != nil {
			pub = k.Public
		}
		if pub == nil {
			return nil, errs.Newf(errs.CodeAuthInvalidConfig, "密钥 %s 既无私钥也无公钥", k.KID)
		}
		s.pubKeys[k.KID] = pub
		s.order = append(s.order, k.KID)
		created := k.CreatedAt
		if created.IsZero() {
			created = time.Now().UTC()
		}
		s.meta[k.KID] = &keyMeta{CreatedAt: created, DemotedAt: k.DemotedAt}
		if i == 0 && k.Private != nil {
			s.signing = &k
		}
	}
	if s.signing == nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "第一把密钥必须带私钥（用于签名）")
	}
	return s, nil
}

// Issuer 返回配置的 iss。
func (s *Signer) Issuer() string { return s.issuer }

// TTL 返回 access_token 有效期。
func (s *Signer) TTL() time.Duration { return s.ttl }

// ActiveKID 返回当前用于签名的 kid。
//
// 调用方（管理端密钥轮换接口）需要在 retire 旧密钥前确认"不存在用该 kid 签发
// 且未过期的 token"，依据就是这个值。
func (s *Signer) ActiveKID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.signing == nil {
		return ""
	}
	return s.signing.KID
}

// Kids 返回 JWKS 中当前发布的全部 kid。
func (s *Signer) Kids() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	// 读锁只在取密钥这一刻持有：签名本身（ECDSA 运算）不比一次 map 访问更危险，
	// 但把整个签发包在锁里会让轮换期间的签发排队。
	s.mu.RLock()
	signing := s.signing
	s.mu.RUnlock()
	if signing == nil || signing.Private == nil {
		return "", nil, errs.New(errs.CodeInternal, "无可用的签名密钥")
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = signing.KID
	signed, err := tok.SignedString(signing.Private)
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
		s.mu.RLock()
		pub, ok := s.pubKeys[kid]
		s.mu.RUnlock()
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
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	ec, err := ParsePrivatePEMBlock(raw)
	if err != nil {
		return Key{}, err
	}
	return Key{KID: kid, Private: ec}, nil
}

// keyMeta 记录一把密钥的生命周期。
//
// DemotedAt 是"不再用于签名"的时刻——retire 的前置校验必须用它而不是
// CreatedAt：一把已经 signing 了三个月的密钥，即使刚 rotate 出去，
// 也还有大量用它签发的 token 没过期，此时下线会让这些 token 全部验签失败。
type keyMeta struct {
	CreatedAt time.Time
	DemotedAt time.Time
}

// 密钥在轮换中的角色。
const (
	// KeyStatusSigning 是当前用于签名的唯一密钥。
	KeyStatusSigning = "signing"
	// KeyStatusPublished 是只发布公钥、不再签名（等待旧 token 过期）。
	KeyStatusPublished = "published"
)

// KeyInfo 是密钥的对外视图（不含任何私钥材料）。
type KeyInfo struct {
	KID       string    `json:"kid"`
	Algorithm string    `json:"algorithm"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	// DemotedAt 是停止签名的时刻（仍在签名时为空）。
	DemotedAt *time.Time `json:"demoted_at,omitempty"`
	// RetirableAt 是"可以安全下线"的最早时刻 = DemotedAt + access TTL + 宽限。
	// 给出这个时间比只说"还不能下线"更有用：运维能据此安排窗口。
	RetirableAt *time.Time `json:"retirable_at,omitempty"`
}

// retainGrace 是 retire 的额外宽限。
//
// 取 1 分钟而不是 0：JWT 的 exp 与本地时钟存在毫秒级偏差，
// 恰好卡在边界上的 token 会因为"服务端认为已过期、验签方认为还没"而失败。
const retainGrace = time.Minute

// List 返回当前全部密钥的状态。
func (s *Signer) List() []KeyInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]KeyInfo, 0, len(s.order))
	for _, kid := range s.order {
		m := s.meta[kid]
		info := KeyInfo{KID: kid, Algorithm: "ES256", Status: KeyStatusPublished}
		if m != nil {
			info.CreatedAt = m.CreatedAt
			if !m.DemotedAt.IsZero() {
				d := m.DemotedAt
				info.DemotedAt = &d
				r := d.Add(s.ttl + retainGrace)
				info.RetirableAt = &r
			}
		}
		if s.signing != nil && s.signing.KID == kid {
			info.Status = KeyStatusSigning
		}
		out = append(out, info)
	}
	return out
}

// Rotate 让新密钥开始签名，旧密钥降级为"仅发布公钥"。
//
// 这正是 §8.3 四步轮换的第 1、2 步：
//   - 第 1 步：新密钥开始签名
//   - 第 2 步：JWKS 同时发布新旧两把公钥（旧密钥仍在 pubKeys 里）
//
// 后两步（等旧 token 过期、下线旧密钥）由 Retire 完成，中间必须等满 TTL。
func (s *Signer) Rotate(k Key) (string, error) {
	if k.KID == "" {
		return "", errs.New(errs.CodeInvalidRequest, "新密钥缺少 kid")
	}
	if k.Private == nil {
		return "", errs.New(errs.CodeInvalidRequest, "新密钥必须带私钥")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, dup := s.pubKeys[k.KID]; dup {
		return "", errs.Newf(errs.CodeAdminConflict, "kid 已存在: %s", k.KID)
	}
	now := time.Now().UTC()
	prev := ""
	if s.signing != nil {
		prev = s.signing.KID
		if m := s.meta[prev]; m != nil && m.DemotedAt.IsZero() {
			m.DemotedAt = now
		}
	}
	s.signing = &k
	s.pubKeys[k.KID] = &k.Private.PublicKey
	s.order = append(s.order, k.KID)
	s.meta[k.KID] = &keyMeta{CreatedAt: now}
	return prev, nil
}

// Retire 下线旧密钥（§8.3 的第 3、4 步）。
//
// 前置校验是本接口存在的全部意义：提前下线旧密钥 = 所有用它签的 token
// 立刻验签失败。因此要求"它已停止签名，且停签时刻 + access TTL 已过"。
func (s *Signer) Retire(kid string) error {
	if kid == "" {
		return errs.New(errs.CodeInvalidRequest, "kid 不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.signing != nil && s.signing.KID == kid {
		return errs.New(errs.CodeAdminConflict,
			"不能下线当前正在签名的密钥，请先 rotate").
			WithDetail("active_kid", kid)
	}
	if _, ok := s.pubKeys[kid]; !ok {
		return errs.New(errs.CodeNotFound, "密钥不存在").WithDetail("kid", kid)
	}
	m := s.meta[kid]
	if m == nil || m.DemotedAt.IsZero() {
		// 防御：理论上只有 signing 才会 DemotedAt 为空，上面已拦。
		return errs.New(errs.CodeAdminConflict, "该密钥仍在使用中，不能下线")
	}
	earliest := m.DemotedAt.Add(s.ttl + retainGrace)
	if now := time.Now().UTC(); now.Before(earliest) {
		return errs.New(errs.CodeAdminConflict,
			"仍有使用该密钥签发的令牌未过期，暂不能下线").
			WithDetail("kid", kid).
			WithDetail("retirable_at", earliest.Format(time.RFC3339)).
			WithDetail("wait_seconds", int(earliest.Sub(now).Seconds()))
	}

	delete(s.pubKeys, kid)
	delete(s.meta, kid)
	for i, v := range s.order {
		if v == kid {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// ExportPrivatePEM 导出私钥 PEM（供持久化层落盘）。
//
// ⚠️ 只应由密钥存储实现调用。私钥不进数据库、不进仓库（§8.3）。
func (s *Signer) ExportPrivatePEM(kid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.signing != nil && s.signing.KID == kid && s.signing.Private != nil {
		return MarshalPrivatePEM(s.signing.Private)
	}
	return nil, errs.New(errs.CodeNotFound, "私钥不存在（仅当前签名密钥保留私钥）").
		WithDetail("kid", kid)
}

// MarshalPrivatePEM 把 ECDSA 私钥编码成 PKCS#8 PEM。
func MarshalPrivatePEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "编码私钥失败", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// KeyState 是持久化用的密钥快照（含私钥）。
//
// 只应交给密钥存储（KMS / 配置中心 / 受权限保护的文件），
// 不得序列化进任何 HTTP 响应。
type KeyState struct {
	KID string
	// Private 与 Public 二者其一非空：当前签名密钥带私钥，旧密钥只有公钥。
	Private   *ecdsa.PrivateKey
	Public    *ecdsa.PublicKey
	CreatedAt time.Time
	DemotedAt time.Time
}

// Snapshot 导出当前全部密钥与其生命周期状态，供持久化。
func (s *Signer) Snapshot() (activeKID string, states []KeyState) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.signing != nil {
		activeKID = s.signing.KID
	}
	states = make([]KeyState, 0, len(s.order))
	for _, kid := range s.order {
		st := KeyState{KID: kid}
		if m := s.meta[kid]; m != nil {
			st.CreatedAt = m.CreatedAt
			st.DemotedAt = m.DemotedAt
		}
		// 私钥只对当前签名密钥保留；其余密钥持久化时只需要公钥。
		if s.signing != nil && s.signing.KID == kid {
			st.Private = s.signing.Private
		} else {
			st.Public = s.pubKeys[kid]
		}
		states = append(states, st)
	}
	return activeKID, states
}

// MarshalPublicPEM 把公钥编码成 SPKI PEM。
func MarshalPublicPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "编码公钥失败", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicPEM 解析 SPKI PEM 公钥。
func ParsePublicPEM(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "公钥不是合法的 PEM")
	}
	any, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "解析公钥失败", err)
	}
	pub, ok := any.(*ecdsa.PublicKey)
	if !ok {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "公钥不是 EC 类型")
	}
	return pub, nil
}

// ParsePrivatePEMBlock 解析 PKCS#8 或 SEC1 格式的私钥 PEM。
//
// 与 LoadPrivateKeyPEM 的区别：后者从文件读，这里从内存字节解析
// （密钥存储加载落盘内容时用）。
func ParsePrivatePEMBlock(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "私钥不是合法的 PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	generic, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "解析私钥失败", err)
	}
	ec, ok := generic.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "私钥不是 ECDSA 类型")
	}
	return ec, nil
}
