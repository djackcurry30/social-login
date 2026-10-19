package apple

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// jwksCache 缓存 Apple 的签名公钥集。
//
// 为什么必须缓存：Apple 的 JWKS 是登录链路上的强依赖，每次登录都去拉一次
// 会把 Apple 的可用性直接放大成我们的可用性。缓存 1 小时，并在 kid 未命中时
// 强制刷新一次——后者是协议语义要求（密钥轮换后必须重取才能验签），
// 不受约束 C6（不重试）的限制。
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration

	http *httpx.Client
	url  string
}

func newJWKSCache(url string, httpClient *httpx.Client) *jwksCache {
	return &jwksCache{
		keys: make(map[string]*rsa.PublicKey),
		ttl:  time.Hour,
		http: httpClient,
		url:  url,
	}
}

// jwkSet 是 Apple JWKS 的响应结构。
type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// get 取指定 kid 的公钥；未命中时刷新一次再取。
//
// jwksURL 允许按租户覆盖（测试与私有代理场景）。URL 变化时先作废缓存，
// 否则会拿 A 环境的 key 去验 B 环境的 token。
func (c *jwksCache) get(ctx context.Context, jwksURL, kid string) (*rsa.PublicKey, error) {
	if jwksURL != "" && jwksURL != c.url {
		c.mu.Lock()
		c.url = jwksURL
		c.mu.Unlock()
		c.invalidate()
	}
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	return nil, errs.Newf(errs.CodeAuthInvalidConfig,
		"Apple 公钥集中找不到 kid=%s（可能是密钥轮换后缓存未更新，或 id_token 来源异常）", kid).
		WithDetail("kid", kid)
}

func (c *jwksCache) lookup(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Since(c.fetchedAt) > c.ttl {
		return nil
	}
	return c.keys[kid]
}

func (c *jwksCache) refresh(ctx context.Context) error {
	var set jwkSet
	if _, err := c.http.GetJSON(ctx, c.url, nil, &set); err != nil {
		return err
	}
	next := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := parseJWK(k.N, k.E)
		if err != nil {
			// 单个 key 解析失败不应让整批失效——Apple 可能新增了非 RSA 的 key。
			continue
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return errs.New(errs.CodeProviderUnavailable, "Apple JWKS 为空或无法解析")
	}

	c.mu.Lock()
	c.keys = next
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// invalidate 主动作废缓存（kid 未命中时用）。
func (c *jwksCache) invalidate() {
	c.mu.Lock()
	c.fetchedAt = time.Time{}
	c.mu.Unlock()
}

// parseJWK 把 JWK 的 n / e（base64url）还原成 rsa.PublicKey。
func parseJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errs.New(errs.CodeProviderUnavailable, "JWK 的 n/e 为空")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// header 是 JWT header 的最小结构。
func jwtHeader(token string) (kid, alg string, err error) {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return "", "", errs.New(errs.CodeAuthInvalidState, "id_token 不是合法的 JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "id_token 头部不是合法 base64url", err)
	}
	var h struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", "", errs.Wrap(errs.CodeAuthInvalidState, "id_token 头部不是合法 JSON", err)
	}
	return h.Kid, h.Alg, nil
}

func splitJWT(token string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			out = append(out, token[start:i])
			start = i + 1
		}
	}
	out = append(out, token[start:])
	return out
}
