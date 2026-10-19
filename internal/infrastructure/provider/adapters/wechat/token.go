package wechat

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// accessTokenCache 缓存小程序接口用的 component access_token。
//
// 为什么必须缓存：微信的 stable_token 接口有调用频率限制，而手机号解密
// （getuserphonenumber）每个用户都要一次 token。不缓存的话，稍有流量就会被限频，
// 表现成"偶发登录失败"这种最难排查的故障形态。
//
// 为什么是进程内缓存而不是 Redis：access_token 是整机维度的凭据，
// 多副本各自持有一份完全正常（各自续期，互不影响）。为它引入一次网络往返，
// 只会把"微信接口慢"放大成"我们的登录慢"。这与熔断器选择进程内状态是同一取舍。
type accessTokenCache struct {
	mu    sync.Mutex
	items map[string]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// 提前 5 分钟过期，避免"刚好在边界上失效"导致一次无谓失败。
const tokenSafetyMargin = 5 * time.Minute

func newAccessTokenCache() *accessTokenCache {
	return &accessTokenCache{items: make(map[string]cachedToken)}
}

func (c *accessTokenCache) get(appID string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[appID]
	if !ok || it.token == "" || time.Now().After(it.expiresAt) {
		return "", false
	}
	return it.token, true
}

func (c *accessTokenCache) put(appID, token string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl > tokenSafetyMargin {
		ttl -= tokenSafetyMargin
	}
	c.items[appID] = cachedToken{token: token, expiresAt: time.Now().Add(ttl)}
}

func (c *accessTokenCache) invalidate(appID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, appID)
}

// stableTokenRequest 是稳定版 access_token 的入参。
type stableTokenRequest struct {
	GrantType    string `json:"grant_type"`
	AppID        string `json:"appid"`
	Secret       string `json:"secret"`
	ForceRefresh bool   `json:"force_refresh"`
}

type stableTokenResponse struct {
	wxError
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// componentAccessToken 取小程序接口所需的 access_token（带缓存）。
func (a *Adapter) componentAccessToken(ctx context.Context, creds provider.Credentials) (string, error) {
	if tok, ok := a.tokens.get(creds.ProviderAppID); ok {
		return tok, nil
	}
	if creds.Secret == "" {
		return "", errs.New(errs.CodeAuthInvalidConfig,
			"小程序场景缺少 app_secret，无法获取 component access_token")
	}

	endpoint := a.apiBaseOf(creds) + "/cgi-bin/stable_token"
	var out stableTokenResponse
	payload := stableTokenRequest{
		GrantType: "client_credential",
		AppID:     creds.ProviderAppID,
		Secret:    creds.Secret,
	}
	if _, err := a.http.PostJSON(ctx, endpoint, payload, &out); err != nil {
		return "", err
	}
	if out.failed() {
		return "", wxErr(out.wxError, a.meta.Platform)
	}
	if out.AccessToken == "" {
		return "", errs.New(errs.CodeProviderRejected, "微信未返回 access_token").
			WithDetail("platform", a.meta.Platform)
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	a.tokens.put(creds.ProviderAppID, out.AccessToken, ttl)
	return out.AccessToken, nil
}

// buildAuthURL 拼接 open.weixin.qq.com 的授权地址。
//
// 两种入口的差异只有路径与默认 scope，其余参数完全一致，
// 因此合并成一个函数，避免两处各改一半。
func buildAuthURL(base, path string, q url.Values) string {
	u := fmt.Sprintf("%s%s?%s#wechat_redirect", base, path, q.Encode())
	return u
}
