// Package httpx 是对 net/http 的极薄封装，专供三方渠道调用。
//
// 设计依据（架构 §5.5 / §5.7 / tech-stack §3.5）：
//
//  1. 【不做网络重试，永久不提供重试开关】。平台侧一次性凭证（授权 code）
//     重放语义不成立：超时后无法从客户端判断 code 是否已被消费，重放既不可靠
//     又会触发平台风控。重试单位是"整个授权流程"，由接入方重新发起 /v1/authorize
//     完成，不属于本层职责。这里的做法是"不写就没有"，而不是"默认开、记得关"。
//  2. 【分层超时】连接超时 + 响应头超时 + 单渠道总超时，逐层兜底。
//  3. 【取消隔离】Exchange / Refresh 这类"已发出即不可撤销"的调用必须用 Detach
//     脱离入站 context，否则用户断网会导致 code 被消费而结果丢失。
//  4. 【响应体上限】三方返回超大 body 不能打爆内存。
//  5. 【原始响应保留】部分渠道需要把原始响应用于 profile_snapshot 落库排障。
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// 默认值。可被 Config 覆盖。
const (
	DefaultConnectTimeout  = 1 * time.Second
	DefaultResponseTimeout = 3 * time.Second // 响应头超时
	DefaultTotalTimeout    = 5 * time.Second // 单渠道总超时
	DefaultMaxBodyBytes    = 1 << 20         // 1 MiB，三方用户信息远小于此
)

// Config 描述一个渠道客户端的构造参数。
type Config struct {
	// Name 用于日志与指标标签，一般取 "wechat" / "alipay" / "apple"。
	Name string
	// TotalTimeout 是单次请求的总超时（含连接、发送、读取）。0 取默认。
	TotalTimeout time.Duration
	// ConnectTimeout 是 TCP 建连超时。0 取默认。
	ConnectTimeout time.Duration
	// ResponseHeaderTimeout 是从发出请求到收到响应头的超时。0 取默认。
	ResponseHeaderTimeout time.Duration
	// MaxIdleConnsPerHost 每主机空闲连接数。0 取 16。
	MaxIdleConnsPerHost int
	// MaxBodyBytes 响应体读取上限（字节）。0 取默认。
	MaxBodyBytes int64
	// Transport 允许注入自定义 RoundTripper。
	// 可观测性接入点：第四期在这里换成 otelhttp.NewTransport(...)，
	// 本层不需要为 OTel 做任何改造（这也是不引入第三方 HTTP 客户端库的原因之一）。
	Transport http.RoundTripper
	// Logger 可选。nil 表示不记录调试日志。
	Logger *zap.Logger
}

// Client 是绑定到单个渠道的 HTTP 客户端。每个渠道一个实例，超时彼此独立。
type Client struct {
	name     string
	hc       *http.Client
	maxBody  int64
	logger   *zap.Logger
	totalTmo time.Duration
}

// Response 是一次三方调用的原始结果。
type Response struct {
	StatusCode int
	Header     http.Header
	// Raw 是未经解构的响应体，供 profile_snapshot 落库排障。
	Raw      []byte
	Duration time.Duration
}

// New 构造渠道客户端。
func New(cfg Config) *Client {
	if cfg.Name == "" {
		cfg.Name = "provider"
	}
	if cfg.TotalTimeout <= 0 {
		cfg.TotalTimeout = DefaultTotalTimeout
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = DefaultResponseTimeout
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = 16
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Transport == nil {
		cfg.Transport = newTransport(cfg)
	}
	return &Client{
		name: cfg.Name,
		hc: &http.Client{
			Transport: cfg.Transport,
			Timeout:   cfg.TotalTimeout,
			// 禁止跟随重定向：OAuth2 的 302 需要由我们显式处理，
			// 自动跟随会把 code 泄漏到 Location 目标（可能是攻击者域名）。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxBody:  cfg.MaxBodyBytes,
		logger:   cfg.Logger,
		totalTmo: cfg.TotalTimeout,
	}
}

func newTransport(cfg Config) http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	t := base.Clone()
	t.DialContext = (&net.Dialer{
		Timeout:   cfg.ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	t.ResponseHeaderTimeout = cfg.ResponseHeaderTimeout
	t.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
	t.ForceAttemptHTTP2 = true
	return t
}

// Name 返回渠道名，用于日志/指标。
func (c *Client) Name() string { return c.name }

// Do 执行一次请求。不重试。
//
// 错误归一化规则（供熔断器判定的基础分类，架构 §5.6.4）：
//
//	超时 / 连接失败     → PROVIDER.TIMEOUT / PROVIDER.UNAVAILABLE，retryable = true
//	三方 5xx            → PROVIDER.UNAVAILABLE，retryable = true
//	三方 4xx            → PROVIDER.REJECTED，retryable = false
//	响应体超限          → PROVIDER.UNAVAILABLE，retryable = true
//
// 注意：本方法返回的错误【不包含】响应体内容，避免把可能含凭据的报文塞进错误链。
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	if req == nil {
		return nil, errs.New(errs.CodeInvalidRequest, "HTTP 请求为空")
	}
	// 兜底 deadline：即使调用方传了无 deadline 的 context，也不能无限等待。
	if _, ok := ctx.Deadline(); !ok && c.totalTmo > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.totalTmo)
		defer cancel()
	}

	started := time.Now()
	resp, err := c.hc.Do(req.WithContext(ctx))
	elapsed := time.Since(started)
	if err != nil {
		return nil, c.classifyTransportError(req, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 读取时多读 1 字节用于判定是否超限。
	limited := io.LimitReader(resp.Body, c.maxBody+1)
	raw, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, errs.Wrap(errs.CodeProviderUnavailable,
			"读取三方响应失败", readErr).
			WithDetail("platform", c.name).
			WithDetail("op", req.URL.Path)
	}
	if int64(len(raw)) > c.maxBody {
		return nil, errs.New(errs.CodeProviderUnavailable, "三方响应体超过上限").
			WithDetail("platform", c.name).
			WithDetail("limit_bytes", c.maxBody).
			WithDetail("op", req.URL.Path)
	}

	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Raw:        raw,
		Duration:   elapsed,
	}

	if c.logger != nil {
		c.logger.Debug("provider_call",
			zap.String("platform", c.name),
			zap.String("method", req.Method),
			zap.String("url", MaskURL(req.URL.String())),
			zap.Int("status", resp.StatusCode),
			zap.Duration("duration", elapsed),
			zap.Int("body_bytes", len(raw)),
		)
	}
	return out, nil
}

// classifyTransportError 把 net/http 的错误映射为业务错误码。
func (c *Client) classifyTransportError(req *http.Request, err error) error {
	op := req.URL.Path
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errs.Wrap(errs.CodeProviderTimeout, "三方平台响应超时", err).
			WithDetail("platform", c.name).WithDetail("op", op)
	case errors.Is(err, context.Canceled):
		// 调用方主动取消（不含 Detach 的场景）。归为不可重试：重开会拿到同样的结果。
		return errs.Wrap(errs.CodeProviderUnavailable, "请求已被取消", err).
			WithDetail("platform", c.name).WithDetail("op", op).WithRetryable(false)
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errs.Wrap(errs.CodeProviderTimeout, "三方平台连接或读写超时", err).
			WithDetail("platform", c.name).WithDetail("op", op)
	}
	return errs.Wrap(errs.CodeProviderUnavailable, "无法连接三方平台", err).
		WithDetail("platform", c.name).WithDetail("op", op)
}

// GetJSON 发起 GET 并解析 JSON。
func (c *Client) GetJSON(ctx context.Context, rawURL string, query url.Values, out any) (*Response, error) {
	if len(query) > 0 {
		rawURL = rawURL + "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造三方请求失败", err)
	}
	return c.decode(ctx, req, out)
}

// PostFormJSON 以 application/x-www-form-urlencoded 发起 POST 并解析 JSON。
// 微信的 code2session / sns/oauth2 均为此形态。
func (c *Client) PostFormJSON(ctx context.Context, rawURL string, form url.Values, out any) (*Response, error) {
	body := form.Encode()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造三方请求失败", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))
	return c.decode(ctx, req, out)
}

// PostJSON 以 application/json 发起 POST 并解析 JSON。
// Apple 的 token / revoke 端点为此形态。
func (c *Client) PostJSON(ctx context.Context, rawURL string, payload any, out any) (*Response, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "序列化三方请求失败", err)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(buf))
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造三方请求失败", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(buf))
	return c.decode(ctx, req, out)
}

// decode 执行请求并按状态码决定是否解析。
func (c *Client) decode(ctx context.Context, req *http.Request, out any) (*Response, error) {
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, c.decodeBody(req, resp, out)
}

// DoJSON 执行一个由调用方自行构造的请求并解析 JSON。
//
// 供需要自定义请求头（如 client_secret_basic 的 Authorization 头）的适配器使用。
func (c *Client) DoJSON(ctx context.Context, req *http.Request, out any) (*Response, error) {
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, c.decodeBody(req, resp, out)
}

// decodeBody 按状态码决定是否解析响应体，并把三方错误归一化。
func (c *Client) decodeBody(req *http.Request, resp *Response, out any) error {
	if resp.StatusCode >= 500 {
		return errs.New(errs.CodeProviderUnavailable, "三方平台返回服务端错误").
			WithDetail("platform", c.name).
			WithDetail("status", resp.StatusCode).
			WithDetail("op", req.URL.Path)
	}
	if resp.StatusCode >= 400 {
		// 4xx 是业务语义的正常返回（如 invalid grant），重试无意义。
		e := errs.New(errs.CodeProviderRejected, "三方平台拒绝了本次请求").
			WithDetail("platform", c.name).
			WithDetail("status", resp.StatusCode).
			WithDetail("op", req.URL.Path)
		if pe := extractProviderError(resp.Raw); pe != "" {
			e.WithDetail("provider_error", pe)
		}
		return e
	}
	if out == nil || len(resp.Raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Raw, out); err != nil {
		return errs.Wrap(errs.CodeProviderUnavailable, "解析三方响应失败", err).
			WithDetail("platform", c.name).
			WithDetail("op", req.URL.Path)
	}
	return nil
}

// extractProviderError 尽力从响应体中提取平台错误描述，用于 details 排障。
// 只取错误信息字段，绝不外泄整个报文。
func extractProviderError(raw []byte) string {
	if len(raw) == 0 || len(raw) > 4096 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, k := range []string{"error", "errmsg", "errormsg", "message", "sub_msg", "error_description"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return fmt.Sprintf("%s: %s", k, s)
			}
		}
	}
	return ""
}

// Detach 返回一个脱离父级取消信号、但保留追踪上下文的 context。
//
// 用途（架构 §5.7 第 3 条）：Exchange / Refresh 属于"已发出即不可撤销"的调用。
// 若沿用入站 context，用户断网会导致请求被取消，而此时 code 可能已被平台消费——
// 结果就是"code 没了、token 也没拿到"。因此必须让它跑完并落库。
//
// 返回的 cancel 仍应被 defer 调用，避免 goroutine 与计时器泄漏。
func Detach(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = DefaultTotalTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// MaskURL 掩码 URL 中的敏感查询参数，用于日志与 trace attributes。
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	changed := false
	for _, k := range sensitiveParams {
		if _, ok := q[k]; ok {
			q.Set(k, "***")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

var sensitiveParams = []string{
	"access_token", "refresh_token", "id_token", "token",
	"secret", "appsecret", "app_secret", "client_secret",
	"code", "session_key", "sessionkey", "js_code", "password",
}
