package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// RemoteKEK 通过 HTTP 调用外部 KMS 来包装/解包 DEK。
//
// 为什么是"一层 HTTP 契约"而不是直接引各云厂商的 SDK：
// 本服务只需要两个动作（wrap / unwrap），而这个形状在 AWS KMS（Encrypt/Decrypt）、
// 阿里云 KMS（Encrypt/Decrypt）、Vault Transit（encrypt/decrypt）、HashiCorp 或
// 自建密钥服务上都能一对一映射。接 SDK 意味着把某个厂商的类型、重试策略、
// 依赖树带进登录服务，而真正要验的只是"这两个动作对不对"。
//
// 生产部署时在 KMS 前放一层薄网关（或在 sidecar 里做），把厂商 API 映射成
// 下面这份契约即可：
//
//	POST {base}/v1/wrap
//	  {"key_id":"kek-2026-11","plaintext":"<base64 DEK>"}
//	  → 200 {"wrapped":"<base64>"}
//
//	POST {base}/v1/unwrap
//	  {"key_id":"kek-2026-11","wrapped":"<base64>"}
//	  → 200 {"plaintext":"<base64 DEK>"}
//
//	鉴权：Authorization: Bearer <token>（可选，内网部署可省）
//
// ⚠️ 这条链路必须走内网或 mTLS：能调 wrap/unwrap 的人等于能解开全部凭据。
type RemoteKEK struct {
	baseURL string
	keyID   string
	token   string
	client  *http.Client
	timeout time.Duration
}

// RemoteKEKConfig 是 RemoteKEK 的构造参数。
type RemoteKEKConfig struct {
	BaseURL string
	KeyID   string
	Token   string
	Timeout time.Duration
	// HTTPClient 留空时用内置客户端（不复用默认 Transport 的连接池语义）。
	HTTPClient *http.Client
}

var _ KEK = (*RemoteKEK)(nil)

// NewRemoteKEK 构造 KMS 客户端。
func NewRemoteKEK(cfg RemoteKEKConfig) (*RemoteKEK, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "KMS 地址不能为空")
	}
	if cfg.KeyID == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "KMS 密钥标识（key_id）不能为空")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultKMSTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}
	return &RemoteKEK{
		baseURL: base,
		keyID:   cfg.KeyID,
		token:   cfg.Token,
		client:  client,
		timeout: cfg.Timeout,
	}, nil
}

// KeyID 实现 KEK。
func (k *RemoteKEK) KeyID() string { return k.keyID }

// Wrap 调用 KMS 包装 DEK。
func (k *RemoteKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, errs.New(errs.CodeInternal, "待包装的数据密钥为空")
	}
	var out struct {
		Wrapped string `json:"wrapped"`
	}
	if err := k.post(ctx, "/v1/wrap", map[string]string{
		"key_id":    k.keyID,
		"plaintext": base64.StdEncoding.EncodeToString(dek),
	}, &out); err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(out.Wrapped)
	if err != nil || len(wrapped) == 0 {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "KMS 返回的 wrapped 不是合法的 Base64 或为空")
	}
	return wrapped, nil
}

// Unwrap 调用 KMS 还原 DEK。
func (k *RemoteKEK) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "待解包的数据密钥为空")
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := k.post(ctx, "/v1/unwrap", map[string]string{
		"key_id":  k.keyID,
		"wrapped": base64.StdEncoding.EncodeToString(wrapped),
	}, &out); err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "KMS 返回的 plaintext 不是合法的 Base64")
	}
	if len(dek) != DEKSize {
		// 长度不对必须拒绝：拿一个截断的密钥去解数据会得到"解密失败"，
		// 而失败点离真正的原因（KMS 返回了别的东西）很远。
		return nil, errs.Newf(errs.CodeAuthInvalidConfig,
			"KMS 返回的数据密钥长度应为 %d 字节，实际 %d", DEKSize, len(dek))
	}
	return dek, nil
}

func (k *RemoteKEK) post(ctx context.Context, path string, body any, out any) error {
	callCtx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()

	buf, err := json.Marshal(body)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "序列化 KMS 请求失败", err)
	}
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, k.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "构造 KMS 请求失败", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		// 超时/连接失败：可重试。文案要指向"KMS 不可用"，而不是"凭据解密失败"——
		// 后者会让运维去查凭据内容，方向完全错。
		return errs.Wrap(errs.CodeInternal, "调用 KMS 失败（检查网络与地址）", err).
			WithRetryable(true).
			WithDetail("kms_path", path)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		retryable := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return errs.Newf(errs.CodeInternal, "KMS 返回 %d: %s", resp.StatusCode, msg).
			WithRetryable(retryable).
			WithDetail("kms_path", path)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errs.Wrap(errs.CodeAuthInvalidConfig, "KMS 响应不是合法 JSON", err)
	}
	return nil
}

// String 便于日志里显示（不打印 token）。
func (k *RemoteKEK) String() string {
	return fmt.Sprintf("kms(%s,key=%s)", k.baseURL, k.keyID)
}
