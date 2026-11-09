package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// HTTPSender 通过 HTTP 把事件投递给登录中心的内部接口。
type HTTPSender struct {
	endpoint string
	token    string
	client   *http.Client
}

// HTTPSenderConfig 是发送器配置。
type HTTPSenderConfig struct {
	// Endpoint 是登录侧接收地址，例如
	// http://127.0.0.1:8080/internal/v1/usercenter/claim-invalidated
	Endpoint string
	// Token 是服务间令牌，放在 X-Service-Token 头里。
	Token string
	// Timeout 是单次投递超时。必须明显小于投递器的租约，否则会出现
	// "上一轮还没结束就被另一实例领走"。
	Timeout time.Duration
}

// NewHTTPSender 构造发送器。
func NewHTTPSender(cfg HTTPSenderConfig) *HTTPSender {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	return &HTTPSender{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		token:    cfg.Token,
		client:   &http.Client{Timeout: cfg.Timeout},
	}
}

// envelope 是投递报文。
//
// 用信封而不是直接把 payload 当 body：event_type 与 event_id 是投递层的信息
// （重试、对账、日志），payload 是业务语义。混在一起后，加第二个事件类型
// 就得改接收方的解析结构。
type envelope struct {
	EventID   string          `json:"event_id"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
}

// Send 投递一条事件。
//
// 失败分类（决定是否重试）：
//
//	2xx              成功
//	408 / 429 / 5xx  可重试：对端暂时不可用或限流
//	其它 4xx         永久失败：报文不合法 / 未知事件类型 / 鉴权失败，
//	                 重试一万次也不会成功，直接进死信让运维看见
func (s *HTTPSender) Send(ctx context.Context, rec postgres.OutboxRecord) error {
	body, err := json.Marshal(envelope{
		EventID:   fmt.Sprintf("%d", rec.ID),
		EventType: rec.EventType,
		Payload:   rec.Payload,
	})
	if err != nil {
		// 序列化失败是本地 bug，不是对端问题：重试也无解。
		return Permanent(fmt.Errorf("序列化事件失败: %w", err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return Permanent(fmt.Errorf("构造投递请求失败: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("X-Service-Token", s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// 网络错误：对端可能只是重启，必须重试。
		return fmt.Errorf("投递失败: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= 500:
		return fmt.Errorf("对端暂时不可用: HTTP %d", resp.StatusCode)
	default:
		return Permanent(fmt.Errorf("对端拒绝该事件: HTTP %d", resp.StatusCode))
	}
}
