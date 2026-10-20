// Package webhook 实现 Webhook 事件的出站投递（架构 §5.4）。
//
// 只做三件事：取投递目标、签名、发出去并分类结果。重试策略与状态流转不在这里，
// 由 outbox 的 dispatcher 决定——投递器返回"可重试 / 永久失败 / 未配置"三类信号。
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// Target 是一次投递的目标配置。
type Target struct {
	URL     string
	Secret  string
	AppCode string
}

// TargetReader 读取应用的投递目标（含解密后的签名密钥）。
type TargetReader interface {
	WebhookTarget(ctx context.Context, appID int64) (*Target, error)
}

// Deliverer 是事件投递器。
type Deliverer struct {
	targets TargetReader
	http    *httpx.Client
	logger  *zap.Logger
	now     func() time.Time
}

// NewDeliverer 构造投递器。
func NewDeliverer(targets TargetReader, logger *zap.Logger) *Deliverer {
	return &Deliverer{
		targets: targets,
		http: httpx.New(httpx.Config{
			Name: "webhook",
			// 业务方接收端点通常很轻，5s 足够；超时按可重试处理。
			TotalTimeout: 5 * time.Second,
			Logger:       logger,
		}),
		logger: logger,
		now:    time.Now,
	}
}

// envelope 是 §5.4 规定的事件体。
type envelope struct {
	EventID       string         `json:"event_id"`
	SchemaVersion int            `json:"schema_version"`
	EventType     string         `json:"event_type"`
	AppID         string         `json:"app_id"`
	OccurredAt    string         `json:"occurred_at"`
	Data          map[string]any `json:"data"`
}

// Deliver 投递一条事件。
//
// 返回值语义：nil 成功；ErrNoWebhook 未配置；*PermanentError 不可重试；其它可重试。
func (d *Deliverer) Deliver(ctx context.Context, e *event.Event) error {
	if e == nil {
		return nil
	}
	t, err := d.targets.WebhookTarget(ctx, e.AppID)
	if err != nil {
		if errors.Is(err, event.ErrNoWebhook) {
			return event.ErrNoWebhook
		}
		// 读配置失败（数据库抖动等）按可重试处理：换一次可能就好了。
		return fmt.Errorf("读取投递目标失败: %w", err)
	}
	if t == nil || t.URL == "" {
		return event.ErrNoWebhook
	}

	body, err := json.Marshal(envelope{
		EventID:       e.EventID,
		SchemaVersion: e.SchemaVersion,
		EventType:     e.Type,
		AppID:         t.AppCode,
		OccurredAt:    e.CreatedAt.UTC().Format(time.RFC3339Nano),
		Data:          e.Payload,
	})
	if err != nil {
		// 序列化失败是代码问题，重试无意义。
		return &event.PermanentError{StatusCode: 0, Body: "事件体序列化失败: " + err.Error()}
	}

	ts := d.now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return &event.PermanentError{StatusCode: 0, Body: "构造请求失败: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "social-login-webhook/1")
	// 业务方按它做幂等（至少一次语义，可能重复）。
	req.Header.Set("X-Event-Id", e.EventID)
	req.Header.Set("X-Event-Type", e.Type)
	req.Header.Set("X-Signature", Signature(t.Secret, ts, body))

	resp, err := d.http.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("投递失败: %w", err)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests:
		// 对方明确说"稍后再来"，属于可重试。
		return fmt.Errorf("对方要求稍后重试（HTTP %d）", resp.StatusCode)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return &event.PermanentError{StatusCode: resp.StatusCode, Body: truncate(resp.Raw, 300)}
	default:
		return fmt.Errorf("对方返回 HTTP %d", resp.StatusCode)
	}
}

// Signature 生成 §5.4 的签名头值：t=<unix>,v1=<hex(HMAC-SHA256(t + "." + body))>。
//
// 为什么签 "t.body" 而不是只签 body：时间戳也纳入签名，业务方才能据此拒绝
// 重放（比如超过 5 分钟的直接丢弃）。只签 body 的话时间戳可被随意替换。
func Signature(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

// VerifySignature 供单测与文档示例使用：业务方按同样规则校验。
//
// 生产代码不调用它——验签发生在业务方那一侧。
func VerifySignature(secret, header string, body []byte) bool {
	var tsStr, sig string
	for _, part := range splitComma(header) {
		if len(part) > 2 && part[:2] == "t=" {
			tsStr = part[2:]
		} else if len(part) > 3 && part[:3] == "v1=" {
			sig = part[3:]
		}
	}
	if tsStr == "" || sig == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// truncate 截断响应体，避免把整页 HTML 写进 last_error。
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
