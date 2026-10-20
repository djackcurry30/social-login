package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/event"
)

type staticTargets struct {
	t   *Target
	err error
}

func (s staticTargets) WebhookTarget(context.Context, int64) (*Target, error) {
	return s.t, s.err
}

func testEvent() *event.Event {
	return &event.Event{
		ID:            1,
		AppID:         7,
		EventID:       "01JEVENTID",
		Type:          event.TypeBindingCreated,
		SchemaVersion: 1,
		Payload:       map[string]any{"identity_id": 42},
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
	}
}

// TestSignatureIsVerifiable 固化 §5.4 的签名格式：
// t=<unix>,v1=<hex HMAC-SHA256(t + "." + body)>。
func TestSignatureIsVerifiable(t *testing.T) {
	body := []byte(`{"event_id":"e1"}`)
	got := Signature("s3cr3t", 1700000000, body)
	if !strings.HasPrefix(got, "t=1700000000,v1=") {
		t.Fatalf("签名头格式不符: %s", got)
	}
	if !VerifySignature("s3cr3t", got, body) {
		t.Fatal("自签自验应通过")
	}
	// 改一个字节就必须失败——否则签名没有意义。
	if VerifySignature("s3cr3t", got, []byte(`{"event_id":"e2"}`)) {
		t.Fatal("body 被篡改后验签必须失败")
	}
	if VerifySignature("other", got, body) {
		t.Fatal("密钥不同必须失败")
	}
}

// TestDeliverSignsAndPosts 验证发出去的请求头与事件体。
func TestDeliverSignsAndPosts(t *testing.T) {
	var gotSig, gotEventID, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Signature")
		gotEventID = r.Header.Get("X-Event-Id")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDeliverer(staticTargets{t: &Target{URL: srv.URL, Secret: "s3cr3t", AppCode: "biz_a"}}, nil)
	if err := d.Deliver(context.Background(), testEvent()); err != nil {
		t.Fatalf("投递应成功: %v", err)
	}

	if gotEventID != "01JEVENTID" {
		t.Fatalf("X-Event-Id 错误: %s", gotEventID)
	}
	if !VerifySignature("s3cr3t", gotSig, []byte(gotBody)) {
		t.Fatalf("签名无法验证: sig=%s body=%s", gotSig, gotBody)
	}

	var env map[string]any
	if err := json.Unmarshal([]byte(gotBody), &env); err != nil {
		t.Fatal(err)
	}
	// app_id 对外用 app_code：业务方认识自己的 code，不认识我们的自增 ID。
	if env["app_id"] != "biz_a" {
		t.Fatalf("app_id 应为 app_code，实际=%v", env["app_id"])
	}
	if env["event_type"] != event.TypeBindingCreated {
		t.Fatalf("event_type 错误: %v", env["event_type"])
	}
	if env["schema_version"] != float64(1) {
		t.Fatalf("schema_version 错误: %v", env["schema_version"])
	}
	if env["data"] == nil {
		t.Fatal("data 不应为空")
	}
}

// TestDeliverClassifiesStatusCodes 是本包的核心契约：
// 4xx（除 408/429）不可重试，5xx / 429 可重试。
func TestDeliverClassifiesStatusCodes(t *testing.T) {
	cases := []struct {
		code      int
		permanent bool
	}{
		{200, false},
		{204, false},
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{408, false}, // 明确要求稍后再来
		{429, false}, // 限流，应退避重试
		{500, false},
		{503, false},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
		}))
		d := NewDeliverer(staticTargets{t: &Target{URL: srv.URL, Secret: "k"}}, nil)
		err := d.Deliver(context.Background(), testEvent())
		srv.Close()

		if tc.permanent {
			if !event.IsPermanent(err) {
				t.Fatalf("HTTP %d 应判为永久失败，实际=%v", tc.code, err)
			}
			continue
		}
		if err != nil && event.IsPermanent(err) {
			t.Fatalf("HTTP %d 不应判为永久失败", tc.code)
		}
		if tc.code >= 300 && err == nil {
			t.Fatalf("HTTP %d 不应视为成功", tc.code)
		}
	}
}

// TestDeliverNoWebhook 确认"未配置"用哨兵表达，dispatcher 据此标 skipped。
func TestDeliverNoWebhook(t *testing.T) {
	d := NewDeliverer(staticTargets{err: event.ErrNoWebhook}, nil)
	err := d.Deliver(context.Background(), testEvent())
	if !errors.Is(err, event.ErrNoWebhook) {
		t.Fatalf("应返回 ErrNoWebhook，实际=%v", err)
	}
}

// TestDeliverEmptyURLIsNoWebhook 防止"配了记录但地址为空"被当成投递成功。
func TestDeliverEmptyURLIsNoWebhook(t *testing.T) {
	d := NewDeliverer(staticTargets{t: &Target{URL: ""}}, nil)
	if err := d.Deliver(context.Background(), testEvent()); !errors.Is(err, event.ErrNoWebhook) {
		t.Fatalf("空地址应视为未配置，实际=%v", err)
	}
}
