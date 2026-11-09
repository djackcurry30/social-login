package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// 这组用例守的是"重试策略与对端语义一致"：
// 把 4xx 当可重试会让一条坏事件永久占着队列；把 5xx 当永久失败会丢通知。

func sendTo(t *testing.T, h http.HandlerFunc, rec postgres.OutboxRecord) error {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	s := NewHTTPSender(HTTPSenderConfig{Endpoint: srv.URL, Token: "tok"})
	return s.Send(context.Background(), rec)
}

func TestSendSuccess(t *testing.T) {
	var gotToken string
	var body map[string]json.RawMessage
	err := sendTo(t, func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Service-Token")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.WriteHeader(http.StatusOK)
	}, postgres.OutboxRecord{ID: 11, EventType: "claim.invalidated", Payload: []byte(`{"user_id":"u1"}`)})
	if err != nil {
		t.Fatalf("成功投递不应报错: %v", err)
	}
	if gotToken != "tok" {
		t.Fatalf("应带服务令牌，实际 %q", gotToken)
	}
	// 信封必须带 event_id 与 event_type：接收方靠它们做日志关联与分支。
	if string(body["event_id"]) != `"11"` || string(body["event_type"]) != `"claim.invalidated"` {
		t.Fatalf("信封字段不符: %s", body)
	}
	if string(body["payload"]) != `{"user_id":"u1"}` {
		t.Fatalf("payload 应原样透传: %s", body["payload"])
	}
}

func TestSendServerErrorIsRetryable(t *testing.T) {
	err := sendTo(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}, postgres.OutboxRecord{ID: 1})
	if err == nil {
		t.Fatal("5xx 必须报错以便重试")
	}
	var perm *PermanentError
	if errors.As(err, &perm) {
		t.Fatal("5xx 不应被判定为永久失败")
	}
}

func TestSendClientErrorIsPermanent(t *testing.T) {
	// 400 / 401 / 404 都意味着"重试无解"：报文、令牌或应用本身有问题。
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound} {
		err := sendTo(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}, postgres.OutboxRecord{ID: 1})
		var perm *PermanentError
		if !errors.As(err, &perm) {
			t.Fatalf("HTTP %d 应判定为永久失败，实际 %v", code, err)
		}
	}
}

func TestSendSemanticFailureKeepsEnvelope(t *testing.T) {
	// 429 是"现在别来"，不是"永远别来"——必须重试，否则限流期间的通知全丢。
	err := sendTo(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}, postgres.OutboxRecord{ID: 1})
	var perm *PermanentError
	if errors.As(err, &perm) {
		t.Fatal("429 不应判定为永久失败")
	}
}
