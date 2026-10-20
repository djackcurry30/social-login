package outbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/event"
)

// fakeStore 记录状态流转，便于断言"事件最后落在哪个状态"。
type fakeStore struct {
	items    []*event.Event
	sent     []int64
	retried  []retryCall
	dead     []deadCall
	skipped  []int64
	claimErr error
}

type retryCall struct {
	id       int64
	attempts int
	next     time.Time
	lastErr  string
}

type deadCall struct {
	id       int64
	attempts int
	lastErr  string
}

func (f *fakeStore) Append(context.Context, *event.Event) error { return nil }

func (f *fakeStore) ClaimDue(context.Context, int, time.Duration) ([]*event.Event, error) {
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	out := f.items
	f.items = nil
	return out, nil
}

func (f *fakeStore) MarkSent(_ context.Context, id int64) error {
	f.sent = append(f.sent, id)
	return nil
}

func (f *fakeStore) MarkRetry(_ context.Context, id int64, attempts int, next time.Time, lastErr string) error {
	f.retried = append(f.retried, retryCall{id: id, attempts: attempts, next: next, lastErr: lastErr})
	return nil
}

func (f *fakeStore) MarkDead(_ context.Context, id int64, attempts int, lastErr string) error {
	f.dead = append(f.dead, deadCall{id: id, attempts: attempts, lastErr: lastErr})
	return nil
}

func (f *fakeStore) MarkSkipped(_ context.Context, id int64, _ string) error {
	f.skipped = append(f.skipped, id)
	return nil
}

func (f *fakeStore) Get(context.Context, int64) (*event.Event, error) {
	return nil, event.ErrNotFound
}

func (f *fakeStore) List(context.Context, event.Filter) ([]*event.Event, int64, error) {
	return nil, 0, nil
}

func (f *fakeStore) Restore(context.Context, int64) error { return nil }
func (f *fakeStore) Discard(context.Context, int64, string) error {
	return nil
}

// fakeDeliverer 按预设结果返回。
type fakeDeliverer struct {
	err   error
	calls int
}

func (d *fakeDeliverer) Deliver(context.Context, *event.Event) error {
	d.calls++
	return d.err
}

func newTestService(store event.Store, d Deliverer) *Service {
	s := New(store, d, DefaultConfig(), nil)
	// 固定时间，避免退避计算依赖真实时钟导致断言不稳。
	s.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	return s
}

func TestDispatchSuccessMarksSent(t *testing.T) {
	store := &fakeStore{items: []*event.Event{{ID: 1, EventID: "e1", Type: event.TypeBindingCreated}}}
	d := &fakeDeliverer{}
	st, err := newTestService(store, d).DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(store.sent) != 1 || store.sent[0] != 1 {
		t.Fatalf("应标记 sent，实际=%v", store.sent)
	}
	if st.Sent != 1 {
		t.Fatalf("统计错误: %+v", st)
	}
}

// TestDispatchNoWebhookMarksSkipped 是"未配置投递地址"的处理：
// 必须落 skipped，既不能假装 sent（骗过监控），也不能反复重试到死信（伪装成故障）。
func TestDispatchNoWebhookMarksSkipped(t *testing.T) {
	store := &fakeStore{items: []*event.Event{{ID: 2, EventID: "e2"}}}
	d := &fakeDeliverer{err: event.ErrNoWebhook}

	if _, err := newTestService(store, d).DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.skipped) != 1 {
		t.Fatalf("应标记 skipped，实际=%v", store.skipped)
	}
	if len(store.retried) != 0 || len(store.dead) != 0 {
		t.Fatal("未配置地址不应重试或进入死信")
	}
}

// TestDispatchPermanentErrorGoesDeadImmediately：对方返回 4xx（非 408/429）时
// 重试没有意义，直接死信，避免浪费五次退避窗口。
func TestDispatchPermanentErrorGoesDeadImmediately(t *testing.T) {
	store := &fakeStore{items: []*event.Event{{ID: 3, EventID: "e3"}}}
	d := &fakeDeliverer{err: &event.PermanentError{StatusCode: 400, Body: "bad request"}}

	if _, err := newTestService(store, d).DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.dead) != 1 {
		t.Fatalf("应直接死信，实际 dead=%v retried=%v", store.dead, store.retried)
	}
	if len(store.retried) != 0 {
		t.Fatal("永久失败不应安排重试")
	}
}

// TestDispatchRetryableSchedulesBackoff 验证退避序列取到正确档位（1s）。
func TestDispatchRetryableSchedulesBackoff(t *testing.T) {
	store := &fakeStore{items: []*event.Event{{ID: 4, EventID: "e4", Attempts: 0}}}
	d := &fakeDeliverer{err: errors.New("connection reset")}

	if _, err := newTestService(store, d).DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.retried) != 1 {
		t.Fatalf("应安排重试，实际=%v", store.retried)
	}
	got := store.retried[0]
	if got.attempts != 1 {
		t.Fatalf("attempts 应为 1，实际=%d", got.attempts)
	}
	want := time.Unix(1700000000, 0).UTC().Add(time.Second)
	if !got.next.Equal(want) {
		t.Fatalf("下次重试时间应为 %v，实际 %v", want, got.next)
	}
}

// TestDispatchMaxAttemptsGoesDead：第 5 次失败后转死信，不再重试。
func TestDispatchMaxAttemptsGoesDead(t *testing.T) {
	store := &fakeStore{items: []*event.Event{
		{ID: 5, EventID: "e5", Attempts: event.MaxAttempts - 1},
	}}
	d := &fakeDeliverer{err: errors.New("timeout")}

	if _, err := newTestService(store, d).DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.dead) != 1 {
		t.Fatalf("达到最大次数应转死信，实际 retried=%v dead=%v", store.retried, store.dead)
	}
	if store.dead[0].attempts != event.MaxAttempts {
		t.Fatalf("attempts 应为 %d，实际=%d", event.MaxAttempts, store.dead[0].attempts)
	}
}

// TestBackoffSchedule 固化 §5.4 的退避序列字面值。
// 业务方按文档实现重试对齐，这里一旦漂移就是契约破坏。
func TestBackoffSchedule(t *testing.T) {
	want := []time.Duration{time.Second, 10 * time.Second, time.Minute, 10 * time.Minute, time.Hour}
	for i, w := range want {
		if got := event.Backoff(i + 1); got != w {
			t.Fatalf("第 %d 次退避应为 %v，实际 %v", i+1, w, got)
		}
	}
	// 超出序列时取最后一档（由 MaxAttempts 兜底转死信）。
	if got := event.Backoff(99); got != time.Hour {
		t.Fatalf("超出序列应取 1h，实际 %v", got)
	}
}

// TestDispatchEmptyBatch 确认没有到期事件时不产生任何状态变更。
func TestDispatchEmptyBatch(t *testing.T) {
	store := &fakeStore{}
	d := &fakeDeliverer{}
	st, err := newTestService(store, d).DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Claimed != 0 || d.calls != 0 {
		t.Fatalf("空批次不应投递: %+v", st)
	}
}

// TestDispatchClaimErrorPropagates 记录领取失败要让 Run 记日志而不是静默。
func TestDispatchClaimErrorPropagates(t *testing.T) {
	store := &fakeStore{claimErr: errors.New("db down")}
	if _, err := newTestService(store, &fakeDeliverer{}).DispatchOnce(context.Background()); err == nil {
		t.Fatal("领取失败应返回错误")
	}
}
