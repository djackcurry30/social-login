package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// 这组用例守的是"通知不会静默丢失"：重试、退避、死信与单条隔离。
// 没有它们，outbox 就只是"多了一张表"。

type fakeStore struct {
	due     []postgres.OutboxRecord
	claimed bool
	sent    []int64
	failed  []failure
}

type failure struct {
	id   int64
	next time.Time
	dead bool
}

func (f *fakeStore) ClaimDueOutbox(context.Context, int, time.Duration) ([]postgres.OutboxRecord, error) {
	if f.claimed {
		// 第二轮没有到期事件：模拟"投递完就空了"。
		return nil, nil
	}
	f.claimed = true
	return f.due, nil
}

func (f *fakeStore) MarkOutboxSent(_ context.Context, id int64) error {
	f.sent = append(f.sent, id)
	return nil
}

func (f *fakeStore) MarkOutboxFailed(_ context.Context, id int64, _ string, next time.Time, dead bool) error {
	f.failed = append(f.failed, failure{id: id, next: next, dead: dead})
	return nil
}

type fakeSender struct {
	errs map[int64]error
}

func (s *fakeSender) Send(_ context.Context, rec postgres.OutboxRecord) error {
	return s.errs[rec.ID]
}

func fixedNow() time.Time { return time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC) }

func newDispatcher(st *fakeStore, se Sender, maxAttempts int) *Dispatcher {
	return New(Deps{Store: st, Sender: se}, Config{
		Now:         fixedNow,
		BaseBackoff: 5 * time.Second,
		MaxBackoff:  time.Hour,
		MaxAttempts: maxAttempts,
	})
}

func TestDispatchMarksSent(t *testing.T) {
	st := &fakeStore{due: []postgres.OutboxRecord{{ID: 7, EventType: "claim.invalidated"}}}
	d := newDispatcher(st, &fakeSender{}, 10)

	n, err := d.DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	if n != 1 || len(st.sent) != 1 || st.sent[0] != 7 {
		t.Fatalf("应标记一条已发送，实际 sent=%v n=%d", st.sent, n)
	}
	if len(st.failed) != 0 {
		t.Fatalf("成功不应记失败: %+v", st.failed)
	}
}

// TestDispatchRetryableBacksOff 验证失败后按指数退避安排下一次，
// 而不是立刻重试——对端整体故障时立刻重试只会把重试预算烧光。
func TestDispatchRetryableBacksOff(t *testing.T) {
	st := &fakeStore{due: []postgres.OutboxRecord{{ID: 3, Attempts: 3}}}
	d := newDispatcher(st, &fakeSender{errs: map[int64]error{3: errors.New("连接被拒绝")}}, 10)
	d.cfg.BaseBackoff = time.Second

	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("轮次不应报错: %v", err)
	}
	if len(st.failed) != 1 {
		t.Fatalf("应记一次失败，实际 %+v", st.failed)
	}
	f := st.failed[0]
	if f.dead {
		t.Fatal("可重试错误不应直接进死信")
	}
	// attempts=3 → 1s * 2^(3-1) = 4s
	if got := f.next.Sub(fixedNow()); got != 4*time.Second {
		t.Fatalf("退避应为 4s，实际 %s", got)
	}
}

// TestDispatchPermanentGoesDeadImmediately 验证"重试没有意义的失败"立刻进死信。
//
// 典型场景：事件体不合法、未知事件类型、令牌错误。重试一万次也不会成功，
// 而留在 pending 会一直占着投递队列并被反复计入积压指标。
func TestDispatchPermanentGoesDeadImmediately(t *testing.T) {
	st := &fakeStore{due: []postgres.OutboxRecord{{ID: 5, Attempts: 1}}}
	d := newDispatcher(st, &fakeSender{errs: map[int64]error{5: Permanent(errors.New("HTTP 400"))}}, 10)

	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("轮次不应报错: %v", err)
	}
	if len(st.failed) != 1 || !st.failed[0].dead {
		t.Fatalf("永久失败应进死信，实际 %+v", st.failed)
	}
}

// TestDispatchMaxAttemptsGoesDead 验证可重试错误在达到上限后也不再重试。
func TestDispatchMaxAttemptsGoesDead(t *testing.T) {
	st := &fakeStore{due: []postgres.OutboxRecord{{ID: 9, Attempts: 3}}}
	d := newDispatcher(st, &fakeSender{errs: map[int64]error{9: errors.New("超时")}}, 3)

	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("轮次不应报错: %v", err)
	}
	if len(st.failed) != 1 || !st.failed[0].dead {
		t.Fatalf("达到最大次数应进死信，实际 %+v", st.failed)
	}
}

// TestDispatchOneFailureDoesNotBlockOthers 验证单条坏事件不阻塞后面的通知。
//
// 这条比看起来重要：一条永久失败的事件如果让整批中断，后面所有用户的
// 换绑通知都会卡在它后面，而告警只会显示"投递失败一条"。
func TestDispatchOneFailureDoesNotBlockOthers(t *testing.T) {
	st := &fakeStore{due: []postgres.OutboxRecord{{ID: 1}, {ID: 2}, {ID: 3}}}
	se := &fakeSender{errs: map[int64]error{1: errors.New("对端 502")}}
	d := newDispatcher(st, se, 10)

	n, err := d.DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("轮次不应报错: %v", err)
	}
	if n != 2 {
		t.Fatalf("应成功 2 条（1 条失败不阻塞），实际 %d", n)
	}
	if len(st.failed) != 1 || st.failed[0].id != 1 {
		t.Fatalf("失败记录不符: %+v", st.failed)
	}
}

// TestBackoffCapsAtMax 验证退避不会无限增长（否则第 10 次要等到天荒地老）。
func TestBackoffCapsAtMax(t *testing.T) {
	d := New(Deps{Store: &fakeStore{}, Sender: &fakeSender{}}, Config{
		BaseBackoff: 5 * time.Second,
		MaxBackoff:  time.Minute,
	})
	if got := d.backoff(10); got != time.Minute {
		t.Fatalf("应封顶到 1m，实际 %s", got)
	}
	if got := d.backoff(1); got != 5*time.Second {
		t.Fatalf("第一次应为 5s，实际 %s", got)
	}
}
