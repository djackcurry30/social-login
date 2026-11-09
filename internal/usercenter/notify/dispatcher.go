// Package notify 把用户中心的出站事件投递给登录中心（目前只有 claim.invalidated）。
//
// 为什么是"投递器 + outbox"而不是在业务事务里直接发 HTTP：
//
//	换绑与注销是已经发生的事实。推送失败就丢了的话，登录侧会一直用过期
//	claim 做归并判定，直到某次人工对账才发现——而"漏了一次通知"在生产上
//	没有任何告警可依。outbox 把"要通知什么"变成一条可重试的记录，
//	代价只是一张表和一个后台循环。
//
// 投递语义是【至少一次 + 接收方幂等】：
//
//	租约到期会重投、进程崩溃会重投、接收方超时但实际处理成功也会重投。
//	因此接收端必须做成"重复执行无副作用"（撤销已撤销的 claim 本来就是 no-op），
//	而不是试图在发送端保证恰好一次——后者需要分布式事务，代价远大于收益。
package notify

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// Store 是投递器需要的持久化能力（窄接口，便于单测替身）。
type Store interface {
	ClaimDueOutbox(ctx context.Context, limit int, lease time.Duration) ([]postgres.OutboxRecord, error)
	MarkOutboxSent(ctx context.Context, id int64) error
	MarkOutboxFailed(ctx context.Context, id int64, reason string, next time.Time, dead bool) error
}

// Sender 投递一条事件。
//
// 返回的 error 需要能区分"可重试"与"永久失败"：
// 对端 5xx / 网络错误该重试；400（事件体不合法）重试一万次也不会成功。
// 用 Permanent 包装表达后者。
type Sender interface {
	Send(ctx context.Context, rec postgres.OutboxRecord) error
}

// PermanentError 表示重试没有意义的失败。
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return "永久失败: " + e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent 把错误标记为不可重试。
func Permanent(err error) error { return &PermanentError{Err: err} }

// Metrics 是投递器的计数器（nil 安全）。
type Metrics interface {
	RecordOutboxSent()
	RecordOutboxFailed(retryable bool)
}

// Config 是投递器参数。
type Config struct {
	// Interval 是扫描间隔。默认 5s。
	Interval time.Duration
	// Batch 是每次最多领取几条。默认 20。
	Batch int
	// Lease 是领取后的租约：进程崩溃时事件在这段时间后重新可投。
	// 必须明显大于单次投递超时，否则会在上一轮还没结束时被另一实例领走。
	Lease time.Duration
	// BaseBackoff / MaxBackoff 控制失败后的重试间隔（指数退避）。
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// MaxAttempts 之后进死信。默认 10（按默认退避约 2 小时窗口）。
	MaxAttempts int
	// Now 可注入，便于测试退避计算。
	Now func() time.Time
}

// Dispatcher 是投递循环。
type Dispatcher struct {
	deps Deps
	cfg  Config
}

// Deps 是投递器依赖。
type Deps struct {
	Store   Store
	Sender  Sender
	Log     *zap.Logger
	Metrics Metrics
}

// New 构造投递器。
func New(d Deps, cfg Config) *Dispatcher {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 20
	}
	if cfg.Lease <= 0 {
		cfg.Lease = time.Minute
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 5 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = time.Hour
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 10
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.Log == nil {
		d.Log = zap.NewNop()
	}
	return &Dispatcher{deps: d, cfg: cfg}
}

// Run 持续投递，直到 ctx 结束。
func (d *Dispatcher) Run(ctx context.Context) {
	t := time.NewTicker(d.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := d.DispatchOnce(ctx); err != nil && ctx.Err() == nil {
				d.deps.Log.Warn("出站事件投递轮次失败", zap.Error(err))
			}
		}
	}
}

// DispatchOnce 投递一轮，返回本轮投递成功条数（单测直接调用）。
//
// 单条失败不影响其它条：一条永久坏掉的事件不应该阻塞后面的换绑通知。
func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	records, err := d.deps.Store.ClaimDueOutbox(ctx, d.cfg.Batch, d.cfg.Lease)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, rec := range records {
		if ctx.Err() != nil {
			// 退出中：本次没投的事件保持 pending，租约到期后重来。
			return sent, ctx.Err()
		}
		if err := d.deps.Sender.Send(ctx, rec); err != nil {
			d.fail(ctx, rec, err)
			continue
		}
		if err := d.deps.Store.MarkOutboxSent(ctx, rec.ID); err != nil {
			// 已经发出去了但标记失败：下轮会重投。接收方幂等，所以这是
			// "多发一次"而不是"丢一次"——方向是对的，只记日志。
			d.deps.Log.Error("出站事件已投递但标记失败，下轮将重发",
				zap.Int64("outbox_id", rec.ID), zap.Error(err))
			continue
		}
		sent++
		if d.deps.Metrics != nil {
			d.deps.Metrics.RecordOutboxSent()
		}
	}
	return sent, nil
}

// fail 处理一次投递失败：算退避、判死信、回写。
func (d *Dispatcher) fail(ctx context.Context, rec postgres.OutboxRecord, cause error) {
	var perm *PermanentError
	permanent := errors.As(cause, &perm)
	dead := permanent || rec.Attempts >= d.cfg.MaxAttempts

	next := d.cfg.Now()
	if !dead {
		next = next.Add(d.backoff(rec.Attempts))
	}

	if err := d.deps.Store.MarkOutboxFailed(ctx, rec.ID, cause.Error(), next, dead); err != nil {
		// 连"记下失败"都失败，只能靠租约到期后重领；日志必须够醒目。
		d.deps.Log.Error("出站事件失败状态回写失败",
			zap.Int64("outbox_id", rec.ID), zap.Error(err), zap.Error(cause))
	}

	if d.deps.Metrics != nil {
		d.deps.Metrics.RecordOutboxFailed(!dead)
	}
	fields := []zap.Field{
		zap.Int64("outbox_id", rec.ID),
		zap.String("event_type", rec.EventType),
		zap.Int("attempts", rec.Attempts),
		zap.Bool("dead", dead),
		zap.Error(cause),
	}
	if dead {
		// 死信意味着登录侧永久不知道这次变更——这是需要人介入的事件，
		// 用 Error 级别（会进告警），不是 Warn。
		d.deps.Log.Error("出站事件进入死信：登录侧将保留过期 claim", fields...)
		return
	}
	d.deps.Log.Warn("出站事件投递失败，稍后重试",
		append(fields, zap.Time("next_attempt_at", next))...)
}

// backoff 计算第 attempts 次失败后的等待时间：base * 2^(attempts-1)，上限 MaxBackoff。
//
// 指数退避而不是固定间隔：对端整体故障时，固定 5s 的 10 次重试只覆盖 50 秒，
// 之后就是死信；指数退避能把同样 10 次铺到约两小时，覆盖一次常规发布或重启。
func (d *Dispatcher) backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	dur := d.cfg.BaseBackoff
	for i := 1; i < attempts; i++ {
		dur *= 2
		if dur >= d.cfg.MaxBackoff {
			return d.cfg.MaxBackoff
		}
	}
	if dur > d.cfg.MaxBackoff {
		return d.cfg.MaxBackoff
	}
	return dur
}
