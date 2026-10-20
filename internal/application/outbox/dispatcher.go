// Package outbox 是 Webhook 事件的投递调度（Transactional Outbox 的出站侧）。
//
// 职责边界：
//   - 存储与并发（租约领取）由 event.Store 负责
//   - 签名与 HTTP 由投递器负责
//   - 这里只做状态机：成功 → sent；未配置 → skipped；对方拒收 → dead；
//     临时故障 → 按 §5.4 的固定退避序列重试，5 次后转死信
//
// 为什么不在这里重试 HTTP：C6 规定"不重试三方渠道同步调用"，但那是针对
// 用户授权链路（重试单位是整个授权流程，不是单个请求）。事件投递是纯出站、
// 幂等（业务方按 event_id 去重），因此这里必须重试——两者不矛盾。
package outbox

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/event"
)

// Deliverer 是投递端口（实现见 infrastructure/webhook）。
type Deliverer interface {
	Deliver(ctx context.Context, e *event.Event) error
}

// Config 是调度参数。
type Config struct {
	// Batch 是单轮最多领取的事件数。
	Batch int
	// Interval 是轮询间隔。事件是旁路，不需要毫秒级实时。
	Interval time.Duration
	// Lease 是领取后的占位时长。必须显著大于单次投递超时，
	// 否则事件会在投递完成前被其它副本重复领取。
	Lease time.Duration
}

// DefaultConfig 返回默认参数。
func DefaultConfig() Config {
	return Config{
		Batch:    20,
		Interval: 5 * time.Second,
		Lease:    2 * time.Minute,
	}
}

// Stats 是一轮的统计，便于日志与指标。
type Stats struct {
	Claimed int
	Sent    int
	Retried int
	Dead    int
	Skipped int
	Failed  int
}

// Service 是投递调度器。
type Service struct {
	store     event.Store
	deliverer Deliverer
	cfg       Config
	logger    *zap.Logger
	now       func() time.Time
}

// New 构造调度器。
func New(store event.Store, d Deliverer, cfg Config, logger *zap.Logger) *Service {
	if cfg.Batch <= 0 {
		cfg.Batch = 20
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 2 * time.Minute
	}
	if logger == nil {
		// 单测与最小装配不该因为少传 logger 就 panic：
		// 日志是观测手段，不能成为运行前提。
		logger = zap.NewNop()
	}
	return &Service{store: store, deliverer: d, cfg: cfg, logger: logger, now: time.Now}
}

// Run 启动循环，直到 ctx 结束。
//
// 单轮失败（数据库抖动）只记日志，不能让 worker 退出——否则一次抖动就永久
// 停止投递，积压会一直涨到人工重启。
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	// 启动即跑一轮：重启后不必等一个 tick 才开始消费积压。
	if _, err := s.DispatchOnce(ctx); err != nil && ctx.Err() == nil {
		s.warn("outbox 首轮投递失败", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.DispatchOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.warn("outbox 投递失败", err)
			}
		}
	}
}

// DispatchOnce 处理一批到期事件。可单测直接调用。
func (s *Service) DispatchOnce(ctx context.Context) (Stats, error) {
	var st Stats
	items, err := s.store.ClaimDue(ctx, s.cfg.Batch, s.cfg.Lease)
	if err != nil {
		return st, err
	}
	st.Claimed = len(items)

	for _, e := range items {
		if ctx.Err() != nil {
			// 优雅退出：已领取的事件靠租约自动回到队列，不会丢。
			return st, ctx.Err()
		}
		if err := s.deliverOne(ctx, e); err != nil {
			st.Failed++
			// 单条状态回写失败不影响其它事件，但要留痕。
			s.warn("回写事件状态失败", err, zap.Int64("id", e.ID))
			continue
		}
		switch e.Status {
		case event.StatusSent:
			st.Sent++
		case event.StatusSkipped:
			st.Skipped++
		case event.StatusDead:
			st.Dead++
		default:
			st.Retried++
		}
	}

	if st.Claimed > 0 {
		s.logger.Info("outbox 投递批次完成",
			zap.Int("claimed", st.Claimed), zap.Int("sent", st.Sent),
			zap.Int("retried", st.Retried), zap.Int("dead", st.Dead),
			zap.Int("skipped", st.Skipped), zap.Int("failed", st.Failed))
	}
	return st, nil
}

// deliverOne 投递并推进状态。返回的错误只表示【状态回写失败】，
// 投递本身的失败会体现在 e.Status 上。
func (s *Service) deliverOne(ctx context.Context, e *event.Event) error {
	attempts := e.Attempts + 1

	err := s.deliverer.Deliver(ctx, e)
	switch {
	case err == nil:
		e.Status = event.StatusSent
		return s.store.MarkSent(ctx, e.ID)

	case errors.Is(err, event.ErrNoWebhook):
		// "没配地址"是配置状态，不是故障：标 skipped，不要重试到死信。
		e.Status = event.StatusSkipped
		return s.store.MarkSkipped(ctx, e.ID, "应用未配置 webhook_url")

	case event.IsPermanent(err):
		// 对方明确拒收（4xx），重试无意义，直接死信。
		e.Status = event.StatusDead
		e.Attempts = attempts
		e.LastError = err.Error()
		return s.store.MarkDead(ctx, e.ID, attempts, err.Error())

	case attempts >= event.MaxAttempts:
		e.Status = event.StatusDead
		e.Attempts = attempts
		e.LastError = err.Error()
		return s.store.MarkDead(ctx, e.ID, attempts, err.Error())

	default:
		next := s.now().UTC().Add(event.Backoff(attempts))
		e.Status = event.StatusPending
		e.Attempts = attempts
		e.LastError = err.Error()
		return s.store.MarkRetry(ctx, e.ID, attempts, next, err.Error())
	}
}

func (s *Service) warn(msg string, err error, fields ...zap.Field) {
	if s.logger == nil {
		return
	}
	s.logger.Warn(msg, append(fields, zap.Error(err))...)
}
