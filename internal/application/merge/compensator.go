package merge

import (
	"context"
	"time"

	"go.uber.org/zap"

	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
)

// Compensator 是合并补偿循环（§7.3「补偿任务」）。
//
// 它扫的是 pending 与 failed：
//
//	pending  进程在"插入记录"与"调用远端"之间崩溃 → 这条永远没人推进。
//	         没有它，P0-3 的"先持久化保证可补偿"就只做了一半。
//	failed   远端或本地收敛失败，按幂等键重放即可（前提：用户中心真的幂等）。
//
// 滞后时间必须配告警：正常合并是秒级完成的，一条记录在 pending/failed
// 待超过几分钟就说明出了问题（用户中心挂了 / 幂等没生效）。
// 这条告警的数据源就是 merge_operations 的 updated_at，见管理端 D 组列表。
type Compensator struct {
	svc      *Service
	ops      mergeStore
	interval time.Duration
	batch    int
	logger   *zap.Logger
}

// mergeStore 只取需要的方法，避免补偿器依赖整个 Store 接口。
type mergeStore interface {
	ListDue(ctx context.Context, limit int) ([]*mergex.Operation, error)
}

// DefaultCompensateInterval 是扫描间隔。
//
// 30 秒而不是 outbox 那种 5 秒：合并是低频、重量级操作，
// 早 25 秒完成补偿对用户几乎没有感知，但会给用户中心带来无谓的请求。
const DefaultCompensateInterval = 30 * time.Second

// NewCompensator 构造补偿器。
func NewCompensator(svc *Service, ops mergeStore, logger *zap.Logger) *Compensator {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Compensator{
		svc:      svc,
		ops:      ops,
		interval: DefaultCompensateInterval,
		batch:    20,
		logger:   logger,
	}
}

// Run 启动循环，直到 ctx 结束。
func (c *Compensator) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	if n, err := c.RunOnce(ctx); err != nil && ctx.Err() == nil {
		c.logger.Warn("合并补偿首轮失败", zap.Error(err))
	} else if n > 0 {
		c.logger.Info("合并补偿首轮完成", zap.Int("count", n))
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := c.RunOnce(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				c.logger.Warn("合并补偿失败", zap.Error(err))
				continue
			}
			if n > 0 {
				c.logger.Info("合并补偿完成", zap.Int("count", n))
			}
		}
	}
}

// RunOnce 处理一批待补偿记录，返回处理条数。可单测直接调用。
func (c *Compensator) RunOnce(ctx context.Context) (int, error) {
	items, err := c.ops.ListDue(ctx, c.batch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, op := range items {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		if err := c.svc.Resume(ctx, op); err != nil {
			// 单条失败不影响其它记录；Resume 内部已回写状态。
			c.logger.Warn("合并补偿单条失败",
				zap.Int64("operation_id", op.ID), zap.Error(err))
			continue
		}
		done++
	}
	return done, nil
}
