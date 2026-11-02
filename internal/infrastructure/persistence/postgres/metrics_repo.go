package postgres

import (
	"context"

	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// metrics_repo.go 集中放"只服务指标采集"的聚合查询。
//
// 为什么单独成文件而不塞进各自的仓储：
//
//	这些查询的共同点是【全表聚合、不看单条】——它们不属于任何业务用例的
//	语义（没人会在登录链路上问"outbox 里死信有多少条"），放进去只会让
//	业务仓储为运维需求背债。放在一起还能一眼看出"为了观测，我们在数据库上
//	多做了哪些扫描"。

// OutboxBacklog 按状态统计待投递/死信数量。
//
// 四个状态一次查完（GROUP BY），而不是四次 COUNT：
// 这是每 15s 被 Prometheus 调一次的查询，四次往返没有必要。
func (r *EventRepository) OutboxBacklog(ctx context.Context) (map[string]int64, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	type row struct {
		Status string
		N      int64
	}
	var rows []row
	err := r.db.WithContext(ctx).
		Model(&eventOutboxModel{}).
		Select("status, count(*) AS n").
		Group("status").
		Scan(&rows).Error
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "统计事件积压失败", err)
	}
	out := make(map[string]int64, len(rows))
	for _, x := range rows {
		out[x.Status] = x.N
	}
	return out, nil
}

// OldestPendingSeconds 返回最久未推进的合并操作已等待的秒数。
//
// 这是 §11 要求的 merge_compensation_lag_seconds 的数据源。
// 语义是"积压里最老的那条等了多久"，而不是平均值：
// 平均值会被大量秒级完成的操作稀释，掩盖住那一条卡了半小时的。
//
// 没有积压时返回 0（COALESCE），而不是 NULL——Gauge 不能是 NULL。
func (r *MergeRepository) OldestPendingSeconds(ctx context.Context) (float64, error) {
	ctx = appctx.WithCrossAppScope(ctx)

	var seconds float64
	err := r.db.WithContext(ctx).
		Raw(`SELECT COALESCE(EXTRACT(EPOCH FROM (now() - MIN(updated_at))), 0)
		       FROM merge_operations
		      WHERE status IN ('pending', 'failed')`).
		Scan(&seconds).Error
	if err != nil {
		return 0, errs.Wrap(errs.CodeInternal, "统计合并补偿滞后失败", err)
	}
	return seconds, nil
}
