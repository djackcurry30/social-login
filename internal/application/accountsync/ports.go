package accountsync

import (
	"context"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
)

// AppSource 提供"要同步哪些应用"与"某个应用现在长什么样"。
//
// 只声明同步需要的两个【读】操作，不直接依赖 tenant.ApplicationRepository：
//   - 接口越窄，测试替身越简单（不用实现 Upsert / FindByID）；
//   - 更重要的是不给同步任务留下"顺手改应用"的可能——它对 applications
//     的唯一合法动作是写 uc_synced_at / uc_sync_error 两个运维字段。
type AppSource interface {
	// ListForSync 列出全部应用（含已停用），用于定时全量对账。
	ListForSync(ctx context.Context, limit int) ([]tenant.Application, error)

	// FindByAppCode 按 app_code 读单个应用，用于即时同步。
	//
	// 为什么不从队列里直接带应用结构体：建应用后可能紧接着被改（改名/停用），
	// 队列里的快照就是过期的；重新读一次只有一次主键查询的成本，却总能拿到
	// 最新状态。应用已被删除时返回 tenant.ErrNotFound，同步任务据此静默跳过。
	FindByAppCode(ctx context.Context, appCode string) (*tenant.Application, error)
}

// SyncRecorder 记录同步结果。
//
// 方法名带 UC 前缀（而不是 MarkSynced / MarkFailed）是刻意的：这个仓库上
// 还会出现别的"同步"（渠道配置、webhook 等），笼统的名字会让人分不清
// 改的是哪一列；也正因为名字具体，仓储可以直接实现本接口，不必额外加一层
// 适配器。
//
// 为什么"成功"与"失败"是两个方法，而不是一个带 error 参数的方法：
// 两者写入的列不同——成功要【清空】上次的错误。用 error 参数让实现方自己
// 判断，很容易漏掉"成功时清空"，而漏掉的表现是管理端永久显示一个已经
// 修好的旧错误，运维会去排查一个不存在的问题。
type SyncRecorder interface {
	// MarkUCSynced 记录成功时间并清空错误。
	MarkUCSynced(ctx context.Context, appID int64, at time.Time) error
	// MarkUCSyncFailed 记录失败原因（保留上次成功时间）。
	MarkUCSyncFailed(ctx context.Context, appID int64, reason string) error
}
