// 应用与用户中心注册同步的仓储方法（契约 v1.1 §2.6）。
//
// 单独成文而不是塞进 app_repo.go：这一组方法只服务"注册同步"这一件事，
// 与应用的增删改查没有共享逻辑；混在一起会让 app_repo.go 越来越难读，
// 也让人分不清"哪些字段是业务字段、哪些是运维字段"。
package postgres

import (
	"context"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

const (
	// DefaultSyncListLimit 是单轮对账拉取的应用数上限。
	//
	// 给上限而不是"全查"：应用表理论上可以无限增长，一次把几万行读进内存
	// 再逐个发 HTTP，会把内存和 GC 拖垮。500 对当前的量级（百级）足够，
	// 真超过时对账会分多轮覆盖——因为对账是幂等重放，不需要"一轮做完"。
	DefaultSyncListLimit = 500

	// maxSyncErrorLen 是失败原因的最大长度（按 rune 计）。
	//
	// 截断理由：原因来自对端错误报文，可能是一整段 HTML 网关页面。
	// 直接落库会让这一列变成事实上的日志仓库，列表页也没法展示。
	maxSyncErrorLen = 300
)

// ListForSync 列出需要同步到用户中心的应用。
//
// 包含已停用的应用：用户中心需要知道"这个应用已停用"，否则它会继续接受
// 该应用的请求。停用状态的同步只是"告知事实"，对端是否据此拒绝属于
// 交互策略（§12.3，MVP 不做）。
func (r *AppRepository) ListForSync(ctx context.Context, limit int) ([]tenant.Application, error) {
	if limit <= 0 {
		limit = DefaultSyncListLimit
	}
	// applications 不在 scopedTables 里（它就是应用表本身），这里显式声明
	// 跨应用作用域只是为了与 Count 等方法保持一致的心智模型。
	ctx = appctx.WithCrossAppScope(ctx)

	var rows []applicationModel
	if err := r.db.WithContext(ctx).
		Order("id ASC").
		Limit(limit).
		Find(&rows).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询待同步应用失败", err)
	}

	out := make([]tenant.Application, 0, len(rows))
	for i := range rows {
		out = append(out, *appToDomain(&rows[i]))
	}
	return out, nil
}

// MarkUCSynced 记录"同步成功"。
//
// ⚠️ 刻意【不更新 updated_at】：那是业务字段（配置最后修改时间），
// 而同步每 5 分钟就会发生一次。若一并刷新，管理端列表里所有应用的
// "更新时间"会一直变，运维会以为配置被人改过。
//
// 用原生 SQL 而不是 GORM 的 Updates/UpdateColumns：GORM 会为带 `UpdatedAt`
// 字段的模型【自动】补 updated_at，不写进 map 也拦不住（Updates 与
// UpdateColumns 都试过，实测仍然会写，只是靠"更新时间恰好等于同步时间"
// 才发现的）。这条 SQL 只碰两列，语义一眼可见，也就没有这类隐式行为。
func (r *AppRepository) MarkUCSynced(ctx context.Context, appID int64, at time.Time) error {
	if appID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	res := r.db.WithContext(ctx).Exec(
		`UPDATE applications SET uc_synced_at = ?, uc_sync_error = NULL WHERE id = ?`,
		at, appID,
	)
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "记录应用同步成功状态失败", res.Error)
	}
	if res.RowsAffected == 0 {
		// 应用在对账过程中被删除。返回 ErrNotFound 让调用方别再写失败状态
		// （那会是一条永远修不掉的记录）。
		return tenant.ErrNotFound
	}
	return nil
}

// MarkUCSyncFailed 记录"同步失败"。
//
// 刻意【不清空 uc_synced_at】：保留"上次成功是什么时候"比抹掉它有用得多。
// 运维看到"从未同步"和"上次成功是 3 天前、此后一直失败"是两种完全不同的
// 判断——前者说明注册从没成功过（大概率配置错），后者说明是后来坏的。
func (r *AppRepository) MarkUCSyncFailed(ctx context.Context, appID int64, reason string) error {
	if appID <= 0 {
		return errs.New(errs.CodeInvalidRequest, "app_id 不合法")
	}
	msg := truncateRunes(reason, maxSyncErrorLen)
	res := r.db.WithContext(ctx).Exec(
		`UPDATE applications SET uc_sync_error = ? WHERE id = ?`,
		msg, appID,
	)
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "记录应用同步失败状态失败", res.Error)
	}
	if res.RowsAffected == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// CountSyncFailed 统计当前"同步失败且未恢复"的应用数（供 /metrics 采集）。
//
// 只在 uc_sync_error 非空时计数：MarkUCSynced 会把该列清空，所以它天然是
// "当前还坏着"的集合，而不是"历史失败过"的累计值——后者会随时间单调增长，
// 对告警没有意义（一条三天前已自愈的失败不该继续触发报警）。
//
// 用原生 SQL 的理由同 MarkUCSynced：走 GORM 的 Count 会带上模型默认作用域，
// 而这个统计本来就该横跨全部应用（跨租户的运维视图）。
func (r *AppRepository) CountSyncFailed(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).
		Raw(`SELECT count(*) FROM applications WHERE uc_sync_error IS NOT NULL`).
		Scan(&n).Error; err != nil {
		return 0, errs.Wrap(errs.CodeInternal, "统计应用同步失败数失败", err)
	}
	return n, nil
}

// truncateRunes 按字符（不是字节）截断，避免把中文截成半个字导致库里存进
// 非法 UTF-8 —— PostgreSQL 的 text 列遇到非法字节会直接拒绝写入，
// 那时真正的同步失败原因就被这个"写日志失败"盖掉了。
func truncateRunes(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	return string(rs[:max]) + "…"
}
