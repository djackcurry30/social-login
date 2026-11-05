package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// slowTracer 是 pgx 的查询追踪器：只做一件事——把超过阈值的 SQL 记进日志。
//
// 为什么用 pgx 的 QueryTracer 而不是在仓储层逐个包一层：
//
//	仓储层有几十个调用点（每个方法里还可能有多个语句），手工包必然漏；
//	而"漏掉的那个"往往就是出问题的那条。QueryTracer 在连接层生效，
//	新增 SQL 不需要记得接埋点。
//
// 代价：它会看到所有语句，包括迁移与健康检查。迁移在启动期执行，
// 慢一点无妨；/readyz 的 Ping 不是查询，不会经过这里。
type slowTracer struct {
	log       *zap.Logger
	threshold time.Duration
}

// queryState 是随 context 传递的"本次查询"信息。
//
// pgx 的 TraceQueryEndData 里【没有】SQL 与参数（只有 CommandTag 与错误），
// 所以必须在 Start 时把要记录的东西塞进 context。这也顺带保证了
// "记的语句"与"测的耗时"是同一次调用，不会因为并发串台。
type queryState struct {
	started  time.Time
	sql      string
	argCount int
}

type startKey struct{}

// TraceQueryStart 记录开始时间。
func (t *slowTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	if t == nil || t.log == nil || t.threshold <= 0 {
		return ctx
	}
	return context.WithValue(ctx, startKey{}, &queryState{
		started:  time.Now(),
		sql:      data.SQL,
		argCount: len(data.Args),
	})
}

// TraceQueryEnd 输出慢查询。
//
// ⚠️ 只记 SQL 模板与参数【个数】，绝不记参数值：
// 本服务的参数里就是手机号哈希与密文，一旦进日志，前面所有脱敏都白做了
// （日志的保留期与访问权限都比数据库宽松得多）。
func (t *slowTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if t == nil || t.log == nil || t.threshold <= 0 {
		return
	}
	st, ok := ctx.Value(startKey{}).(*queryState)
	if !ok || st == nil {
		return
	}
	took := time.Since(st.started)
	if took < t.threshold {
		return
	}

	fields := []zap.Field{
		zap.Duration("took", took),
		zap.String("sql", clip(oneLine(st.sql), 500)),
		zap.Int("args", st.argCount),
		zap.String("trace_id", reqmeta.TraceID(ctx)),
		zap.String("command", commandOf(data.CommandTag)),
	}
	if data.Err != nil {
		fields = append(fields, zap.Error(data.Err))
	}
	t.log.Warn("慢查询", fields...)
}

// oneLine 把多行 SQL 压成一行：日志要能 grep，换行会让一条语句散成多行。
func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	prevSpace := false
	for _, r := range s {
		switch r {
		case '\n', '\r', '\t':
			r = ' '
		}
		if r == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		out = append(out, r)
	}
	return string(out)
}

// commandOf 取语句类型（SELECT/UPDATE/...），便于按类型做聚合。
func commandOf(tag pgconn.CommandTag) string {
	if s := tag.String(); s != "" {
		return s
	}
	return ""
}
