// Package postgres 是用户中心的持久化实现。
//
// 为什么用 pgx + 手写 SQL，而不是项目里已有的 GORM：
//
//	本服务的正确性建立在三条 PostgreSQL 特性上，而 ORM 恰好都不擅长：
//	  1. 【部分唯一索引】uk_claim_value / uk_claim_one_per_type 只约束
//	     revoked_at IS NULL 的行。捕获冲突时要看 constraint 名才能区分
//	     "凭证被占用"与"同账号重复类型"——ORM 通常把唯一冲突统一报成
//	     "duplicate key"，语义在那一层就丢了。
//	  2. 【ON CONFLICT 的部分索引推断】必须写成
//	     ON CONFLICT (app_id, claim_type, value_hash) WHERE revoked_at IS NULL，
//	     漏掉 WHERE 会直接报 "no unique or exclusion constraint matching"。
//	  3. 【按 id 升序加锁】合并要用 ORDER BY id FOR UPDATE 防双向死锁，
//	     这是并发正确性的一部分，不该藏在 ORM 生成的 SQL 里。
//
//	代价是 SQL 与 schema 紧耦合（改表要改这里），但那本来就是同一件事：
//	表结构就是这份代码的数据契约。
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// Config 是连接池配置。
type Config struct {
	DSN              string
	MaxConns         int32
	MinConns         int32
	MaxConnLifetime  time.Duration
	MaxConnIdleTime  time.Duration
	ConnectTimeout   time.Duration
	StatementTimeout time.Duration
}

// Store 是 PostgreSQL 存储。
type Store struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// Open 建立连接池并验证连通性。
//
// 启动时就 Ping 一次：连不上数据库的服务应该启动失败，而不是"健康检查通过、
// 第一个请求 500"。后者在多副本编排里会让坏实例一直被挂在负载均衡后面。
func Open(ctx context.Context, cfg Config, log *zap.Logger) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, domain.New(domain.CodeInternal, "database.dsn 不是合法的连接串").WithCause(err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	poolCfg.MinConns = cfg.MinConns
	if cfg.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.ConnectTimeout > 0 {
		poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}
	// statement_timeout 在服务端生效，因此对"卡在锁等待上的 SQL"也有效。
	// 放在客户端超时里做不到这一点：客户端放弃后，服务端的语句还在跑。
	if cfg.StatementTimeout > 0 {
		poolCfg.ConnConfig.RuntimeParams["statement_timeout"] =
			fmt.Sprintf("%dms", cfg.StatementTimeout.Milliseconds())
	}
	// 让 pg_stat_activity 里能一眼看出是哪个服务连上来的。
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "user-center"

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, domain.New(domain.CodeInternal, "创建数据库连接池失败").WithCause(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, domain.New(domain.CodeInternal, "连接数据库失败").WithCause(err)
	}
	return &Store{pool: pool, log: log}, nil
}

// Close 关闭连接池。
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Ping 用于 /readyz。
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// inTx 在一个事务里执行 fn，出错自动回滚。
//
// 隔离级别保持默认的 READ COMMITTED：本服务所有冲突点都由唯一索引与行锁兜住，
// 不需要 SERIALIZABLE。用 SERIALIZABLE 会引入"序列化失败需要重试"的新分支，
// 而重试与幂等键语义叠加后会变成"到底算第几次调用"的泥潭。
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return translateDBError("begin", err)
	}
	defer func() {
		// 用 WithoutCancel：请求 ctx 被取消时也要把回滚发出去，
		// 否则连接会带着未结束的事务回到池里（pgx 会丢弃它，但日志里全是噪音）。
		_ = tx.Rollback(context.WithoutCancel(ctx))
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return translateDBError("commit", err)
	}
	return nil
}

// 唯一索引名。捕获唯一冲突后按名字区分语义——这是 ORM 做不到的地方。
const (
	constraintClaimValue     = "uk_claim_value"
	constraintClaimOneType   = "uk_claim_one_per_type"
	constraintAccountsPublic = "uk_accounts_public_id"
	constraintMergesIdem     = "uk_merges_idem"
)

// pgUniqueViolation 是 PostgreSQL 的唯一约束冲突 SQLSTATE。
const pgUniqueViolation = "23505"

// isUniqueViolation 判断错误是否为指定约束的唯一冲突。
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == constraint
}

// translateDBError 把驱动层错误翻成可对外表达的错误。
//
// 不把原始 SQL 错误透出去：它含表名、列名、约束名，对调用方毫无用处，
// 对攻击者是一份免费的 schema 说明。
func translateDBError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return domain.New(domain.CodeInternal, "数据库操作被取消或超时").
			WithCause(err).WithDetail("op", op)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// 42P01 = undefined_table。这几乎总是"迁移没跑"，
		// 而现象是"服务起来了但每个请求都 500"，值得单独给一句人话。
		if pgErr.Code == "42P01" {
			return domain.New(domain.CodeInternal,
				"数据库表不存在：请先执行用户中心的迁移（usercenter -migrate up）").
				WithCause(err).WithDetail("op", op)
		}
		return domain.New(domain.CodeInternal, "数据库操作失败").
			WithCause(err).WithDetail("op", op).WithDetail("sqlstate", pgErr.Code)
	}
	return domain.New(domain.CodeInternal, "数据库操作失败").WithCause(err).WithDetail("op", op)
}

// nullString 把可能为 NULL 的 text 转成 string。
func nullString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
