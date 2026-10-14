package postgres

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/17track/social-login/internal/pkg/errs"
)

// Config 是数据库连接参数。
type Config struct {
	// DSN 形如 postgres://user:pass@host:5432/dbname?sslmode=disable
	DSN string
	// MaxOpenConns 最大连接数。三方登录是 IO 密集型，连接数不必很大，
	// 但要与 §5.7 的入站超时匹配——超时过长会让连接被慢查询占满。
	MaxOpenConns int
	MaxIdleConns int
	// ConnMaxLifetime 连接最长存活时间。
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	// SlowThreshold 慢查询阈值。
	SlowThreshold time.Duration
	// LogSQL 为 true 时记录每条 SQL（仅开发环境开启，生产会淹没日志）。
	LogSQL bool
}

// Open 打开数据库连接并注册隔离回调。
func Open(ctx context.Context, cfg Config, log *zap.Logger) (*gorm.DB, error) {
	if cfg.DSN == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "数据库 DSN 未配置")
	}
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = 25
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = 5
	}
	if cfg.ConnMaxLifetime <= 0 {
		cfg.ConnMaxLifetime = time.Hour
	}
	if cfg.ConnMaxIdleTime <= 0 {
		cfg.ConnMaxIdleTime = 10 * time.Minute
	}

	gormCfg := &gorm.Config{
		Logger: newZapLogger(log, cfg.SlowThreshold, cfg.LogSQL),
		// 我们自己控制事务边界（应用层是事务边界所在，架构 §3），
		// 关掉 GORM 的默认事务可以少两次 BEGIN/COMMIT。
		SkipDefaultTransaction: true,
		// 时间统一用 UTC 入库，避免跨时区部署时出现"同一事件两个时间"。
		NowFunc: func() time.Time { return time.Now().UTC() },
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), gormCfg)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "连接数据库失败", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "获取数据库连接池失败", err)
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "数据库连通性检查失败", err)
	}

	if err := registerAppScopeCallbacks(db); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "注册应用隔离回调失败", err)
	}

	if log != nil {
		log.Info("数据库连接就绪",
			zap.Int("max_open_conns", cfg.MaxOpenConns),
			zap.Duration("conn_max_lifetime", cfg.ConnMaxLifetime))
	}
	return db, nil
}

// Close 关闭连接池。
func Close(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// InTx 在事务中执行 fn。
//
// 事务边界约定（架构 §3）：事务边界在应用层，由应用服务显式调用本函数；
// 仓储方法内部不开事务。
//
// ⚠️ 严禁把 HTTP 调用（AccountProvider.Merge / Provider.Exchange）包进本函数——
// 那会导致"远端成功而本地提交失败"的永久孤儿窗口（修正 P0-3）。跨服务合并
// 必须拆成三次独立事务，见架构 §7.3。
func InTx(ctx context.Context, db *gorm.DB, fn func(tx *gorm.DB) error) error {
	if db == nil {
		return errs.New(errs.CodeInternal, "数据库未初始化")
	}
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(tx)
	})
	if err != nil {
		return fmt.Errorf("事务执行失败: %w", err)
	}
	return nil
}
