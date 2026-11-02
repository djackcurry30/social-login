// Package app 装配用户中心：配置 → 密钥 → 数据库 → 用例 → HTTP。
//
// 装配顺序是刻意的：先构造密钥再连库，最后才是路由。任何一步失败都让进程
// 启动失败，而不是带着半套依赖启动——"起来了但不能用"比"起不来"更难排查，
// 尤其在多副本编排里，坏实例会一直被挂在负载均衡后面。
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/metrics"
	ucmigrations "github.com/djackcurry30/social-login/migrations/usercenter"

	"github.com/djackcurry30/social-login/internal/usercenter/config"
	"github.com/djackcurry30/social-login/internal/usercenter/cryptox"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/httpapi"
	"github.com/djackcurry30/social-login/internal/usercenter/observe"
	"github.com/djackcurry30/social-login/internal/usercenter/service"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// Version 由 -ldflags 注入。
var Version = "dev"

// App 是组装好的服务实例。
type App struct {
	cfg    *config.Config
	log    *zap.Logger
	store  *postgres.Store
	server *http.Server
}

// New 构造服务。
func New(ctx context.Context, cfg *config.Config) (*App, error) {
	log, err := observe.NewLogger(cfg.Log.Level, cfg.Log.Format, cfg.Log.File)
	if err != nil {
		return nil, err
	}

	hasher, env, err := buildCrypto(cfg, log)
	if err != nil {
		return nil, err
	}

	store, err := postgres.Open(ctx, postgres.Config{
		DSN:              cfg.Database.DSN,
		MaxConns:         cfg.Database.MaxConns,
		MinConns:         cfg.Database.MinConns,
		MaxConnLifetime:  cfg.Database.MaxConnLifetime,
		MaxConnIdleTime:  cfg.Database.MaxConnIdleTime,
		ConnectTimeout:   cfg.Database.ConnectTimeout,
		StatementTimeout: cfg.Database.StatementTimeout,
	}, log)
	if err != nil {
		return nil, err
	}

	if cfg.Migrate.Enabled {
		if err := Migrate(ctx, cfg.Database.DSN, "up", log); err != nil {
			store.Close()
			return nil, err
		}
	}

	reg := metrics.NewRegistry()
	obs := observe.NewMetrics(reg)
	svc := service.New(store, hasher, env, log, obs)

	router := httpapi.NewRouter(httpapi.Deps{
		Service:         svc,
		Store:           store,
		Metrics:         obs,
		MetricsRegistry: reg,
		Logger:          log,
		Token:           cfg.Security.ServiceToken,
		MaxBodyBytes:    cfg.Server.MaxBodyBytes,
		Mode:            ginMode(cfg.Server.Mode),
	})

	return &App{
		cfg:   cfg,
		log:   log,
		store: store,
		server: &http.Server{
			Addr:    cfg.Server.Addr,
			Handler: router,
			// 超时都要设：没有 ReadHeaderTimeout 的服务会积累慢速攻击连接；
			// 没有 WriteTimeout 的服务会在对端不读时把 goroutine 挂住。
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}, nil
}

// Run 启动 HTTP 服务并等待退出信号。
func (a *App) Run(ctx context.Context) error {
	defer a.store.Close()
	defer func() { _ = a.log.Sync() }()

	errCh := make(chan error, 1)
	go func() {
		a.log.Info("用户中心已启动",
			zap.String("addr", a.cfg.Server.Addr),
			zap.String("mode", a.cfg.Server.Mode),
			zap.String("version", Version),
			zap.Bool("auth", a.cfg.Security.ServiceToken != ""))
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		a.log.Info("收到退出信号，开始优雅关闭")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.Server.ShutdownTimeout)
		defer cancel()
		// 关闭期间不再接新连接，已建立的请求最多等到超时。
		return a.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return domain.New(domain.CodeInternal, "HTTP 服务异常退出").WithCause(err)
	}
}

// buildCrypto 构造哈希器与加密器。
func buildCrypto(cfg *config.Config, log *zap.Logger) (*cryptox.ClaimHasher, *cryptox.Envelope, error) {
	salt := cfg.Security.ClaimSalt
	if salt == "" {
		if cfg.Server.IsProduction() {
			return nil, nil, domain.New(domain.CodeInternal, "生产模式缺少 security.claim_salt")
		}
		// 随机盐能启动，但必须喊出来：它每次重启都变，意味着重启后
		// 所有历史凭证的 hash 都对不上——现象是"老用户全部按手机号查不到账号"。
		salt = "dev-claim-salt-" + fmt.Sprint(time.Now().UnixNano())
		log.Warn("开发模式使用随机凭证盐：进程重启后按手机号/邮箱反查账号的能力将失效。"+
			"请配置 security.claim_salt 并保持稳定",
			zap.String("generated_claim_salt", salt))
	}
	hasher, err := cryptox.NewClaimHasher([]byte(salt))
	if err != nil {
		return nil, nil, err
	}

	var key []byte
	if cfg.Security.MasterKey == "" {
		if cfg.Server.IsProduction() {
			return nil, nil, domain.New(domain.CodeInternal, "生产模式缺少 security.master_key")
		}
		key, err = cryptox.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		log.Warn("开发模式自动生成临时主密钥：进程重启会更换，旧密文将无法解密"+
			"（会明确报错，不会静默返回错误值）。把下面这行写入 security.master_key 即可固定",
			zap.String("generated_master_key", cryptox.EncodeKey(key)))
	} else {
		key, err = cryptox.DecodeKey(cfg.Security.MasterKey)
		if err != nil {
			return nil, nil, err
		}
	}
	env, err := cryptox.NewEnvelope(cfg.Security.KEKID, key)
	if err != nil {
		return nil, nil, err
	}
	return hasher, env, nil
}

// Migrate 执行数据库迁移。
//
// direction 取 up / down / status。
// 用 goose 嵌入 SQL 而不是 AutoMigrate：迁移要可审计、可回滚，
// 而"由代码推断 schema"既写不出部分唯一索引，也解释不了它为什么存在。
func Migrate(ctx context.Context, dsn, direction string, log *zap.Logger) error {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return domain.New(domain.CodeInternal, "database.dsn 不是合法的连接串").WithCause(err)
	}
	// 迁移用独立连接：不复用业务连接池，避免迁移期间的长事务占满业务连接。
	db := stdlib.OpenDB(*poolCfg.ConnConfig)
	defer db.Close()

	if err := pingDB(ctx, db); err != nil {
		return domain.New(domain.CodeInternal, "连接数据库失败").WithCause(err)
	}

	goose.SetBaseFS(ucmigrations.FS)
	goose.SetLogger(gooseLogger{log: log})
	if err := goose.SetDialect("postgres"); err != nil {
		return domain.New(domain.CodeInternal, "设置迁移方言失败").WithCause(err)
	}

	switch direction {
	case "up":
		err = goose.Up(db, ".")
	case "down":
		// 只回滚一个版本：一次 down 到底在多服务共用一个库时非常危险，
		// 而本服务的迁移都是成组设计的，逐步回滚更容易判断影响。
		err = goose.Down(db, ".")
	case "status":
		err = goose.Status(db, ".")
	default:
		return domain.Newf(domain.CodeInvalid, "未知的迁移方向: %s（up/down/status）", direction)
	}
	if err != nil {
		return domain.New(domain.CodeInternal, "执行数据库迁移失败").WithCause(err)
	}
	if log != nil {
		log.Info("迁移执行完成", zap.String("direction", direction))
	}
	return nil
}

func pingDB(ctx context.Context, db *sql.DB) error {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return db.PingContext(pingCtx)
}

// gooseLogger 把 goose 的输出接到 zap。
type gooseLogger struct{ log *zap.Logger }

func (g gooseLogger) Printf(format string, v ...any) {
	if g.log != nil {
		g.log.Sugar().Infof(format, v...)
	}
}

func (g gooseLogger) Fatalf(format string, v ...any) {
	if g.log != nil {
		g.log.Sugar().Errorf(format, v...)
	}
}

// ginMode 把本服务的 mode 映射成 gin 的模式。
func ginMode(mode string) string {
	if mode == "release" {
		return "release"
	}
	// 测试模式关掉 gin 的调试输出，避免每个请求打一行 "[GIN-debug]"。
	return "test"
}
