package bootstrap

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/17track/social-login/internal/application/authflow"
	"github.com/17track/social-login/internal/application/binding"
	"github.com/17track/social-login/internal/application/tenantconfig"
	"github.com/17track/social-login/internal/application/token"
	"github.com/17track/social-login/internal/domain/identitysource"
	"github.com/17track/social-login/internal/domain/provider"
	"github.com/17track/social-login/internal/infrastructure/cache"
	"github.com/17track/social-login/internal/infrastructure/persistence/postgres"
	httpapi "github.com/17track/social-login/internal/interfaces/http"
	"github.com/17track/social-login/internal/interfaces/http/handler"
	"github.com/17track/social-login/internal/pkg/errs"

	// blank import 触发各渠道适配器的编译期注册（决策 D7）。
	// 新增渠道时改这一行即可，装配代码与核心编排都不需要动。
	_ "github.com/17track/social-login/internal/infrastructure/provider/adapters"
)

// Version 由构建时通过 -ldflags 注入。
var Version = "dev"

// App 是装配完成的运行实例。
type App struct {
	cfg    *Config
	log    *zap.Logger
	db     *gorm.DB
	rdb    *redis.Client
	router http.Handler
	server *http.Server
}

// Options 是装配参数。
type Options struct {
	Config *Config
	// Logger 可选；为空时按配置构造。
	Logger *zap.Logger
	// SkipDatabase 为 true 时跳过数据库与 Redis 连接（仅用于路由/中间件级测试）。
	SkipDatabase bool
}

// New 装配运行实例。
func New(ctx context.Context, opts Options) (*App, error) {
	if opts.Config == nil {
		return nil, errs.New(errs.CodeConfigInvalid, "缺少配置")
	}
	cfg := opts.Config

	logger := opts.Logger
	if logger == nil {
		var err error
		logger, err = NewLogger(cfg.Log)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Server.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	app := &App{cfg: cfg, log: logger}

	keyManager, err := buildKeyManager(cfg, logger)
	if err != nil {
		return nil, err
	}
	claimHasher, err := buildClaimHasher(cfg, logger)
	if err != nil {
		return nil, err
	}
	appSecretHasher := buildAppSecretHasher(cfg, logger)

	signer, err := buildSigner(cfg, logger)
	if err != nil {
		return nil, err
	}

	if opts.SkipDatabase {
		// 只装配到密钥层，用于不依赖存储的测试。
		return app, nil
	}

	db, err := postgres.Open(ctx, postgres.Config{
		DSN:             cfg.Database.DSN,
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		SlowThreshold:   cfg.Database.SlowThreshold,
		LogSQL:          cfg.Database.LogSQL,
	}, logger)
	if err != nil {
		return nil, err
	}
	app.db = db

	if cfg.Migrate.Enabled {
		if err := applyMigrations(db, logger); err != nil {
			return nil, err
		}
	}

	rdb, err := cache.NewClient(ctx, cache.Config{
		Addr:     cfg.Cache.Addr,
		Password: cfg.Cache.Password,
		DB:       cfg.Cache.DB,
		PoolSize: cfg.Cache.PoolSize,
	}, logger)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "连接 Redis 失败", err)
	}
	app.rdb = rdb

	accounts, err := buildAccountProvider(cfg, logger)
	if err != nil {
		return nil, err
	}

	// --- 仓储 ---
	appRepo := postgres.NewAppRepository(db)
	configRepo := postgres.NewProviderConfigRepository(db)
	identityRepo := postgres.NewIdentityRepository(db)
	claimRepo := postgres.NewClaimRepository(db)
	bindingRepo := postgres.NewBindingRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	auditRepo := postgres.NewAuditRepository(db)
	ticketStore := cache.NewTicketStore(rdb)

	// --- 应用服务 ---
	tenantSvc := tenantconfig.New(tenantconfig.Options{Env: cfg.Auth.Env},
		appRepo, configRepo, keyManager)

	sources := identitysource.GlobalRegistry()
	if sources.List() == nil || len(sources.List()) == 0 {
		return nil, errs.New(errs.CodeInternal,
			"没有任何渠道适配器被注册：请确认 adapters 包已被 blank import")
	}
	logger.Info("渠道适配器已注册",
		zap.Int("count", len(sources.List())))

	authflowSvc := authflow.New(authflow.Config{
		CallbackBaseURL: cfg.Server.CallbackBaseURL,
		ExchangeTimeout: cfg.Auth.ExchangeTimeout,
	}, authflow.Deps{
		Tenant:     tenantSvc,
		Sources:    sources,
		Tickets:    ticketStore,
		Identities: identityRepo,
		Claims:     claimRepo,
		Hasher:     claimHasher,
		Bindings:   bindingRepo,
		Accounts:   accounts,
		Audit:      auditRepo,
		Logger:     logger,
	})

	tokenSvc := token.New(token.Config{
		AccessTokenTTL:  cfg.JWT.AccessTokenTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTokenTTL,
	}, token.Deps{
		Signer:   signer,
		Tickets:  ticketStore,
		Sessions: sessionRepo,
		Tenant:   tenantSvc,
		Audit:    auditRepo,
		Logger:   logger,
	})

	bindingSvc := binding.New(binding.Deps{
		Tenant:   tenantSvc,
		Tickets:  ticketStore,
		Bindings: bindingRepo,
		Tokens:   tokenSvc,
		Audit:    auditRepo,
		Logger:   logger,
	})

	// --- 接入层 ---
	h := handler.New(handler.Deps{
		Tenant:       tenantSvc,
		AuthFlow:     authflowSvc,
		Tokens:       tokenSvc,
		Bindings:     bindingSvc,
		Signer:       signer,
		SecretHasher: appSecretHasher,
		Issuer:       cfg.Server.Issuer,
		Version:      Version,
		Health: handler.HealthDeps{
			PingDatabase: func(ctx context.Context) error {
				sqlDB, err := db.DB()
				if err != nil {
					return err
				}
				return sqlDB.PingContext(ctx)
			},
			PingCache: func(ctx context.Context) error { return rdb.Ping(ctx).Err() },
		},
		Logger: logger,
	})

	app.router = httpapi.NewRouter(httpapi.RouterDeps{
		Handler:      h,
		Tenant:       tenantSvc,
		Tokens:       tokenSvc,
		SecretHasher: appSecretHasher,
		Logger:       logger,
	})
	app.server = httpapi.HTTPServer(cfg.Server.Addr, app.router)

	logger.Info("装配完成",
		zap.String("version", Version),
		zap.String("env", cfg.Auth.Env),
		zap.String("account_provider", cfg.Account.Provider),
		zap.Bool("migrate_enabled", cfg.Migrate.Enabled))
	return app, nil
}

// Run 启动 HTTP 服务并阻塞直到 ctx 取消或服务出错。
func (a *App) Run(ctx context.Context) error {
	if a.server == nil {
		return errs.New(errs.CodeInternal, "HTTP 服务未装配")
	}
	errCh := make(chan error, 1)
	go func() {
		a.log.Info("HTTP 服务启动", zap.String("addr", a.cfg.Server.Addr))
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		a.log.Info("收到退出信号，开始优雅退出")
		return a.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// Shutdown 优雅退出：先停接入层，再关存储。
//
// 顺序不可颠倒：先关数据库会让正在处理的请求以"连接已关闭"失败，
// 用户看到的是 500 而不是"服务正在重启"。
func (a *App) Shutdown(ctx context.Context) error {
	if a.server != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, a.cfg.Server.ShutdownTimeout)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			a.log.Error("HTTP 服务优雅退出失败", zap.Error(err))
		}
	}
	if a.rdb != nil {
		if err := cache.Close(a.rdb); err != nil {
			a.log.Error("关闭 Redis 失败", zap.Error(err))
		}
	}
	if a.db != nil {
		if err := postgres.Close(a.db); err != nil {
			a.log.Error("关闭数据库失败", zap.Error(err))
		}
	}
	a.log.Info("已退出")
	_ = a.log.Sync()
	return nil
}

// Router 返回 HTTP 路由，供集成测试直接使用（无需监听端口）。
func (a *App) Router() http.Handler { return a.router }

// Logger 返回日志器。
func (a *App) Logger() *zap.Logger { return a.log }

// DB 返回数据库句柄。
func (a *App) DB() *gorm.DB { return a.db }

// Redis 返回 Redis 客户端。
func (a *App) Redis() *redis.Client { return a.rdb }

// Config 返回配置。
func (a *App) Config() *Config { return a.cfg }

// CertifyProviders 断言渠道注册结果，供启动自检与测试使用。
func (a *App) RegisteredProviders() []provider.Metadata {
	return provider.Global().List()
}
