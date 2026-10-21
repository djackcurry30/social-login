package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/application/authflow"
	"github.com/djackcurry30/social-login/internal/application/binding"
	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	"github.com/djackcurry30/social-login/internal/application/oauthnotify"
	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/application/token"
	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/identitysource"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/infrastructure/cache"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
	"github.com/djackcurry30/social-login/internal/infrastructure/providerguard"
	"github.com/djackcurry30/social-login/internal/infrastructure/webhook"
	httpapi "github.com/djackcurry30/social-login/internal/interfaces/http"
	"github.com/djackcurry30/social-login/internal/interfaces/http/handler"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/guards/breaker"

	// blank import 触发各渠道适配器的编译期注册（决策 D7）。
	// 新增渠道时改这一行即可，装配代码与核心编排都不需要动。
	_ "github.com/djackcurry30/social-login/internal/infrastructure/provider/adapters"
	wechatadapter "github.com/djackcurry30/social-login/internal/infrastructure/provider/adapters/wechat"

	// 管理端（/admin/v1）依赖：单独成一组 import，与业务端依赖视觉分隔。
	"github.com/djackcurry30/social-login/internal/application/adminapp"
	"github.com/djackcurry30/social-login/internal/application/adminaudit"
	"github.com/djackcurry30/social-login/internal/application/adminchan"
	"github.com/djackcurry30/social-login/internal/application/adminevent"
	"github.com/djackcurry30/social-login/internal/application/adminidentity"
	"github.com/djackcurry30/social-login/internal/application/adminmerge"
	"github.com/djackcurry30/social-login/internal/application/adminobs"
	"github.com/djackcurry30/social-login/internal/application/adminsession"
	"github.com/djackcurry30/social-login/internal/application/auditexport"
	"github.com/djackcurry30/social-login/internal/application/outbox"
	"github.com/djackcurry30/social-login/internal/embedweb"
	adminhttp "github.com/djackcurry30/social-login/internal/interfaces/http/admin"
	adminhandler "github.com/djackcurry30/social-login/internal/interfaces/http/admin/handler"
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

	// dispatcher 是 outbox 投递循环；nil 表示不启用（SkipDatabase 的测试装配）。
	dispatcher *outbox.Service
	// exporter 是审计导出执行循环；nil 表示未配置导出目录。
	exporter *auditexport.Service
	// compensator 是账号合并的补偿循环（§7.3）。
	compensator *appmerge.Compensator
	// accounts 是账号体系端口。暴露给集成测试用（构造 source/target 账号），
	// 与 DB()/Redis() 同属测试可达的装配产物。
	accounts domainaccount.Provider
	bgCancel context.CancelFunc
	bgWG     sync.WaitGroup
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

	// 小程序会话密钥的跨请求共享。
	//
	// 必须在服务开始接流量之前注入：业务方常见接法是"先换登录态、再单独
	// 上报加密手机号"，两次请求在负载均衡下可能落到不同实例，进程内缓存
	// 会让第二次请求解不开（概率性失败，单实例本地复现不了）。
	// 值走信封加密，与渠道凭据同一把 KEK：拿到 Redis 快照不等于拿到手机号。
	wechatadapter.ConfigureSessionStore(cache.NewSessionKeyStore(rdb, keyManager), logger)

	accounts, err := buildAccountProvider(cfg, logger)
	if err != nil {
		return nil, err
	}
	app.accounts = accounts

	// --- 仓储 ---
	appRepo := postgres.NewAppRepository(db)
	configRepo := postgres.NewProviderConfigRepository(db)
	identityRepo := postgres.NewIdentityRepository(db)
	claimRepo := postgres.NewClaimRepository(db)
	bindingRepo := postgres.NewBindingRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	auditRepo := postgres.NewAuditRepository(db)
	ticketStore := cache.NewTicketStore(rdb)
	// 撤销名单（§8.4 高危撤销）：强制下线后让已签发的 access_token
	// 在 check_revocation=true 时立即失效。
	revocationStore := cache.NewRevocationStore(rdb)

	// 管理端仓储（admin_users / admin_sessions / admin_audit_logs）。
	adminUserRepo := postgres.NewAdminUserRepository(db)
	adminSessionRepo := postgres.NewAdminSessionRepository(db)
	adminAuditRepo := postgres.NewAdminAuditWriter(db)
	// ListAppIDs 把 adminapp 用到的"按 ID 倒序取 N 个"能力挂上。
	adminListAppIDs := appRepo.ListIDs

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

	// 渠道熔断（架构 §5.6）：用装饰器包住所有出站调用。
	//
	// 装配在 Lookup 时生效，而不是改适配器的注册方式——这样"新增渠道 =
	// 新增一个包 + 一行 import"（D7）保持不变，渠道实现完全不知道熔断的存在。
	guard := breaker.New(breaker.Config{
		Enabled:             cfg.ProviderGuard.CircuitBreaker.Enabled,
		Granularity:         cfg.ProviderGuard.CircuitBreaker.Granularity,
		WindowSeconds:       cfg.ProviderGuard.CircuitBreaker.WindowSeconds,
		BucketSeconds:       cfg.ProviderGuard.CircuitBreaker.BucketSeconds,
		MinRequests:         cfg.ProviderGuard.CircuitBreaker.MinRequests,
		FailureRatio:        cfg.ProviderGuard.CircuitBreaker.FailureRatio,
		TimeoutRatio:        cfg.ProviderGuard.CircuitBreaker.TimeoutRatio,
		SlowRatio:           cfg.ProviderGuard.CircuitBreaker.SlowRatio,
		SlowThreshold:       cfg.ProviderGuard.CircuitBreaker.SlowThreshold,
		ConsecutiveTimeouts: cfg.ProviderGuard.CircuitBreaker.ConsecutiveTimeouts,
		ConsecutiveFailures: cfg.ProviderGuard.CircuitBreaker.ConsecutiveFailures,
		OpenDuration:        cfg.ProviderGuard.CircuitBreaker.OpenDuration,
		HalfOpenRequests:    cfg.ProviderGuard.CircuitBreaker.HalfOpenRequests,
	}, logger)
	sources.SetWrapper(func(p provider.Provider) provider.Provider {
		return providerguard.Wrap(p, guard)
	})
	logger.Info("渠道熔断已装配",
		zap.Bool("enabled", guard.Enabled()),
		zap.String("granularity", guard.Config().Granularity),
		zap.Int("min_requests", guard.Config().MinRequests),
		zap.Duration("open_duration", guard.Config().OpenDuration))

	// 账号合并（第三期，§7.3）。
	//
	// 三个协作对象必须分别注入：Store 管操作记录，Converger 管"一个事务内
	// 改挂绑定 + 撤销令牌 + 写事件 + 写审计"，Locker 管同一目标的串行化。
	// 合成一个对象会让人误以为它们在同一个事务里。
	mergeRepo := postgres.NewMergeRepository(db)
	mergeSvc := appmerge.New(appmerge.Deps{
		Ops:              mergeRepo,
		Converger:        postgres.NewMergeConverger(db),
		Accounts:         accounts,
		Locker:           cache.NewMergeLocker(rdb),
		Audit:            auditRepo,
		Logger:           logger,
		Tickets:          ticketStore,
		Challenges:       cache.NewMergeChallengeStore(rdb),
		Sender:           buildSMSSender(cfg, logger),
		RemoteIdempotent: cfg.Merge.RemoteIdempotent,
	})
	// 补偿时需要读应用策略（Resume 不做前置校验，但仍需要 app 上下文）。
	mergeSvc.SetAppLookup(appRepo.FindByID)
	mergeCompensator := appmerge.NewCompensator(mergeSvc, mergeRepo, logger)

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
		Merge:      mergeSvc,
	})

	tokenSvc := token.New(token.Config{
		AccessTokenTTL:  cfg.JWT.AccessTokenTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTokenTTL,
	}, token.Deps{
		Signer:     signer,
		Revocation: revocationStore,
		Tickets:    ticketStore,
		Sessions:   sessionRepo,
		Tenant:     tenantSvc,
		Audit:      auditRepo,
		Logger:     logger,
	})

	bindingSvc := binding.New(binding.Deps{
		Tenant:   tenantSvc,
		Tickets:  ticketStore,
		Bindings: bindingRepo,
		Tokens:   tokenSvc,
		Audit:    auditRepo,
		Logger:   logger,
	})

	// 平台服务端通知（Apple 解约 / 支付宝异步通知）。
	//
	// 复用 authflow 的三个依赖（sources / identityRepo / bindingRepo）而不是
	// 另建一套：通知要做的事是"按 openid 找到身份 → 解绑"，与授权链路
	// 写的是同样两张表，必须走同一批仓储实例，否则事务边界与 GORM 的
	// app_id 注入回调会出现不一致。
	notifySvc := oauthnotify.New(oauthnotify.Deps{
		Tenant:     tenantSvc,
		Sources:    sources,
		Identities: identityRepo,
		Bindings:   bindingRepo,
		Audit:      auditRepo,
		Logger:     logger,
	})

	// --- 管理端 services（A 组 + B 组 + I 组 + LoginService）---
	//
	// ⚠️ HashSecret 必须注入 crypto.AppSecretHasher。
	//
	// 早期版本这里传 nil，落到 adminapp.defaultHashSecret 的占位实现
	// （`"placeholder:" + 明文`），造成两个后果：
	//  1. 管理端创建的应用在业务端【永远验签失败】——业务端
	//     middleware.AuthenticateApp 用 HMAC 比对，与 placeholder 前缀永不相等，
	//     即前后台链路是断的；
	//  2. app_secret 以明文形式落在 applications.app_secret_hash。
	//
	// 这里做的是"同一把哈希器"：管理端写入、业务端校验，必须共用同一个盐与算法，
	// 否则写入与校验的对端永远对不上。
	adminAppSvc := adminapp.New(adminapp.Deps{
		TenantApps: appRepo,
		AdminAudit: adminAuditRepo,
		Logger:     logger,
		ListAppIDs: adminListAppIDs,
		HashSecret: func(plain string) (string, error) {
			// AppSecretHasher.Hash 是纯函数（HMAC-SHA256 + 固定盐），不会失败；
			// 适配成 error 返回只是为了保持 Deps 签名对测试友好。
			if plain == "" {
				return "", errs.New(errs.CodeInvalidRequest, "app_secret 不能为空")
			}
			return appSecretHasher.Hash(plain), nil
		},
		// webhook 签名密钥必须可解密（HMAC 需要明文），与渠道凭据同一把 KEK。
		EncryptSecret: func(plain string) ([]byte, string, error) {
			ct, err := keyManager.Encrypt(plain)
			return ct, keyManager.KEKID(), err
		},
		SetWebhook: appRepo.SetWebhook,
		GetWebhook: appRepo.WebhookConfig,
	})

	// adminchan 的 EncryptSecret 注入 keymanager。
	// KeyManager 当前是单 KEK，把 KEKID 作为 dekID 写入 secret_dek_id 列；
	// 真正的 DEK 信封加密（kek → dek → secret）是第二期再扩。
	adminChanSvc := adminchan.New(adminchan.Deps{
		TenantConfigs: configRepo,
		TenantSecrets: keyManager,
		EncryptSecret: func(plain string) ([]byte, string, error) {
			ct, err := keyManager.Encrypt(plain)
			return ct, keyManager.KEKID(), err
		},
		AdminAudit: adminAuditRepo,
		Logger:     logger,
		VerifyHTTP: adminchan.VerifyHTTPDefault(),
	})

	adminObsSvc := adminobs.New(adminobs.Deps{
		// 熔断状态与复位：直接接 guard，管理端看到的就是进程内的真实状态。
		CircuitStates: guard.States,
		ResetCircuit:  guard.Reset,
		AdminAudit:    adminAuditRepo,
		// 健康探测优先走适配器的 HealthChecker：它知道该平台真正的
		// 健康端点（微信的稳定 token、Apple 的 JWKS），比通用 HTTP 猜测准确。
		PingSource: func(ctx context.Context, platform, scene string) error {
			src, err := sources.Lookup(platform, scene)
			if err != nil {
				return err
			}
			// Ping 是可选能力（identitysource.HealthChecker），不是 Source 的必选方法。
			if hc, ok := src.(identitysource.HealthChecker); ok {
				return hc.Ping(ctx)
			}
			return provider.NotSupported("health_check")
		},
		Logger: logger,
	})

	// G 组：事件与死信。
	eventRepo := postgres.NewEventRepository(db)
	adminEventSvc := adminevent.New(adminevent.Deps{
		Events:     eventRepo,
		AdminAudit: adminAuditRepo,
		Logger:     logger,
	})

	// H 组：审计查询与异步导出。
	//
	// 查询直接复用 auditRepo（它同时实现 audit.Writer 与 audit.Query）：
	// 读写同一张表，没有理由再包一层。
	auditExportRepo := postgres.NewAuditExportRepository(db)
	adminAuditSvc := adminaudit.New(adminaudit.Deps{
		Query:      auditRepo,
		Exports:    auditExportRepo,
		AdminAudit: adminAuditRepo,
		ExportTTL:  cfg.Audit.ExportFileTTL,
		ExportDir:  cfg.Audit.ExportDir,
	})

	// D 组：账号合并运维。
	adminMergeSvc := adminmerge.New(adminmerge.Deps{
		Ops:        mergeRepo,
		Merger:     mergeSvc,
		Impactor:   postgres.NewMergeImpactor(db),
		AdminAudit: adminAuditRepo,
		Logger:     logger,
	})

	// C 组：身份与绑定。
	//
	// Bindings 同时充当查询与干预入口：ListAdmin 走同一批过滤条件，
	// ForceUnbind/Transfer 在仓储内用事务写事件，避免"改了本地没发通知"。
	bindingAdminRepo := postgres.NewBindingAdminRepository(db)
	adminIdentitySvc := adminidentity.New(adminidentity.Deps{
		Identities:  postgres.NewIdentityAdminRepository(db),
		IdentityGet: identityRepo,
		Claims:      claimRepo,
		Bindings:    bindingAdminRepo,
		Writer:      bindingAdminRepo,
		AdminAudit:  adminAuditRepo,
		Logger:      logger,
	})

	// E 组：会话与令牌。
	adminSessionSvc := adminsession.New(adminsession.Deps{
		Sessions:       sessionRepo,
		AdminList:      postgres.NewSessionAdminRepository(db),
		Revocation:     revocationStore,
		AdminAudit:     adminAuditRepo,
		Logger:         logger,
		AccessTokenTTL: cfg.JWT.AccessTokenTTL,
	})

	// 审计导出 worker：与在线请求分离部署是架构建议，当前同进程；
	// 领取用 SQL 原子更新（FOR UPDATE SKIP LOCKED），多副本不会重复导出。
	var auditExporter *auditexport.Service
	if cfg.Audit.ExportWorkerOn() {
		auditExporter = auditexport.New(auditRepo, auditExportRepo,
			auditexport.DefaultConfig(cfg.Audit.ExportDir), logger)
	} else {
		logger.Warn("审计导出 worker 未启用：audit.export_dir 为空或显式关闭，" +
			"提交的导出任务会一直停在 pending")
	}

	// Outbox 投递 worker：事件外发的唯一出口。
	//
	// 与在线请求分离部署是架构 §9 的建议；当前同进程运行，但通过租约
	// （SELECT ... FOR UPDATE SKIP LOCKED）保证多副本不重复投递，
	// 因此将来拆成独立进程不需要改代码。
	webhookDeliverer := webhook.NewDeliverer(
		&appWebhookTargets{apps: appRepo, keys: keyManager}, logger)
	outboxDispatcher := outbox.New(eventRepo, webhookDeliverer, outbox.DefaultConfig(), logger)

	adminLoginSvc := adminhandler.NewLoginService(adminhandler.LoginServiceDeps{
		Users:    adminUserRepo,
		Sessions: adminSessionRepo,
		Logger:   logger,
	})

	// 管理端被用来"启用"才会挂上路由；为保持简洁第一期默认挂上。
	adminDeps := &adminhttp.RouterDeps{
		Logger:        logger,
		AuthSessions:  adminSessionRepo,
		AuthUsers:     adminUserRepo,
		AuthLogin:     adminLoginSvc,
		AdminApp:      adminAppSvc,
		AdminChan:     adminChanSvc,
		AdminObs:      adminObsSvc,
		AdminEvent:    adminEventSvc,
		AdminAudit:    adminAuditSvc,
		AdminMerge:    adminMergeSvc,
		AdminIdentity: adminIdentitySvc,
		AdminSession:  adminSessionSvc,
	}
	_ = adminDeps

	// --- 接入层 ---
	h := handler.New(handler.Deps{
		Tenant:       tenantSvc,
		AuthFlow:     authflowSvc,
		Tokens:       tokenSvc,
		Bindings:     bindingSvc,
		Notify:       notifySvc,
		Merge:        mergeSvc,
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
		Admin:        adminDeps,
		WebFS:        embedweb.FS(),
	})
	app.server = httpapi.HTTPServer(cfg.Server.Addr, app.router)
	app.dispatcher = outboxDispatcher
	app.exporter = auditExporter
	app.compensator = mergeCompensator

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
	// 后台投递循环跟随进程生命周期：ctx 结束时退出，Shutdown 里等待它收敛。
	bgCtx, bgCancel := context.WithCancel(ctx)
	a.bgCancel = bgCancel
	if a.dispatcher != nil {
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			a.dispatcher.Run(bgCtx)
		}()
	}
	if a.exporter != nil {
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			a.exporter.Run(bgCtx)
		}()
	}
	if a.compensator != nil {
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			a.compensator.Run(bgCtx)
		}()
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
	// 先停后台投递循环：它持有数据库连接，必须在关库之前收敛，
	// 否则会以"连接已关闭"刷一片错误日志。
	if a.bgCancel != nil {
		a.bgCancel()
		a.bgWG.Wait()
		a.bgCancel = nil
	}
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

// Accounts 返回账号体系端口（集成测试用：构造 source/target 账号）。
func (a *App) Accounts() domainaccount.Provider { return a.accounts }

// Redis 返回 Redis 客户端。
func (a *App) Redis() *redis.Client { return a.rdb }

// Config 返回配置。
func (a *App) Config() *Config { return a.cfg }

// CertifyProviders 断言渠道注册结果，供启动自检与测试使用。
func (a *App) RegisteredProviders() []provider.Metadata {
	return provider.Global().List()
}
