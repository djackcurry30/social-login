package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/application/accountsync"
	"github.com/djackcurry30/social-login/internal/application/authflow"
	"github.com/djackcurry30/social-login/internal/application/binding"
	"github.com/djackcurry30/social-login/internal/application/claimsync"
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
	infraratelimit "github.com/djackcurry30/social-login/internal/infrastructure/ratelimit"
	"github.com/djackcurry30/social-login/internal/infrastructure/webhook"
	httpapi "github.com/djackcurry30/social-login/internal/interfaces/http"
	"github.com/djackcurry30/social-login/internal/interfaces/http/handler"
	"github.com/djackcurry30/social-login/internal/interfaces/http/middleware"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/guards/breaker"
	"github.com/djackcurry30/social-login/internal/pkg/metrics"
	"github.com/djackcurry30/social-login/internal/pkg/tracing"

	// blank import 触发各渠道适配器的编译期注册（决策 D7）。
	// 新增渠道时改这一行即可，装配代码与核心编排都不需要动。
	_ "github.com/djackcurry30/social-login/internal/infrastructure/provider/adapters"
	wechatadapter "github.com/djackcurry30/social-login/internal/infrastructure/provider/adapters/wechat"

	// 管理端（/admin/v1）依赖：单独成一组 import，与业务端依赖视觉分隔。
	"github.com/djackcurry30/social-login/internal/application/accountclose"
	"github.com/djackcurry30/social-login/internal/application/adminapp"
	"github.com/djackcurry30/social-login/internal/application/adminapproval"
	"github.com/djackcurry30/social-login/internal/application/adminaudit"
	"github.com/djackcurry30/social-login/internal/application/adminchan"
	"github.com/djackcurry30/social-login/internal/application/adminevent"
	"github.com/djackcurry30/social-login/internal/application/admingrant"
	"github.com/djackcurry30/social-login/internal/application/adminidentity"
	"github.com/djackcurry30/social-login/internal/application/adminkey"
	"github.com/djackcurry30/social-login/internal/application/adminmerge"
	"github.com/djackcurry30/social-login/internal/application/adminobs"
	"github.com/djackcurry30/social-login/internal/application/adminsession"
	"github.com/djackcurry30/social-login/internal/application/adminuser"
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
	// appSync 是应用注册同步循环（契约 v1.1 §2.6）；nil 表示没有用户中心或已关闭。
	appSync *accountsync.Service
	// tracer 是链路追踪的生命周期持有者。nil 不可能发生在正常装配路径上
	// （关闭追踪时也是非 nil 的空壳），保留判断只是为 SkipDatabase 测试。
	tracer *tracing.Provider
	// logLevel 是日志级别的原子句柄，配置热更新用它改级别。
	logLevel *zap.AtomicLevel
	// reloader 是配置热更新器（管理端 /config/reload 与 SIGHUP 共用）。
	reloader *Reloader
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
	// ConfigPath 是配置文件路径。配置热更新要重新读它，因此必须在装配时记下来——
	// 进程启动后无法反推"-config"参数是什么。
	ConfigPath string
}

// New 装配运行实例。
func New(ctx context.Context, opts Options) (*App, error) {
	if opts.Config == nil {
		return nil, errs.New(errs.CodeConfigInvalid, "缺少配置")
	}
	cfg := opts.Config

	var (
		logger   = opts.Logger
		logLevel *zap.AtomicLevel
	)
	if logger == nil {
		var err error
		logger, logLevel, err = NewLoggerWithControl(cfg.Log)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Server.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	app := &App{cfg: cfg, log: logger, logLevel: logLevel}

	// 追踪尽早初始化：注册同步、outbox 等后台循环在 New 的尾部就开始装配，
	// 它们的出站调用要能带 traceparent，就必须先有全局 TracerProvider。
	//
	// 失败即终止启动：走到这里说明配置层已经校验过 endpoint 非空，
	// 再失败就是"地址/凭据/证书"这类环境问题，带病启动只会把问题
	// 推迟到"某天发现追踪一直没数据"。
	tracer, err := tracing.Init(ctx, cfg.Tracing.TracingOptions(Version), logger)
	if err != nil {
		return nil, errs.Wrap(errs.CodeConfigInvalid, "初始化链路追踪失败", err)
	}
	app.tracer = tracer

	keyManager, err := buildKeyManager(cfg, logger)
	if err != nil {
		return nil, err
	}
	claimHasher, err := buildClaimHasher(cfg, logger)
	if err != nil {
		return nil, err
	}
	appSecretHasher := buildAppSecretHasher(cfg, logger)

	signer, keyStore, err := buildSigner(cfg, logger)
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
	// J 组：凭证漂移记录。写端在登录链路（authflow），读与闭环端在管理端，
	// 因此在这里构造一次、两处共用——同一个事实不该有两个仓储实例。
	claimMismatchRepo := postgres.NewClaimMismatchRepository(db)
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
		// 已绑定用户的回源核对：状态闸门 + 平台侧凭证变更换绑。
		// 只在真实用户中心下启用：桩的账号在进程内存里，重启即空，
		// 核对会把所有老用户误判成"账号不存在"。
		AccountCheck: authflow.AccountCheckConfig{
			Enabled:            cfg.Account.Provider == "http",
			AllowOnUnavailable: cfg.Account.Gate.AllowOnUnavailable,
			Timeout:            cfg.Account.Gate.Timeout,
		},
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
		// J 组：回源核对失败时落一条漂移记录（§8.5）。
		// 这是 best-effort 写入，失败不影响登录。
		Mismatches: claimMismatchRepo,
		// 身份维度限流（rl:identity）。开关与阈值都跟随 ratelimit.enabled，
		// 与接入层的两档一起生效或一起关闭——分两个开关只会让人忘记打开。
		IdentityLimiter: infraratelimit.NewIdentityLimiter(
			rdb, cfg.RateLimit.Enabled, cfg.RateLimit.IdentityPerMinute),
		// 渠道日配额（rl:platform:{platform}:day）。
		PlatformQuota: infraratelimit.NewPlatformQuota(
			rdb, cfg.RateLimit.Enabled, cfg.RateLimit.PlatformDaily, cfg.RateLimit.PlatformDailyDefault),
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

	// 账号注销（数据合规）：关对端 → 断本地绑定 → 撤令牌 → 清凭证密文。
	//
	// 只在 provider 真的能关账号时才装配。装配了但 provider 不支持，
	// 会让用户点"注销"得到一个语法上成功、语义上什么都没发生的响应——
	// 所以服务内部也会二次检查（account.AccountCloser 类型断言）。
	accountCloseSvc := accountclose.New(accountclose.Deps{
		Tenant:     tenantSvc,
		Accounts:   accounts,
		Bindings:   bindingRepo,
		Identities: identityRepo,
		Sessions:   sessionRepo,
		Revocation: revocationStore,
		Claims:     claimRepo,
		Audit:      auditRepo,
		Logger:     logger,
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

	// --- 应用注册同步（契约 v1.1 §2.6）---
	//
	// 只在"真的有用户中心"时装配。StubProvider 没有注册能力，硬塞一个空实现
	// 会让管理端显示"已同步"，而实际上并不存在用户中心——一个会撒谎的状态
	// 比没有状态更糟，因为它会让人跳过排查。
	var appSyncSvc *accountsync.Service
	if registrar, ok := accounts.(domainaccount.AppRegistrar); ok && cfg.Account.Sync.Enabled {
		appSyncSvc = accountsync.New(accountsync.Deps{
			Apps:      appRepo,
			Registrar: registrar,
			Recorder:  appRepo,
			Logger:    logger,
			Interval:  cfg.Account.Sync.Interval,
			Timeout:   cfg.Account.Sync.Timeout,
			Workers:   cfg.Account.Sync.Workers,
		})
		app.appSync = appSyncSvc
	} else if !cfg.Account.Sync.Enabled {
		// 关掉同步是一个有后果的决定，必须喊出来：新建的应用不会注册，
		// 这些应用的登录会以 ACCOUNT.UNAVAILABLE 失败。
		logger.Warn("应用注册同步已被配置关闭（account.sync.enabled=false）：" +
			"新建应用不会注册到用户中心，这些应用的登录会被拒绝")
	} else {
		logger.Info("账号体系为内存桩，应用注册同步不启用（没有可注册的对端）")
	}

	// 把 nil 指针赋给接口变量后，接口本身不为 nil（typed nil），调用方法会
	// 进到 nil 接收者里 panic。所以这里显式判空后再赋值。
	var appSyncHook adminapp.AppSyncNotifier
	if appSyncSvc != nil {
		appSyncHook = appSyncSvc
	}

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
		AppSync:    appSyncHook,
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
		// 账号体系现状：stub 还是真实用户中心（见 §26 的进度标记）。
		AccountCenter: describeAccountCenter(cfg),
		// 应用总数：看板上的 apps_count。
		//
		// 这个口子此前没有接线，于是看板恒显示 0——库里有 160 个应用也一样。
		// 数字恒为 0 比没有这个数字更糟：它看起来像"还没人接入"。
		OverviewGetter: func(ctx context.Context) (adminobs.OverviewStats, error) {
			n, err := appRepo.Count(ctx)
			if err != nil {
				return adminobs.OverviewStats{}, err
			}
			return adminobs.OverviewStats{AppsCount: int(n)}, nil
		},
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
		// J 组的漂移数进总览（§15.4 I 组要求的"claim 不一致数"）。
		// 取不到只是这个字段为 0，不影响渠道健康的结果。
		OpenMismatches: claimMismatchRepo.CountOpen,
		Logger:         logger,
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

	// C 组 + J 组：身份、绑定与凭证一致性。
	//
	// Bindings 同时充当查询与干预入口：ListAdmin 走同一批过滤条件，
	// ForceUnbind/Transfer 在仓储内用事务写事件，避免"改了本地没发通知"。
	//
	// J 组的两块依赖刻意分开：
	//   ClaimAdmin  跨身份分页查询（含已撤销），核心 claimRepo 不做这类查询
	//   Mismatches  漂移记录的读与闭环；写入端口在 authflow 侧（见后）
	bindingAdminRepo := postgres.NewBindingAdminRepository(db)
	adminIdentitySvc := adminidentity.New(adminidentity.Deps{
		Identities:  postgres.NewIdentityAdminRepository(db),
		IdentityGet: identityRepo,
		Claims:      claimRepo,
		ClaimAdmin:  postgres.NewClaimAdminRepository(db),
		Mismatches:  claimMismatchRepo,
		Bindings:    bindingAdminRepo,
		Writer:      bindingAdminRepo,
		AdminAudit:  adminAuditRepo,
		Logger:      logger,
	})

	// K 组：管理员授权。
	//
	// 与 admin_users.role 并存取并集（见 admin.User.Can）：
	// 这样上线不需要迁移现有管理员，也不会因漏迁让人失去权限。
	adminGrantSvc := admingrant.New(admingrant.Deps{
		Grants:     postgres.NewAdminGrantRepository(db),
		Users:      adminUserRepo,
		AdminAudit: adminAuditRepo,
		Logger:     logger,
	})

	// M 组：管理员账号管理（§25 B 组）。
	//
	// 在这之前加人只能靠 cmd/adminseed 或直接改库：没有校验、没有审计、
	// 也没有"别把自己锁在门外"的护栏。
	adminUserSvc := adminuser.New(adminuser.Deps{
		Users:    adminUserRepo,
		Sessions: adminSessionRepo,
		Audit:    adminAuditRepo,
		Logger:   logger,
	})

	// F 组：签名密钥轮换。
	//
	// keyStore 可能为 nil（未配置 security.key_dir）：此时 rotate/retire
	// 会明确拒绝，而不是只改内存造出"轮换成功"的假象。
	var keyStorePort adminkey.KeyStore
	if keyStore != nil {
		keyStorePort = keyStore
	}
	adminKeySvc := adminkey.New(adminkey.Deps{
		Signer:     signer,
		Store:      keyStorePort,
		AdminAudit: adminAuditRepo,
		Logger:     logger,
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

	// 双人复核：审批单仓储 + 用例。表在 00008 迁移里建。
	approvalRepo := postgres.NewAdminApprovalRepository(db)
	approvalSvc := adminapproval.New(adminapproval.Deps{
		Store: approvalRepo,
		// 审批的生命周期写进 admin_audit_logs：审计查询页要能看到
		// "谁申请、谁批准、谁执行"，只写普通日志等于查不到。
		Audit: adminAuditRepo,
		Log:   logger,
	})

	adminLoginSvc := adminhandler.NewLoginService(adminhandler.LoginServiceDeps{
		Users:    adminUserRepo,
		Sessions: adminSessionRepo,
		Logger:   logger,
	})

	// 管理端被用来"启用"才会挂上路由；为保持简洁第一期默认挂上。
	adminDeps := &adminhttp.RouterDeps{
		Logger:          logger,
		AuthSessions:    adminSessionRepo,
		AuthUsers:       adminUserRepo,
		AuthLogin:       adminLoginSvc,
		AdminApp:        adminAppSvc,
		AdminChan:       adminChanSvc,
		AdminObs:        adminObsSvc,
		AdminEvent:      adminEventSvc,
		AdminAudit:      adminAuditSvc,
		AdminMerge:      adminMergeSvc,
		AdminIdentity:   adminIdentitySvc,
		AdminSession:    adminSessionSvc,
		AdminKey:        adminKeySvc,
		AdminGrant:      adminGrantSvc,
		AdminUser:       adminUserSvc,
		Approvals:       approvalSvc,
		ApprovalActions: approvalActionSet(cfg.Admin.ApprovalRequiredActions),
	}
	_ = adminDeps

	// 指标注册表提前到这里：接收端（claim.invalidated）与路由都要它。
	// 后面那一大段 gauge 注册仍留在原处，只把"创建"提前，避免再造第二个注册表。
	metricsReg := metrics.NewRegistry()

	// 用户中心推来的 claim 失效通知。
	//
	// 这是【反向】依赖（UC → 本服务），与 account provider 的正向依赖
	// 互不冲突：两边各有一个受控的内部接口，谁也不读对方的库。
	claimInvalidatedCtr := metricsReg.Counter("social_login_claim_invalidated_total",
		"按用户中心通知失效 claim 的次数", "result")
	claimSyncSvc := claimsync.New(claimsync.Deps{
		Apps:     appRepo,
		Bindings: bindingRepo,
		Claims:   claimRepo,
		Audit:    auditRepo,
		Metrics:  claimSyncMetrics{ctr: claimInvalidatedCtr},
		Log:      logger,
	})

	// --- 接入层 ---
	h := handler.New(handler.Deps{
		Tenant:       tenantSvc,
		AuthFlow:     authflowSvc,
		Tokens:       tokenSvc,
		Bindings:     bindingSvc,
		Notify:       notifySvc,
		Merge:        mergeSvc,
		AccountClose: accountCloseSvc,
		ClaimsSync:   claimSyncSvc,
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

	// 入站限流（§6.3）。未启用时 Limiter 仍构造出来但 Enabled()=false，
	// 路由装配里会据此跳过挂载。
	limiter := middleware.NewLimiter(rdb, middleware.LimitConfig{
		Enabled:         cfg.RateLimit.Enabled,
		NotifyPerMinute: cfg.RateLimit.NotifyPerMinute,
		AppIPPerMinute:  cfg.RateLimit.AppIPPerMinute,
	})

	// 配置热更新：只热更日志级别与两档入站限流阈值，其余返回"需重启"。
	// 装配在这里是因为它同时需要 limiter 与日志级别句柄。
	app.reloader = NewReloader(configPath(opts), cfg, logLevel, limiter, logger)
	adminDeps.ConfigReload = app.reloader

	// --- 指标注册（架构 §11）---
	//
	// 只注册"出事时必须能看见"的几项，不做无差别埋点：
	//
	//	HTTP 请求数与耗时（中间件自动采集，覆盖全部端点与状态码）
	//	claim 漂移未闭环数          —— 数据一致性探针
	//	outbox 死信 / 待投递         —— 外发链路是否卡住
	//	merge 补偿滞后秒数           —— 跨服务合并是否卡住
	//
	// 登录成功率不单独建指标：/v1/oauth/callback 的 2xx 比例就是它，
	// 从 HTTP 指标里算即可。为它再维护一套埋点只会多一个漂移的口径。
	// 采集时查库：用带超时的独立 context，避免慢查询拖住 /metrics 端点。
	gatherCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 2*time.Second)
	}

	metricsReg.GaugeFunc("social_login_claim_mismatch_open",
		"未闭环的凭证漂移数（非 0 表示有用户本该被归并、但被拦住了）",
		func() float64 {
			ctx, cancel := gatherCtx()
			defer cancel()
			n, err := claimMismatchRepo.CountOpen(ctx)
			if err != nil {
				logger.Warn("采集凭证漂移数失败", zap.Error(err))
				return 0
			}
			return float64(n)
		})

	// 死信与待投递分开看：pending 高说明投递慢（可自愈），
	// dead 非 0 说明已经放弃重试（必须人工处理）。
	metricsReg.GaugeFunc("social_login_outbox_dead",
		"投递重试耗尽的死信数（非 0 需要人工重投或丢弃）",
		func() float64 {
			ctx, cancel := gatherCtx()
			defer cancel()
			backlog, err := eventRepo.OutboxBacklog(ctx)
			if err != nil {
				logger.Warn("采集事件积压失败", zap.Error(err))
				return 0
			}
			return float64(backlog["dead"])
		})
	metricsReg.GaugeFunc("social_login_outbox_pending",
		"待投递事件数（持续升高说明投递跟不上）",
		func() float64 {
			ctx, cancel := gatherCtx()
			defer cancel()
			backlog, err := eventRepo.OutboxBacklog(ctx)
			if err != nil {
				logger.Warn("采集事件积压失败", zap.Error(err))
				return 0
			}
			return float64(backlog["pending"])
		})

	metricsReg.GaugeFunc("social_login_merge_compensation_lag_seconds",
		"最久未推进的合并操作已等待秒数（架构 §11 的 merge_compensation_lag_seconds）",
		func() float64 {
			ctx, cancel := gatherCtx()
			defer cancel()
			sec, err := mergeRepo.OldestPendingSeconds(ctx)
			if err != nil {
				logger.Warn("采集合并补偿滞后失败", zap.Error(err))
				return 0
			}
			return sec
		})

	// 应用注册同步的失败数：这是"某个应用的所有登录都挂"的唯一先行指标。
	//
	// 为什么用采集时查库而不是同步失败时 Inc 一个计数器：需要的是"当前还坏着
	// 几个"（MarkUCSynced 会清空 uc_sync_error，所以该列非空即"还没修好"），
	// 而累计计数只增不减，告警会因为历史失败一直处于 firing。
	//
	// 挂掉时返回 0 而不是保留上一次的值：数据库不可用时别的告警（连接池、
	// HTTP 5xx）已经会响，这里再叠加一条只会产生噪音。
	metricsReg.GaugeFunc("social_login_uc_sync_failed",
		"当前未同步到用户中心的应用数（非 0 表示这些应用的登录会失败）",
		func() float64 {
			ctx, cancel := gatherCtx()
			defer cancel()
			n, err := appRepo.CountSyncFailed(ctx)
			if err != nil {
				logger.Warn("采集应用同步失败数失败", zap.Error(err))
				return 0
			}
			return float64(n)
		})

	// 应用总数：单独暴露只为让"同步失败数"有分母。
	//
	// 没有它，"uc_sync_failed == apps_total" 就只能靠人眼看管理端，
	// 而"全挂"和"挂了一个"的处置完全不同（前者查对端，后者查该应用配置）。
	metricsReg.GaugeFunc("social_login_apps_total",
		"应用总数（用于判断同步失败是单租户问题还是全链路问题）",
		func() float64 {
			ctx, cancel := gatherCtx()
			defer cancel()
			n, err := appRepo.Count(ctx)
			if err != nil {
				logger.Warn("采集应用总数失败", zap.Error(err))
				return 0
			}
			return float64(n)
		})

	app.router = httpapi.NewRouter(httpapi.RouterDeps{
		Handler:       h,
		Tenant:        tenantSvc,
		Tokens:        tokenSvc,
		SecretHasher:  appSecretHasher,
		Limiter:       limiter,
		Logger:        logger,
		Admin:         adminDeps,
		WebFS:         embedweb.FS(),
		Metrics:       metricsReg,
		ServiceName:   cfg.Tracing.TracingOptions(Version).ServiceName,
		InternalToken: cfg.Internal.ServiceToken,
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
	if a.appSync != nil {
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			a.appSync.Run(bgCtx)
		}()
	}
	if a.reloader != nil {
		// SIGHUP 热更新。与 /config/reload 走同一个 Reloader，避免两条路径
		// 各有一套"哪些生效"的判断逻辑。
		a.bgWG.Add(1)
		go func() {
			defer a.bgWG.Done()
			a.watchReloadSignal(bgCtx)
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
	// 追踪刷盘放在 HTTP 关闭之后、日志与存储关闭之前：
	//   - 之后：在途请求的 span 已经 End，能赶上最后一批；
	//   - 之前：日志还活着，导出失败能留痕。
	// 漏掉这一步的后果是"每次部署前后的那几十秒永远没有 trace"——
	// 而那恰好是最容易出问题的窗口。
	if a.tracer != nil {
		if err := a.tracer.Shutdown(ctx); err != nil {
			a.log.Warn("链路追踪刷盘失败（不影响退出）", zap.Error(err))
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

// approvalActionSet 把动作列表转成集合（路由用 map 查，避免每次比较切片）。
func approvalActionSet(actions []string) map[string]bool {
	if len(actions) == 0 {
		return nil
	}
	out := make(map[string]bool, len(actions))
	for _, a := range actions {
		out[a] = true
	}
	return out
}

// claimSyncMetrics 把 claim 失效的处理结果接到指标上。
//
// revoked 不进标签（基数不可控），只进日志——指标回答"有多少次通知、
// 其中多少被忽略"，"撤销了多少行"是排障细节。
type claimSyncMetrics struct{ ctr *metrics.Counter }

func (m claimSyncMetrics) RecordClaimInvalidated(result string, _ int) {
	m.ctr.Inc(result)
}

// configPath 返回生效的配置文件路径（未指定时取默认值）。
func configPath(opts Options) string {
	if opts.ConfigPath != "" {
		return opts.ConfigPath
	}
	return "configs/config.yaml"
}

// Router 返回 HTTP 路由，供集成测试直接使用（无需监听端口）。
func (a *App) Router() http.Handler { return a.router }

// Logger 返回日志器。
func (a *App) Logger() *zap.Logger { return a.log }

// DB 返回数据库句柄。
func (a *App) DB() *gorm.DB { return a.db }

// Accounts 返回账号体系端口（集成测试用：构造 source/target 账号）。
func (a *App) Accounts() domainaccount.Provider { return a.accounts }

// AppSync 返回应用注册同步服务；nil 表示没有用户中心或同步已关闭。
//
// 暴露给集成测试：验收"对账之后这个应用才能在用户中心登录"时，需要一个
// 能主动触发一轮对账的入口，而不是等 5 分钟的定时器。
func (a *App) AppSync() *accountsync.Service { return a.appSync }

// Redis 返回 Redis 客户端。
func (a *App) Redis() *redis.Client { return a.rdb }

// Config 返回配置。
func (a *App) Config() *Config { return a.cfg }

// CertifyProviders 断言渠道注册结果，供启动自检与测试使用。
func (a *App) RegisteredProviders() []provider.Metadata {
	return provider.Global().List()
}
