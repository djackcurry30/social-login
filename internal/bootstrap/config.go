// Package bootstrap 负责配置加载、日志装配、依赖组装与优雅退出。
//
// 装配的顺序是有讲究的：日志 → 配置 → 加密 → 存储 → 领域服务 → 应用服务 → 接入层。
// 任何一步失败都直接终止启动，而不是降级运行——本服务是登录链路上的关键节点，
// 带病启动比不启动更糟：它会把错误以"用户登录失败"的形式散播到所有业务应用。
package bootstrap

import (
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/djackcurry30/social-login/internal/application/accountsync"
	"github.com/djackcurry30/social-login/internal/domain/approval"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/tracing"
)

// Config 是全量配置。
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Cache    CacheConfig    `mapstructure:"cache"`
	Security SecurityConfig `mapstructure:"security"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Account  AccountConfig  `mapstructure:"account"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Log      LogConfig      `mapstructure:"log"`
	Migrate  MigrateConfig  `mapstructure:"migrate"`
	// ProviderGuard 是渠道熔断配置（服务级，不能下放到应用）。
	ProviderGuard ProviderGuardConfig `mapstructure:"provider_guard"`
	// Audit 是审计相关配置（H 组异步导出）。
	Audit AuditConfig `mapstructure:"audit"`
	// Merge 是账号合并配置（第三期）。
	Merge MergeConfig `mapstructure:"merge"`
	// SMS 是验证码短信通道配置。
	SMS SMSConfig `mapstructure:"sms"`
	// RateLimit 是入站限流配置（架构 §6.3）。
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	// Tracing 是链路追踪配置（OpenTelemetry，OTLP/HTTP 上报）。
	Tracing TracingConfig `mapstructure:"tracing"`
	// Admin 是管理端的横切配置。
	Admin AdminConfig `mapstructure:"admin"`
	// Internal 是服务间内部接口的配置。
	Internal InternalConfig `mapstructure:"internal"`
}

// InternalConfig 是内部接口（X-Service-Token）配置。
//
// 目前只有一个接收端点：用户中心推来的 claim.invalidated。
// 令牌独立于业务方的 app_secret 与用户令牌：它代表"另一个内部服务"，
// 泄漏范围应该只覆盖内部接口，而不是能签发令牌的那套凭据。
type InternalConfig struct {
	ServiceToken string `mapstructure:"service_token"`
}

// AdminConfig 是管理端配置。
type AdminConfig struct {
	// ApprovalRequiredActions 是需要双人复核的动作（见 domain/approval 的常量）。
	//
	// 默认值随环境不同：
	//   release 且未配置 → 三个高危轮换动作全部要求审批（安全默认）
	//   debug 且未配置   → 不要求审批（本地流程不必走两遍账号）
	//
	// 这条规则刻意"生产默认安全"，因为漏配的后果是"高危操作没有第二个人"，
	// 而调试环境漏配只意味着少点一次点击。
	ApprovalRequiredActions []string `mapstructure:"approval_required_actions"`
}

// TracingConfig 是链路追踪配置。
//
// 默认关闭：多数开发/测试环境没有 collector，开着只会让进程每分钟打一批
// "导出失败"的 Warn，而真正的问题被这些噪音盖住。
type TracingConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// ServiceName 出现在 trace 的 service.name 上。两个服务必须不同，
	// 否则在 Jaeger 的 service 下拉框里分不出是谁发的 span。
	ServiceName string `mapstructure:"service_name"`
	// Environment 是部署环境标识（dev / staging / prod）。
	// 为空时回落到 auth.env：生产上这两个值本来就该一致，
	// 允许单独配置是为了"生产配置、旁路验证"这种场景。
	Environment string `mapstructure:"environment"`
	// Endpoint 是 OTLP/HTTP 接收地址，例如 http://otel-collector:4318。
	Endpoint string `mapstructure:"endpoint"`
	// Insecure 表示明文传输（内网 collector 的常态）。
	Insecure bool `mapstructure:"insecure"`
	// SampleRatio 是入口采样比例（0–1）。见 pkg/tracing.Config.SampleRatio。
	SampleRatio float64 `mapstructure:"sample_ratio"`
	// ExportTimeout 是单批导出超时，也是退出时刷盘的上限。
	ExportTimeout time.Duration `mapstructure:"export_timeout"`
	// BatchTimeout 是批量导出的最大攒批时间。
	BatchTimeout time.Duration `mapstructure:"batch_timeout"`
	// MaxQueueSize 是待导出 span 的内存队列长度（满则丢弃新 span）。
	MaxQueueSize int `mapstructure:"max_queue_size"`
	// Headers 是导出请求附加头（collector 侧鉴权用）。
	Headers map[string]string `mapstructure:"headers"`
}

// TracingOptions 把配置翻译成 tracing 包能直接消费的结构。
//
// version 由 bootstrap 注入，避免 pkg 反向依赖服务版本号。
func (t TracingConfig) TracingOptions(version string) tracing.Config {
	name := t.ServiceName
	if name == "" {
		name = "social-login"
	}
	return tracing.Config{
		Enabled:        t.Enabled,
		ServiceName:    name,
		ServiceVersion: version,
		Environment:    t.Environment,
		Endpoint:       t.Endpoint,
		Insecure:       t.Insecure,
		SampleRatio:    t.SampleRatio,
		Headers:        t.Headers,
		ExportTimeout:  t.ExportTimeout,
		BatchTimeout:   t.BatchTimeout,
		MaxQueueSize:   t.MaxQueueSize,
	}
}

// RateLimitConfig 是入站限流参数。
//
// 默认关闭：限流阈值与业务量强相关，猜一个值上线比不限制更危险——
// 阈值偏低时正常用户会成片收到 429，而运维的第一反应往往是"服务坏了"。
type RateLimitConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// NotifyPerMinute 是 /v1/oauth/notify/{platform} 的上限（平台 + IP）。
	// 这个端点无鉴权、公开可达，是被刷的首选目标。
	NotifyPerMinute int `mapstructure:"notify_per_minute"`
	// AppIPPerMinute 是业务端应用的上限（app + 客户端 IP）。
	AppIPPerMinute int `mapstructure:"app_ip_per_minute"`
	// IdentityPerMinute 是单个三方身份每分钟的上限（rl:identity，防撞库）。
	//
	// 与上面两档不同，它作用在授权流程内部：中间件看不到身份，
	// 只有平台返回 open_id、本服务 Upsert 出 identity 之后才有主语。
	// 阈值取 30：正常用户一分钟内不可能完成 30 次完整授权往返。
	// 留空或 <=0 时取 infrastructure/ratelimit 的默认值（30）。
	IdentityPerMinute int `mapstructure:"identity_per_minute"`
	// PlatformDaily 是渠道日配额（rl:platform:{platform}:day），键为平台标识。
	//
	// 取值必须【小于】渠道后台的日上限：留 10%~20% 余量，用于健康探测、
	// 补偿任务等配额之外的调用。填 0 或省略表示该平台不限。
	//
	// 超限的行为是"快速失败"（PROVIDER.QUOTA_EXCEEDED，不排队）：
	// 排队只会把请求堆在内存里，然后在配额恢复的瞬间形成尖峰。
	PlatformDaily map[string]int `mapstructure:"platform_daily"`
	// PlatformDailyDefault 是未在 PlatformDaily 里列出的渠道的默认上限，0 = 不限。
	PlatformDailyDefault int `mapstructure:"platform_daily_default"`
}

// SMSConfig 是短信通道配置。
type SMSConfig struct {
	// Provider 取值 log | none。
	//
	//	log  把验证码打进日志（仅开发/测试）。release 模式下启动会被拒绝——
	//	     用户收不到码，表现为"合并流程走到一半没反应"，比启动失败难查得多。
	//	none 显式声明未接通道：发码接口会返回 CONFIG.INVALID 而不是假装成功。
	Provider string `mapstructure:"provider"`
}

// MergeConfig 是账号合并的运行期配置。
//
// ⚠️ 这里没有"是否启用合并"的开关：合并是应用级策略
// （applications.policy.merge.mode），不是服务级开关。服务级关掉合并会让
// 所有 auto 应用静默退化成 manual，与 §7.5.4「静默降级比报错更危险」相悖。
type MergeConfig struct {
	// RemoteIdempotent 声明用户中心的 Merge 是否真正按幂等键去重（§D3）。
	//
	// 为 false（默认）时，补偿任务【不会】自动重试失败的合并，只把记录标为
	// dead 等人工推进。理由：非幂等的 Merge 被重复执行会重复迁移订单/资产，
	// 比"合并没做完"严重得多（§7.3 明确要求）。
	//
	// 接入真实用户中心后，必须在其契约确认幂等后再打开。
	RemoteIdempotent bool `mapstructure:"remote_idempotent"`
}

// AuditConfig 是审计配置。
type AuditConfig struct {
	// ExportDir 是审计导出文件的落盘目录。为空时导出 worker 不启动——
	// 静默空转会让"提交了却永远 pending"变成谜案，所以宁可明确不启动并打日志。
	//
	// 生产建议挂独立卷：导出文件是临时产物，不该和密钥、日志混在同一层。
	ExportDir string `mapstructure:"export_dir"`
	// ExportFileTTL 是导出文件保留期，默认 7 天。
	ExportFileTTL time.Duration `mapstructure:"export_file_ttl"`
	// ExportWorkerEnabled 允许在"不落盘"的环境（如只读容器）关掉 worker。
	ExportWorkerEnabled *bool `mapstructure:"export_worker_enabled"`
}

// ExportWorkerOn 判断是否启用导出 worker。
//
// 用 *bool 而不是 bool：零值 false 会让"没写这一项"与"显式关闭"无法区分，
// 而默认应该是【启用】（配置了 export_dir 就该跑）。未配置时按目录是否为空判断。
func (a AuditConfig) ExportWorkerOn() bool {
	if a.ExportWorkerEnabled != nil {
		return *a.ExportWorkerEnabled
	}
	return a.ExportDir != ""
}

// ServerConfig 是 HTTP 服务配置。
type ServerConfig struct {
	Addr string `mapstructure:"addr"`
	// Mode 是 debug | release。release 会启用一组"生产必须项"的强校验。
	Mode string `mapstructure:"mode"`
	// CallbackBaseURL 是本服务对外可访问的基地址，用于拼三方回调地址。
	// ⚠️ 必须与平台侧配置的回调域名完全一致，且通常是 HTTPS。
	CallbackBaseURL string `mapstructure:"callback_base_url"`
	// Issuer 是 JWT 的 iss，也是 OIDC Discovery 的 issuer。
	Issuer string `mapstructure:"issuer"`
	// ShutdownTimeout 是优雅退出时等待在途请求的时间。
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

// IsProduction 判断是否生产模式。
func (s ServerConfig) IsProduction() bool {
	return strings.EqualFold(s.Mode, "release") || strings.EqualFold(s.Mode, "prod")
}

// DatabaseConfig 是数据库配置。
type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	SlowThreshold   time.Duration `mapstructure:"slow_threshold"`
	LogSQL          bool          `mapstructure:"log_sql"`
}

// CacheConfig 是 Redis 配置。
type CacheConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	PoolSize int    `mapstructure:"pool_size"`
}

// KMSConfig 是托管密钥（KEK）配置。
//
// 契约只有两个动作（wrap / unwrap DEK），由 KMS 前面的薄网关映射到具体厂商
// （AWS KMS / 阿里云 KMS / Vault Transit 均可）。详见
// internal/infrastructure/crypto/kek_remote.go 的文件头。
type KMSConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	BaseURL string `mapstructure:"base_url"`
	// KeyID 是 KMS 侧的密钥标识；留空则回落到 security.kek_id。
	KeyID string `mapstructure:"key_id"`
	// Token 是调用 KMS 网关的 Bearer 凭据（内网部署可留空）。
	Token   string        `mapstructure:"token"`
	Timeout time.Duration `mapstructure:"timeout"`
	// DEKCacheTTL 是解包后 DEK 的内存缓存时长。
	//
	// 默认 5 分钟：渠道凭据在每次登录时都要解密，而 KMS 一次往返 5–20ms。
	// 设为 0 表示不缓存（每次登录都打一次 KMS，只在排障时值得这么做）。
	DEKCacheTTL  time.Duration `mapstructure:"dek_cache_ttl"`
	DEKCacheSize int           `mapstructure:"dek_cache_size"`
}

// SecurityConfig 是密钥与哈希盐配置。
type SecurityConfig struct {
	// MasterKey 是信封加密的主密钥（Base64，32 字节）。
	// ⚠️ 生产环境必须由 KMS 或密钥管理系统下发，且不得进版本库。
	MasterKey string `mapstructure:"master_key"`
	// KEKID 是主密钥版本标识，写入 app_provider_configs.secret_dek_id，
	// 用于密钥轮换时区分"哪一版密钥加密的凭据"。
	KEKID string `mapstructure:"kek_id"`
	// KMS 是托管密钥配置。启用后 master_key 不再需要，也不需要出现在
	// 本服务的任何配置文件或环境变量里。
	KMS KMSConfig `mapstructure:"kms"`
	// ClaimSalt 是身份凭证哈希的静态盐。
	//
	// ⚠️ 绝不能用每行随机盐：claim 的核心用途就是"按手机号反查身份"，
	// 随机盐会让同一号码每次算出不同哈希，该功能直接失效。
	ClaimSalt string `mapstructure:"claim_salt"`
	// AppSecretSalt 是应用密钥哈希的静态盐。
	AppSecretSalt string `mapstructure:"app_secret_salt"`
	// KeyDir 是签名密钥状态文件的目录（F 组轮换用）。
	//
	// 留空则不支持管理端轮换：rotate/retire 会因为没有持久化而拒绝执行——
	// 只改内存的轮换在重启后就失效，那是最容易骗过运维的假象。
	//
	// ⚠️ 这是"没有 KMS 时的可用实现"（§8.3 要求私钥由 KMS 托管）。
	// 目录权限 0700、文件 0600，且必须排除在版本库与公开备份之外。
	KeyDir string `mapstructure:"key_dir"`
}

// JWTConfig 是签名配置。
type JWTConfig struct {
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
	// SigningKeys 是签名密钥列表。第一把用于签名，其余仅发布公钥。
	// 为空时启动会临时生成一把（仅允许在非生产模式）。
	SigningKeys []SigningKeyConfig `mapstructure:"signing_keys"`
}

// SigningKeyConfig 是一把签名密钥的配置。
type SigningKeyConfig struct {
	KID string `mapstructure:"kid"`
	// PrivateKeyFile 是 PEM 私钥文件路径。文件权限应为 0600，且不进版本库。
	PrivateKeyFile string `mapstructure:"private_key_file"`
}

// AccountConfig 是账号体系（用户中心）配置。
type AccountConfig struct {
	// Provider 是 stub | http。stub 仅供开发与测试。
	Provider string      `mapstructure:"provider"`
	HTTP     HTTPAccount `mapstructure:"http"`
	// Sync 是应用注册同步的开关与节奏（契约 v1.1 §2.6）。
	//
	// 用户中心按 app_key 隔离账号空间，未注册的应用一律 400 APP.UNKNOWN。
	// 所以"应用已注册"是登录的前置条件，这一组配置不是可选的润色项。
	Sync AccountSync `mapstructure:"sync"`
	// Gate 是"已绑定用户登录时回源核对账号"的策略（P1）。
	Gate AccountGate `mapstructure:"gate"`
}

// AccountGate 是回源核对的开关与取舍。
//
// 这一组配置存在的唯一理由：它决定了"用户中心挂了会不会导致所有登录失败"。
// 架构 §6.2 选的是会——无法确认账号是否被停用，就不签发令牌。这是安全优先
// 的默认；牺牲的是可用性（对端故障 = 全站登录故障）。
type AccountGate struct {
	// AllowOnUnavailable 为 true 时，用户中心不可用仍放行登录。
	//
	// 打开前请确认能接受：在用户中心故障窗口内，已被停用/注销的账号
	// 依然可以登录（因为本服务无从得知）。
	AllowOnUnavailable bool `mapstructure:"allow_on_unavailable"`
	// Timeout 是单次回源超时，默认 1s。
	Timeout time.Duration `mapstructure:"timeout"`
}

// AccountSync 是应用注册同步的配置。
type AccountSync struct {
	// Enabled 关闭后不再同步（也不启动对账循环）。
	//
	// 存在的意义是应急：如果用户中心侧出问题且暂时无法修，关掉它可以避免
	// 每 5 分钟一轮的无谓调用与错误日志。关掉之后新建的应用【不会】注册，
	// 该应用登录会 400 APP.UNKNOWN——这个代价必须由运维知情地承担。
	Enabled bool `mapstructure:"enabled"`
	// Interval 是全量对账周期，默认 5m。
	Interval time.Duration `mapstructure:"interval"`
	// Timeout 是单次注册调用的超时，默认 3s（与登录链路一致）。
	Timeout time.Duration `mapstructure:"timeout"`
	// Workers 是单轮对账的并发数，默认 4。
	Workers int `mapstructure:"workers"`
}

// HTTPAccount 是用户中心 HTTP 客户端配置。
type HTTPAccount struct {
	BaseURL string `mapstructure:"base_url"`
	// Token 是服务间鉴权用的 Bearer token。
	//
	// 与渠道凭据一样属于密钥材料：生产环境应由 KMS / 密钥管理系统注入
	// 环境变量（SOCIAL_LOGIN_ACCOUNT_HTTP_TOKEN），不要写进配置文件。
	Token string `mapstructure:"token"`
	// Timeout 是单次调用总超时，默认 3s。
	//
	// 比 httpx 的默认 5s 短：用户中心是登录链路的同步依赖，
	// 整条链路预算 8s，Exchange+UserInfo 已占 5s。
	Timeout time.Duration `mapstructure:"timeout"`
}

// AuthConfig 是授权流程配置。
type AuthConfig struct {
	// Env 用于筛选渠道配置（prod | test），对应 app_provider_configs.env。
	Env string `mapstructure:"env"`
	// ExchangeTimeout 是 Exchange + UserInfo 的独立超时（架构 §5.7 第 3 条）。
	ExchangeTimeout time.Duration `mapstructure:"exchange_timeout"`
}

// LogConfig 是日志配置。
type LogConfig struct {
	Level string `mapstructure:"level"`
	// Format 是 json | console。生产用 json（便于采集），开发用 console（便于阅读）。
	Format string `mapstructure:"format"`
	// File 为空时输出到 stdout。非空时按 lumberjack 规则切割。
	File       string `mapstructure:"file"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAgeDays int    `mapstructure:"max_age_days"`
}

// MigrateConfig 是数据库迁移配置。
type MigrateConfig struct {
	// Enabled 决定启动时是否自动执行迁移。
	//
	// 生产环境建议置为 false，由发布流程单独执行迁移——
	// 让应用启动顺带改 schema，会在多副本滚动发布时出现并发迁移与半途失败。
	Enabled bool `mapstructure:"enabled"`
}

// ProviderGuardConfig 是渠道熔断配置（架构 §5.6.5）。
//
// 为什么是【服务级】而不是 applications.policy：
// 熔断保护的是所有应用共享的连接池与 goroutine，平台故障也是全局的。
// 一旦允许按应用配置，就会出现"App1 关了熔断、消耗的是两个应用共享的资源"，
// 等于一个应用可以替所有应用关掉保护。
type ProviderGuardConfig struct {
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
}

// CircuitBreakerConfig 对应 §5.6.5 的 YAML。
type CircuitBreakerConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Granularity   string `mapstructure:"granularity"` // platform | platform_scene
	WindowSeconds int    `mapstructure:"window_seconds"`
	BucketSeconds int    `mapstructure:"bucket_seconds"`
	MinRequests   int    `mapstructure:"min_requests"`

	FailureRatio        float64       `mapstructure:"failure_ratio"`
	TimeoutRatio        float64       `mapstructure:"timeout_ratio"`
	SlowRatio           float64       `mapstructure:"slow_ratio"`
	SlowThreshold       time.Duration `mapstructure:"slow_threshold"`
	ConsecutiveTimeouts int           `mapstructure:"consecutive_timeouts"`
	ConsecutiveFailures int           `mapstructure:"consecutive_failures"`

	OpenDuration     time.Duration `mapstructure:"open_seconds"`
	HalfOpenRequests uint32        `mapstructure:"half_open_requests"`
}

// Load 读取配置：默认值 → 配置文件 → 环境变量（SOCIAL_LOGIN_ 前缀，下划线分层）。
func Load(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, errs.Wrap(errs.CodeConfigInvalid, "读取配置文件失败", err).
				WithDetail("path", path)
		}
	}

	// 环境变量覆盖：SOCIAL_LOGIN_DATABASE_DSN → database.dsn
	//
	// 环境变量优先级高于配置文件，是为了让密钥类配置（主密钥、数据库密码）
	// 可以完全不落到文件里——文件更容易被误提交。
	v.SetEnvPrefix("SOCIAL_LOGIN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, errs.Wrap(errs.CodeConfigInvalid, "解析配置失败", err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", "0.0.0.0:8080")
	v.SetDefault("server.mode", "debug")
	v.SetDefault("server.callback_base_url", "http://localhost:8080")
	v.SetDefault("server.issuer", "http://localhost:8080")
	v.SetDefault("server.shutdown_timeout", "15s")

	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "1h")
	v.SetDefault("database.slow_threshold", "200ms")
	v.SetDefault("database.log_sql", false)

	v.SetDefault("cache.addr", "127.0.0.1:6379")
	v.SetDefault("cache.db", 0)
	v.SetDefault("cache.pool_size", 20)

	v.SetDefault("security.kek_id", "local-kek-v1")

	v.SetDefault("jwt.access_token_ttl", "15m")
	v.SetDefault("jwt.refresh_token_ttl", "720h")

	v.SetDefault("account.provider", "stub")
	v.SetDefault("account.http.timeout", "3s")
	// 应用注册同步默认开启：它在 stub 模式下自动不生效（没有注册端口），
	// 所以"默认开"不会给演示环境带来额外失败路径。
	v.SetDefault("account.sync.enabled", true)
	v.SetDefault("account.sync.interval", "5m")
	v.SetDefault("account.sync.timeout", "3s")
	v.SetDefault("account.sync.workers", 4)

	v.SetDefault("auth.env", "prod")
	v.SetDefault("auth.exchange_timeout", "5s")

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.max_size_mb", 128)
	v.SetDefault("log.max_backups", 10)
	v.SetDefault("log.max_age_days", 30)

	// 追踪：默认关闭；开启时按 10% 采样。10% 是"够用来定位故障"与
	// "不会把 collector 打满"之间的经验值，压测后按实际量再调。
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_name", "social-login")
	v.SetDefault("tracing.endpoint", "")
	v.SetDefault("tracing.insecure", true)
	v.SetDefault("tracing.sample_ratio", 0.1)
	v.SetDefault("tracing.export_timeout", "5s")
	v.SetDefault("tracing.batch_timeout", "5s")
	v.SetDefault("tracing.max_queue_size", 2048)

	v.SetDefault("migrate.enabled", true)

	// 渠道熔断默认值：与架构 §5.6.5 完全一致。
	v.SetDefault("provider_guard.circuit_breaker.enabled", true)
	v.SetDefault("provider_guard.circuit_breaker.granularity", "platform")
	v.SetDefault("provider_guard.circuit_breaker.window_seconds", 60)
	v.SetDefault("provider_guard.circuit_breaker.bucket_seconds", 10)
	v.SetDefault("provider_guard.circuit_breaker.min_requests", 20)
	v.SetDefault("provider_guard.circuit_breaker.failure_ratio", 0.5)
	v.SetDefault("provider_guard.circuit_breaker.timeout_ratio", 0.3)
	v.SetDefault("provider_guard.circuit_breaker.slow_ratio", 0.5)
	v.SetDefault("provider_guard.circuit_breaker.slow_threshold", "2s")
	v.SetDefault("provider_guard.circuit_breaker.consecutive_timeouts", 5)
	v.SetDefault("provider_guard.circuit_breaker.consecutive_failures", 10)
	v.SetDefault("provider_guard.circuit_breaker.open_seconds", "30s")
	v.SetDefault("provider_guard.circuit_breaker.half_open_requests", 3)

	// 审计导出：默认落在 ./var/exports（相对进程工作目录）。
	// 配置为空字符串即关闭 worker（见 AuditConfig.ExportWorkerOn）。
	v.SetDefault("audit.export_dir", "./var/exports")
	v.SetDefault("audit.export_file_ttl", "168h")

	// 合并补偿默认关闭自动重试（安全默认）。
	v.SetDefault("merge.remote_idempotent", false)

	// 短信通道默认日志实现（仅开发可用，见 normalizeAndValidate 的生产校验）。
	v.SetDefault("sms.provider", "log")

	// 签名密钥状态目录：默认放本地 data 目录，便于开发环境直接演练轮换。
	v.SetDefault("security.key_dir", "./var/keys")

	v.SetDefault("ratelimit.enabled", false)
	v.SetDefault("ratelimit.notify_per_minute", 120)
	v.SetDefault("ratelimit.app_ip_per_minute", 600)
}

// normalizeAndValidate 做归一化与启动期校验。
//
// 校验原则：宁可在启动时拒绝，也不要带着错误配置跑起来。
// 一个错误配置的服务会以"用户登录失败"的形式暴露问题，排查成本远高于启动失败。
func (c *Config) normalizeAndValidate() error {
	if c.Server.Addr == "" {
		return errs.New(errs.CodeConfigInvalid, "server.addr 不能为空")
	}
	// 短信通道的生产校验。
	//
	// release 模式下用日志通道 = 用户永远收不到验证码，而接口返回 200。
	// 这种"功能看起来正常、实际不可用"的状态最难排查，必须在启动时拒绝。
	if c.Server.IsProduction() && (c.SMS.Provider == "" || c.SMS.Provider == "log") {
		return errs.New(errs.CodeConfigInvalid,
			"生产环境必须配置真实短信通道：sms.provider 不能为 log/none").
			WithDetail("hint", "接入短信服务商后把 sms.provider 改为对应实现")
	}
	switch c.SMS.Provider {
	case "", "log", "none":
	default:
		return errs.Newf(errs.CodeConfigInvalid, "未知的 sms.provider: %s", c.SMS.Provider)
	}
	if c.Server.CallbackBaseURL == "" {
		return errs.New(errs.CodeConfigInvalid, "server.callback_base_url 不能为空").
			WithDetail("hint", "它用于拼三方回调地址，必须与平台侧配置完全一致")
	}
	if c.Server.Issuer == "" {
		c.Server.Issuer = c.Server.CallbackBaseURL
	}
	if c.Database.DSN == "" {
		return errs.New(errs.CodeConfigInvalid, "database.dsn 不能为空")
	}
	if c.Cache.Addr == "" {
		return errs.New(errs.CodeConfigInvalid, "cache.addr 不能为空")
	}
	if c.JWT.AccessTokenTTL <= 0 {
		c.JWT.AccessTokenTTL = 15 * time.Minute
	}
	if c.JWT.RefreshTokenTTL <= 0 {
		c.JWT.RefreshTokenTTL = 720 * time.Hour
	}
	if c.Auth.ExchangeTimeout <= 0 {
		c.Auth.ExchangeTimeout = 5 * time.Second
	}
	if c.Server.ShutdownTimeout <= 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}

	// 追踪：开启但没给收件地址属于配置漏项，必须在启动时拒绝。
	// 放行的话现象是"服务正常、Jaeger 里查不到任何东西"，而排查会从
	// 业务代码开始——这类"配置没生效但没人报错"的问题代价最高。
	if c.Tracing.Enabled && strings.TrimSpace(c.Tracing.Endpoint) == "" {
		return errs.New(errs.CodeConfigInvalid, "tracing.endpoint 不能为空").
			WithDetail("hint", "例如 http://otel-collector:4318；不需要追踪时把 tracing.enabled 关掉")
	}
	if c.Tracing.SampleRatio < 0 || c.Tracing.SampleRatio > 1 {
		return errs.Newf(errs.CodeConfigInvalid,
			"tracing.sample_ratio 必须在 0–1 之间（当前 %v）", c.Tracing.SampleRatio)
	}
	if c.Tracing.Environment == "" {
		c.Tracing.Environment = c.Auth.Env
	}

	// 双人复核：生产默认要求审批。
	if len(c.Admin.ApprovalRequiredActions) == 0 && c.Server.IsProduction() {
		c.Admin.ApprovalRequiredActions = []string{
			approval.ActionAppRotateSecret,
			approval.ActionConfigRotateSecret,
			approval.ActionKeyRotate,
		}
	}
	// 去重并拒绝未知动作：写错一个动作名等于"这个高危操作不受审批保护"，
	// 而配置看起来是开着的——正是要避免的"能配不生效"。
	seen := make(map[string]struct{}, len(c.Admin.ApprovalRequiredActions))
	known := map[string]struct{}{
		approval.ActionAppRotateSecret:    {},
		approval.ActionConfigRotateSecret: {},
		approval.ActionKeyRotate:          {},
	}
	actions := make([]string, 0, len(c.Admin.ApprovalRequiredActions))
	for _, a := range c.Admin.ApprovalRequiredActions {
		if _, ok := known[a]; !ok {
			return errs.Newf(errs.CodeConfigInvalid, "未知的 admin.approval_required_actions: %s", a).
				WithDetail("valid", []string{
					approval.ActionAppRotateSecret,
					approval.ActionConfigRotateSecret,
					approval.ActionKeyRotate,
				})
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		actions = append(actions, a)
	}
	c.Admin.ApprovalRequiredActions = actions

	// 应用注册同步：留空取默认值，过密直接报错。
	if c.Account.Sync.Interval <= 0 {
		c.Account.Sync.Interval = accountsync.DefaultInterval
	}
	if c.Account.Sync.Timeout <= 0 {
		c.Account.Sync.Timeout = accountsync.DefaultTimeout
	}
	if c.Account.Sync.Interval < 10*time.Second {
		// 全量对账会把每个应用 upsert 一遍。周期过密时，对端的写压力会随
		// 应用数线性放大，而收益只是"漂移被发现得更早"——那是分钟级的差别，
		// 不值得用对端稳定性去换。
		return errs.Newf(errs.CodeConfigInvalid,
			"account.sync.interval 不能小于 10s（当前 %s）", c.Account.Sync.Interval)
	}
	if c.Account.Sync.Workers < 0 {
		c.Account.Sync.Workers = 0 // 0 交给 accountsync 用默认值
	}

	// 生产模式的强校验。
	// 生产必须有内部接口令牌：为空时这些端点返回 503，而且"推不进来"
	// 不会有任何告警——只在某个用户的 claim 该失效却没失效时才看得出来。
	if c.Server.IsProduction() && strings.TrimSpace(c.Internal.ServiceToken) == "" {
		return errs.New(errs.CodeConfigInvalid,
			"生产模式缺少 internal.service_token：用户中心无法推送 claim.invalidated")
	}

	if c.Server.IsProduction() {
		if c.Security.MasterKey == "" {
			return errs.New(errs.CodeConfigInvalid,
				"生产模式必须配置 security.master_key（渠道凭据的信封加密主密钥）")
		}
		if c.Security.ClaimSalt == "" {
			// 盐为空会让凭证哈希失去防护意义，且变更盐会导致历史 claim 全部失效。
			return errs.New(errs.CodeConfigInvalid,
				"生产模式必须配置 security.claim_salt（并确保它是稳定值）")
		}
		if c.Security.AppSecretSalt == "" {
			return errs.New(errs.CodeConfigInvalid,
				"生产模式必须配置 security.app_secret_salt")
		}
		if len(c.JWT.SigningKeys) == 0 {
			// 生产环境禁止临时生成签名密钥：重启就会换 key，
			// 导致业务方缓存的 JWKS 与所有在途令牌同时失效。
			return errs.New(errs.CodeConfigInvalid,
				"生产模式必须配置 jwt.signing_keys（禁止启动时临时生成签名密钥）")
		}
		if !strings.HasPrefix(c.Server.CallbackBaseURL, "https://") {
			return errs.New(errs.CodeConfigInvalid,
				"生产模式 callback_base_url 必须是 HTTPS").
				WithDetail("value", c.Server.CallbackBaseURL)
		}
		if c.Account.Provider == "stub" {
			return errs.New(errs.CodeConfigInvalid,
				"生产模式禁止使用 account.provider=stub（内存桩实现会在重启后丢失全部账号）")
		}
		if c.Migrate.Enabled {
			return errs.New(errs.CodeConfigInvalid,
				"生产模式禁止自动迁移（migrate.enabled 必须为 false），请由发布流程单独执行")
		}
	}
	return nil
}
