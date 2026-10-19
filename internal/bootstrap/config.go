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

	"github.com/djackcurry30/social-login/internal/pkg/errs"
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

// SecurityConfig 是密钥与哈希盐配置。
type SecurityConfig struct {
	// MasterKey 是信封加密的主密钥（Base64，32 字节）。
	// ⚠️ 生产环境必须由 KMS 或密钥管理系统下发，且不得进版本库。
	MasterKey string `mapstructure:"master_key"`
	// KEKID 是主密钥版本标识，写入 app_provider_configs.secret_dek_id，
	// 用于密钥轮换时区分"哪一版密钥加密的凭据"。
	KEKID string `mapstructure:"kek_id"`
	// ClaimSalt 是身份凭证哈希的静态盐。
	//
	// ⚠️ 绝不能用每行随机盐：claim 的核心用途就是"按手机号反查身份"，
	// 随机盐会让同一号码每次算出不同哈希，该功能直接失效。
	ClaimSalt string `mapstructure:"claim_salt"`
	// AppSecretSalt 是应用密钥哈希的静态盐。
	AppSecretSalt string `mapstructure:"app_secret_salt"`
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
}

// HTTPAccount 是用户中心 HTTP 客户端配置。
type HTTPAccount struct {
	BaseURL string        `mapstructure:"base_url"`
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
	Enabled     bool   `mapstructure:"enabled"`
	Granularity string `mapstructure:"granularity"` // platform | platform_scene
	WindowSeconds int  `mapstructure:"window_seconds"`
	BucketSeconds int  `mapstructure:"bucket_seconds"`
	MinRequests   int  `mapstructure:"min_requests"`

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

	v.SetDefault("auth.env", "prod")
	v.SetDefault("auth.exchange_timeout", "5s")

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.max_size_mb", 128)
	v.SetDefault("log.max_backups", 10)
	v.SetDefault("log.max_age_days", 30)

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
}

// normalizeAndValidate 做归一化与启动期校验。
//
// 校验原则：宁可在启动时拒绝，也不要带着错误配置跑起来。
// 一个错误配置的服务会以"用户登录失败"的形式暴露问题，排查成本远高于启动失败。
func (c *Config) normalizeAndValidate() error {
	if c.Server.Addr == "" {
		return errs.New(errs.CodeConfigInvalid, "server.addr 不能为空")
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

	// 生产模式的强校验。
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
