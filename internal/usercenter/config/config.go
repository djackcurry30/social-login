// Package config 加载用户中心服务的配置。
//
// 与 social-login 的配置刻意分开：两边部署形态不同（本服务无 Redis、无 JWT、
// 无三方渠道），共用一个结构体只会让每边都带着一堆用不到的字段，
// 而"配置里有但代码不读"是最容易骗过运维的东西（改了不起作用）。
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/djackcurry30/social-login/internal/pkg/tracing"
)

// Config 是用户中心的全部配置。
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Security SecurityConfig `mapstructure:"security"`
	Log      LogConfig      `mapstructure:"log"`
	Migrate  MigrateConfig  `mapstructure:"migrate"`
	Tracing  TracingConfig  `mapstructure:"tracing"`
}

// TracingConfig 是链路追踪配置。
//
// 与登录中心的同名配置保持独立：两个服务是独立进程、独立配置文件，
// 共用一个结构体就需要把 bootstrap 包暴露给本服务——那正是边界护栏
// 禁止的方向（docs/user-center-mvp-design.md §15）。
//
// 字段含义见 internal/pkg/tracing.Config：那边是唯一实现，这里是它的
// 配置投影，不复制默认值的逻辑（默认值在 Load 里设一次）。
type TracingConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	ServiceName   string            `mapstructure:"service_name"`
	Environment   string            `mapstructure:"environment"`
	Endpoint      string            `mapstructure:"endpoint"`
	Insecure      bool              `mapstructure:"insecure"`
	SampleRatio   float64           `mapstructure:"sample_ratio"`
	ExportTimeout time.Duration     `mapstructure:"export_timeout"`
	BatchTimeout  time.Duration     `mapstructure:"batch_timeout"`
	MaxQueueSize  int               `mapstructure:"max_queue_size"`
	Headers       map[string]string `mapstructure:"headers"`
}

// TracingOptions 把配置翻译成 tracing 包能消费的结构。
func (t TracingConfig) TracingOptions(version string) tracing.Config {
	name := t.ServiceName
	if name == "" {
		// 与登录中心必须不同，否则 Jaeger 的 service 下拉框里两者会合并。
		name = "usercenter"
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

// ServerConfig 是 HTTP 服务配置。
type ServerConfig struct {
	Addr            string        `mapstructure:"addr"`
	Mode            string        `mapstructure:"mode"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	// MaxBodyBytes 限制请求体大小。
	//
	// 本服务的请求体只有几十字节（几个凭证值），默认 64KB 已经非常宽松。
	// 不限制的话，一个构造的超大 body 就能让进程分配上百 MB——
	// 这类请求在网关层通常也会被拦，但本服务可能被内网直接调用。
	MaxBodyBytes int64 `mapstructure:"max_body_bytes"`
}

// IsProduction 判断是否为生产模式。
func (s ServerConfig) IsProduction() bool { return strings.EqualFold(s.Mode, "release") }

// DatabaseConfig 是 PostgreSQL 配置。
//
// 本服务只依赖 PostgreSQL：没有会话、没有限流计数器、没有分布式锁
// （幂等靠唯一键）。少一个组件就少一类故障（§8）。
type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxConns        int32         `mapstructure:"max_conns"`
	MinConns        int32         `mapstructure:"min_conns"`
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time"`
	ConnectTimeout  time.Duration `mapstructure:"connect_timeout"`
	// StatementTimeout 是单条 SQL 的上限。
	//
	// 调用方（social-login）的超时是 3s。如果本服务这边没有上限，
	// 一条因为锁等待卡住的 SQL 会拖到调用方超时，而"我们还在算"这件事
	// 对方看不到；有上限则双方都能在日志里看到同一时刻的失败。
	StatementTimeout time.Duration `mapstructure:"statement_timeout"`
	// SlowQueryThreshold 是慢查询日志阈值（只记录，不中断）。
	//
	// 与 statement_timeout 配合使用：阈值应明显小于上限（默认 200ms vs 3s），
	// 这样"快要超时的语句"会先出现在日志里，而不是等它被杀掉才发现。
	// 设为 0 关闭。⚠️ 日志里只有 SQL 模板与参数个数，没有参数值。
	SlowQueryThreshold time.Duration `mapstructure:"slow_query_threshold"`
}

// SecurityConfig 是密钥与鉴权配置。
type SecurityConfig struct {
	// ServiceToken 是服务间鉴权的 Bearer token。
	//
	// 服务级、不区分应用：UC 不签发凭据，也不复用业务方的 app_secret
	// （那是给业务方的，不该扩散到内部服务）。见 §2.3。
	ServiceToken string `mapstructure:"service_token"`
	// ClaimSalt 是凭证哈希的静态盐。
	//
	// ⚠️ 必须稳定：换盐会让已入库的 value_hash 全部无法匹配，
	// 表现为"所有老用户按手机号都查不到账号"。换盐需要配合 hash_version
	// 做迁移（E1）。
	ClaimSalt string `mapstructure:"claim_salt"`
	// KEKID 是信封加密的密钥版本标识，写入 account_claims.dek_id。
	KEKID string `mapstructure:"kek_id"`
	// MasterKey 是 AES-256 主密钥（Base64）。生产必须配置，由密钥管理系统下发。
	MasterKey string `mapstructure:"master_key"`
}

// LogConfig 是日志配置。
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

// MigrateConfig 是迁移开关。
type MigrateConfig struct {
	// Enabled 为 true 时进程启动会执行迁移。
	//
	// ⚠️ 生产必须关闭：多副本滚动发布时并发执行迁移会互相抢锁，
	// 半途失败还会留下"部分迁移已应用"的状态。生产由发布流程显式执行
	// `usercenter -migrate up`。
	Enabled bool `mapstructure:"enabled"`
}

// Load 读取配置文件并应用默认值与环境变量覆盖。
//
// 环境变量前缀 UC_，层级用下划线（UC_DATABASE_DSN）。
// 这样部署时密钥可以通过编排注入，不必写进配置文件。
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	setDefaults(v)

	v.SetEnvPrefix("UC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", "0.0.0.0:8090")
	v.SetDefault("server.mode", "debug")
	v.SetDefault("server.shutdown_timeout", "15s")
	v.SetDefault("server.max_body_bytes", 64*1024)

	v.SetDefault("database.max_conns", 20)
	v.SetDefault("database.min_conns", 2)
	v.SetDefault("database.max_conn_lifetime", "1h")
	v.SetDefault("database.max_conn_idle_time", "10m")
	v.SetDefault("database.connect_timeout", "5s")
	v.SetDefault("database.statement_timeout", "2s")

	v.SetDefault("security.kek_id", "uc-kek-v1")

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")

	v.SetDefault("migrate.enabled", false)
	// 200ms：本服务所有线上语句都是索引命中 + 单行写入，正常在 5ms 以内；
	// 200ms 已经意味着"锁等待或索引失效"，值得记一条。
	v.SetDefault("database.slow_query_threshold", 200*time.Millisecond)

	// 追踪默认关闭；开启时按 10% 采样（与登录中心同一策略，
	// 否则会出现"上游记了、下游没记"的半截链路）。
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_name", "usercenter")
	v.SetDefault("tracing.endpoint", "")
	v.SetDefault("tracing.insecure", true)
	v.SetDefault("tracing.sample_ratio", 0.1)
	v.SetDefault("tracing.export_timeout", "5s")
	v.SetDefault("tracing.batch_timeout", "5s")
	v.SetDefault("tracing.max_queue_size", 2048)
}

// normalizeAndValidate 补齐派生默认值并做启动自检。
//
// 生产模式下的"必须项"在这里硬失败，而不是等到第一次请求：
// 缺 token 时服务能启动、能通过 /healthz，但所有登录都会失败，
// 那种"看起来健康"的状态最难排查。
func (c *Config) normalizeAndValidate() error {
	c.Server.Addr = strings.TrimSpace(c.Server.Addr)
	if c.Server.Addr == "" {
		return fmt.Errorf("server.addr 不能为空")
	}
	if c.Server.ShutdownTimeout <= 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}
	if c.Server.MaxBodyBytes <= 0 {
		c.Server.MaxBodyBytes = 64 * 1024
	}

	c.Database.DSN = strings.TrimSpace(c.Database.DSN)
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn 不能为空：本服务没有本地存储，没有数据库无法启动")
	}
	if c.Database.MaxConns <= 0 {
		c.Database.MaxConns = 20
	}
	if c.Database.MinConns < 0 {
		c.Database.MinConns = 0
	}
	if c.Database.MinConns > c.Database.MaxConns {
		c.Database.MinConns = c.Database.MaxConns
	}
	if c.Database.StatementTimeout <= 0 {
		c.Database.StatementTimeout = 2 * time.Second
	}

	c.Security.ServiceToken = strings.TrimSpace(c.Security.ServiceToken)
	c.Security.ClaimSalt = strings.TrimSpace(c.Security.ClaimSalt)
	c.Security.KEKID = strings.TrimSpace(c.Security.KEKID)
	if c.Security.KEKID == "" {
		return fmt.Errorf("security.kek_id 不能为空：它是密文的密钥版本标识")
	}

	c.Tracing.Endpoint = strings.TrimSpace(c.Tracing.Endpoint)
	if c.Tracing.Enabled && c.Tracing.Endpoint == "" {
		// 开了追踪却没给地址：放行的结果是"服务正常、链路查不到"，
		// 而排查会从业务代码开始。
		return fmt.Errorf("tracing.endpoint 不能为空（例如 http://otel-collector:4318）；" +
			"不需要追踪时请关闭 tracing.enabled")
	}
	if c.Tracing.SampleRatio < 0 || c.Tracing.SampleRatio > 1 {
		return fmt.Errorf("tracing.sample_ratio 必须在 0–1 之间（当前 %v）", c.Tracing.SampleRatio)
	}

	if c.Server.IsProduction() {
		// 三条缺一不可，且失败原因要具体——只说"配置不合法"会让人逐个试。
		if c.Security.ServiceToken == "" {
			return fmt.Errorf("生产模式必须配置 security.service_token（服务间鉴权），" +
				"否则账号接口对任何内网调用方都是开放的")
		}
		if c.Security.ClaimSalt == "" {
			return fmt.Errorf("生产模式必须配置 security.claim_salt（凭证哈希盐），" +
				"随机盐会让按手机号反查账号的能力整体失效")
		}
		if c.Security.MasterKey == "" {
			return fmt.Errorf("生产模式必须配置 security.master_key（凭证明文加密密钥），" +
				"无法加密时不能降级为明文存储")
		}
		if c.Migrate.Enabled {
			return fmt.Errorf("生产模式必须关闭 migrate.enabled：多副本滚动发布时并发迁移会互相抢锁，" +
				"请由发布流程显式执行迁移")
		}
	}
	return nil
}
