// Package tracing 是 OpenTelemetry 链路追踪的装配层。
//
// 为什么单独成包，而不是在 bootstrap 里直接 new 一堆 exporter：
//
//	两个服务（登录中心 / 用户中心）都要接入，而它们的业务代码必须零相互依赖
//	（docs/user-center-mvp-design.md §15）。追踪是"横切"能力，唯一合法的
//	共用位置就是 internal/pkg —— 但它也不能借机把 otel SDK 的装配细节
//	漏到每个调用点，否则换 exporter、改采样策略要动业务代码。
//
// 三条刻意的取舍：
//
//  1. 【关闭即零开销】。enabled=false 时不注册全局 TracerProvider、不构造
//     exporter、也不设置 propagator。业务侧拿到的是 otel 的默认 noop 实现，
//     除了几次函数调用没有别的成本。而不是"注册一个不发数据的 provider"——
//     那样每次请求仍会分配 span、走一遍 SDK 的判断逻辑。
//
//  2. 【自己写 HTTP 客户端 transport，不用 otelhttp】。otelhttp 会把
//     url.full 写进 span，而本服务的查询串里有手机号/邮箱
//     （GET /accounts/by-claim?type=phone&value=138...）。trace 存储是
//     第二个日志系统，日志里必须脱敏的东西在 trace 里同样必须脱敏；
//     用 otelhttp 就等于把这套约束交给第三方默认行为。详见 transport.go。
//
//  3. 【trace_id 仍是 X-Trace-Id】。追踪接进来之后，trace_id 的取值从
//     "自建 ULID"变成"W3C trace id（32 位小写十六进制）"，但对外暴露的
//     头名与日志字段一律不变 —— 审计表里已经写了几十万条 26 位 ULID，
//     改字段名会让历史数据与新数据对不上。
//
// 采样策略是 ParentBased(TraceIDRatioBased)：入口按比例采样，下游一律
// 跟随上游的采样决定。这条很关键 —— 如果两边各自独立按比例采样，
// 会出现"上游记了、下游没记"的半截链路，比不采样更难排查。
package tracing

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

// errEndpointRequired 表示"开了追踪但没给收件地址"。
//
// 不做默认回退（localhost:4318）：那样配置漏项的表现是"服务正常、
// 追踪找不到数据"，而排查的人会先从业务代码查起。
var errEndpointRequired = errors.New("tracing.enabled=true 但 tracing.endpoint 为空")

// instrumentationName 是 SDK 里填写作用域的名字，出现在 span 的
// instrumentation_scope 上。用模块路径，便于在 Jaeger 里按来源过滤。
const instrumentationName = "github.com/djackcurry30/social-login/internal/pkg/tracing"

// 默认值。
const (
	DefaultSampleRatio    = 1.0
	DefaultExportTimeout  = 5 * time.Second
	DefaultBatchTimeout   = 5 * time.Second
	DefaultMaxQueueSize   = 2048
	DefaultServiceName    = "social-login"
	defaultEndpointScheme = "http://"
)

// Config 是追踪配置。
//
// 所有字段都有安全的零值行为：Enabled=false 时其余字段一律被忽略，
// 因此"没有配置 tracing 段"不会让服务起不来。
type Config struct {
	// Enabled 打开后才真正上报。默认关闭：没有 collector 的环境里
	// 打开只会让进程每分钟打印一批导出失败日志。
	Enabled bool
	// ServiceName 是服务名，出现在 trace 的 service.name 上。
	// 两个服务必须不同，否则在 Jaeger 里分不出是谁发的 span。
	ServiceName string
	// ServiceVersion 一般取编译期注入的版本号。
	ServiceVersion string
	// Environment 部署环境（dev / staging / prod）。
	Environment string
	// Endpoint 是 OTLP/HTTP 的接收地址，例如 http://otel-collector:4318。
	// 只写 host:port 也可以，缺 scheme 时按 Insecure 补 http/https。
	Endpoint string
	// Insecure 表示明文传输。内网 collector 通常如此；跨网络安全域应关掉。
	Insecure bool
	// SampleRatio 是入口采样比例，0–1。1 表示全采。
	//
	// 生产建议 0.05–0.1：追踪的价值在"能定位到出问题的那一次"，而不在
	// 全量。全量采样在登录高峰会把 collector 和存储一起拖垮，而拖垮的
	// 后果是"出问题时恰好没有 trace"。
	SampleRatio float64
	// Headers 是附加到导出请求上的头，用于 collector 侧的鉴权
	//（例如 Authorization）。不写进日志。
	Headers map[string]string
	// ExportTimeout 是单批导出的超时，也是 Shutdown 刷盘的上限。
	ExportTimeout time.Duration
	// BatchTimeout 是批量导出的最大等待时间。
	BatchTimeout time.Duration
	// MaxQueueSize 是内存里待导出 span 的队列长度。队列满时新 span 被丢弃
	// 并计数（SDK 行为），而不是阻塞业务——这是必须接受的取舍。
	MaxQueueSize int
	// Exporter 可选。非 nil 时忽略 Endpoint / Insecure / Headers，
	// 直接用注入的导出器。用途：单元测试用内存导出器断言链路，
	// 以及将来接别的协议（Zipkin / 自建网关）时不必改本包。
	Exporter sdktrace.SpanExporter
}

func (c Config) withDefaults() Config {
	if strings.TrimSpace(c.ServiceName) == "" {
		c.ServiceName = DefaultServiceName
	}
	if c.ExportTimeout <= 0 {
		c.ExportTimeout = DefaultExportTimeout
	}
	if c.BatchTimeout <= 0 {
		c.BatchTimeout = DefaultBatchTimeout
	}
	if c.MaxQueueSize <= 0 {
		c.MaxQueueSize = DefaultMaxQueueSize
	}
	if c.SampleRatio <= 0 {
		// 注意：<=0 视为"没配"，取默认全采。
		// 想把采样关到 0 请直接关 Enabled —— "开着但一条不记"是纯粹的
		// 故障制造机（配置看起来是开的，实际什么都看不到）。
		c.SampleRatio = DefaultSampleRatio
	}
	if c.SampleRatio > 1 {
		c.SampleRatio = 1
	}
	return c
}

// endpoint 把配置里的地址规整成 otlptracehttp 需要的 host:port 形式。
func (c Config) endpoint() string {
	e := strings.TrimSpace(c.Endpoint)
	e = strings.TrimPrefix(e, defaultEndpointScheme)
	e = strings.TrimPrefix(e, "https://")
	return strings.TrimRight(e, "/")
}

// Provider 持有 TracerProvider 的生命周期。
//
// 必须调用 Shutdown：批量导出器在内存里攒着最后一批 span，
// 进程直接退出会让这一批（往往正是出错前后的那几秒）永久丢失。
type Provider struct {
	cfg Config
	tp  *sdktrace.TracerProvider
	log *zap.Logger
}

// globalEnabled 供 Transport / 中间件做"要不要挂 instrumentation"的判断。
//
// 用包级原子变量而不是每个调用点传 provider：httpx 是通用工具包，
// 它的构造函数不该为了追踪多出一个参数（那会把 otel 装配细节扩散到
// 每一个渠道适配器的装配点）。进程内只初始化一次，语义上就是全局的。
var globalEnabled atomic.Bool

// Enabled 报告当前进程是否开启了追踪。
func Enabled() bool { return globalEnabled.Load() }

// Init 按配置初始化追踪。
//
// 返回的 Provider 在 enabled=false 时是"空壳"，Shutdown 是空操作。
// 初始化失败（例如 endpoint 填错）返回错误——由装配方决定是启动失败
// 还是降级；本包不替它决定，因为"追踪配错了要不要拒绝启动"是部署策略。
func Init(ctx context.Context, cfg Config, logger *zap.Logger) (*Provider, error) {
	cfg = cfg.withDefaults()
	p := &Provider{cfg: cfg, log: logger}
	if !cfg.Enabled {
		globalEnabled.Store(false)
		return p, nil
	}

	exp := cfg.Exporter
	if exp == nil {
		if cfg.endpoint() == "" {
			// 打开追踪却没给地址，一定是配置漏了。这里直接报错而不是
			// 静默用默认 localhost:4318：那会让"配了但没生效"变成
			// "看起来生效了、数据发去了没人看的地方"。
			return nil, errEndpointRequired
		}
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.endpoint()),
			otlptracehttp.WithTimeout(cfg.ExportTimeout),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		var err error
		exp, err = otlptracehttp.New(ctx, opts...)
		if err != nil {
			return nil, err
		}
	}

	res, err := buildResource(ctx, cfg)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		// ParentBased 让下游跟随上游的采样决定，见包注释第 4 段。
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
		sdktrace.WithBatcher(exp,
			sdktrace.WithBatchTimeout(cfg.BatchTimeout),
			sdktrace.WithExportTimeout(cfg.ExportTimeout),
			sdktrace.WithMaxQueueSize(cfg.MaxQueueSize),
		),
	)

	otel.SetTracerProvider(tp)
	// 只接受 W3C TraceContext（跨厂商、跨语言都认）与 Baggage。
	// 不启用 B3 等其他格式：多一种入口就多一种被伪造 trace 的途径。
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	// SDK 默认把导出错误打到 stderr。生产上 stderr 往往没人看，
	// 于是"追踪悄悄停了"和"追踪正常"在运维眼里没有区别。
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		if logger != nil {
			logger.Warn("链路追踪上报异常（不影响业务请求）", zap.Error(err))
		}
	}))

	p.tp = tp
	globalEnabled.Store(true)
	if logger != nil {
		logger.Info("链路追踪已启用",
			zap.String("service", cfg.ServiceName),
			zap.String("endpoint", cfg.endpoint()),
			zap.Float64("sample_ratio", cfg.SampleRatio),
			zap.Bool("insecure", cfg.Insecure))
	}
	return p, nil
}

// Flush 立即把已结束的 span 推给导出器，不关闭 provider。
//
// 两个用途：
//   - 单元测试：批量导出器默认攒 5s，断言"span 有没有导出"必须先刷一次；
//     注意不能改用 Shutdown —— 内存导出器的 Shutdown 会清空已收集的 span。
//   - 运维排障：手工触发一次请求后想立刻在 Jaeger 里看到，而不等攒批。
func (p *Provider) Flush(ctx context.Context) error {
	if p == nil || p.tp == nil {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(ctx, p.cfg.ExportTimeout)
	defer cancel()
	return p.tp.ForceFlush(flushCtx)
}

// Shutdown 刷出剩余 span 并关闭导出器。
//
// 超时取 ExportTimeout：收集器挂掉时不能让进程退出卡在这里——
// 追踪是旁路，进程的退出时间不该由它决定。
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.tp == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, p.cfg.ExportTimeout)
	defer cancel()
	err := p.tp.Shutdown(shutdownCtx)
	p.tp = nil
	globalEnabled.Store(false)
	return err
}

// ServiceName 返回生效的服务名（供日志与测试断言）。
func (p *Provider) ServiceName() string { return p.cfg.ServiceName }

// buildResource 组装资源属性。
//
// 保留 resource.Default()（含 telemetry.sdk.* 与 host.name）：排障时
// "哪个实例发的"和"哪个服务发的"一样重要，多副本场景下没有主机名
// 就只能靠猜。
func buildResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", cfg.ServiceName),
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, attribute.String("service.version", cfg.ServiceVersion))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, attribute.String("deployment.environment.name", cfg.Environment))
	}
	return resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
}
