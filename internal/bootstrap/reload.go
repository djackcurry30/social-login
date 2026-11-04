package bootstrap

import (
	"reflect"
	"sync"
	"time"

	"go.uber.org/zap"

	adminhttp "github.com/djackcurry30/social-login/internal/interfaces/http/admin"
	"github.com/djackcurry30/social-login/internal/interfaces/http/middleware"
)

// Reloader 是服务级配置的热更新入口（C4）。
//
// 为什么是"白名单式"而不是"整体重载"：
//
//	配置里的多数字段一旦生效就与已建立的资源绑定在一起——监听地址、
//	数据库连接池、Redis 连接、JWT 时长、渠道客户端超时、密钥……
//	这些字段"改文件后悄悄不生效"和"热更到一半状态不一致"都比重启更危险。
//	所以这里只热更两类：
//
//	  log.level                    调整日志级别（线上排障的日常动作）
//	  ratelimit.notify_per_minute  两档入站限流阈值（按流量校准后的微调）
//	  ratelimit.app_ip_per_minute
//	  ratelimit.enabled            只能从 true 改 false（关掉立即生效）
//
//	其余字段改动一律返回 RequiresRestart 列表并在日志里 Warn——不是静默忽略。
//	"配置改了但没生效且没人知道"是这类功能最坏的失败方式。
type Reloader struct {
	path    string
	log     *zap.Logger
	level   *zap.AtomicLevel
	limiter *middleware.Limiter

	mu      sync.Mutex
	current *Config
}

// NewReloader 构造热更新器。
//
// level / limiter 允许为 nil（例如单元测试或未启用限流），此时对应的
// 热更项会被跳过并计入 RequiresRestart。
func NewReloader(path string, current *Config, level *zap.AtomicLevel, limiter *middleware.Limiter, log *zap.Logger) *Reloader {
	return &Reloader{path: path, current: current, level: level, limiter: limiter, log: log}
}

// Current 返回当前生效的配置（供测试与只读展示）。
func (r *Reloader) Current() *Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// Reload 重新读取配置文件并应用可热更字段。
//
// 返回的 Applied 是真正生效的项，RequiresRestart 是检测到改动但必须重启的
// 配置段。解析失败时【不做任何修改】——半个配置比旧配置更危险。
func (r *Reloader) Reload() (adminhttp.ConfigReloadResult, error) {
	var out adminhttp.ConfigReloadResult

	r.mu.Lock()
	defer r.mu.Unlock()

	next, err := Load(r.path)
	if err != nil {
		return out, err
	}

	if next.Log.Level != r.current.Log.Level {
		lvl, err := parseLevel(next.Log.Level)
		if err != nil {
			return out, err
		}
		if r.level != nil {
			r.level.SetLevel(lvl)
			out.Applied = append(out.Applied, "log.level")
		} else {
			out.RequiresRestart = append(out.RequiresRestart, "log.level")
		}
	}

	if next.RateLimit.NotifyPerMinute != r.current.RateLimit.NotifyPerMinute ||
		next.RateLimit.AppIPPerMinute != r.current.RateLimit.AppIPPerMinute {
		if r.limiter != nil {
			cfg := r.limiter.LimitConfig()
			cfg.NotifyPerMinute = next.RateLimit.NotifyPerMinute
			cfg.AppIPPerMinute = next.RateLimit.AppIPPerMinute
			r.limiter.Apply(cfg)
			out.Applied = append(out.Applied, "ratelimit.notify_per_minute", "ratelimit.app_ip_per_minute")
		} else {
			out.RequiresRestart = append(out.RequiresRestart,
				"ratelimit.notify_per_minute", "ratelimit.app_ip_per_minute")
		}
	}

	if next.RateLimit.Enabled != r.current.RateLimit.Enabled {
		if r.limiter == nil {
			out.RequiresRestart = append(out.RequiresRestart, "ratelimit.enabled")
		} else if next.RateLimit.Enabled {
			// false → true：中间件在装配期就没挂上，热更无法让它生效。
			// 这条必须显式告警，否则运维会以为"开了限流"，实际全放行。
			out.RequiresRestart = append(out.RequiresRestart, "ratelimit.enabled")
			out.Warnings = append(out.Warnings,
				"ratelimit.enabled 从 false 改为 true 需要重启：限流中间件在启动时决定是否挂载")
		} else {
			cfg := r.limiter.LimitConfig()
			cfg.Enabled = false
			r.limiter.Apply(cfg)
			out.Applied = append(out.Applied, "ratelimit.enabled")
		}
	}

	out.RequiresRestart = append(out.RequiresRestart, restartSections(r.current, next)...)

	r.current = next
	out.ReloadedAt = time.Now().UTC()

	if r.log != nil {
		fields := []zap.Field{
			zap.Strings("applied", out.Applied),
			zap.Strings("requires_restart", out.RequiresRestart),
		}
		if len(out.RequiresRestart) > 0 {
			r.log.Warn("配置已重新读取：部分改动需要重启才生效", fields...)
		} else {
			r.log.Info("配置已重新读取", fields...)
		}
	}
	return out, nil
}

// restartSections 列出"改了但必须重启"的配置段。
//
// 做法：把可热更字段回填成旧值后再整体比较，剩下的差异就是不可热更的。
// 这样新增配置字段时不需要维护一份"不可热更清单"——默认不可热更，
// 只有显式加进回填逻辑的字段才会热更。默认安全。
func restartSections(cur, next *Config) []string {
	n := *next
	n.Log.Level = cur.Log.Level
	n.RateLimit.NotifyPerMinute = cur.RateLimit.NotifyPerMinute
	n.RateLimit.AppIPPerMinute = cur.RateLimit.AppIPPerMinute
	n.RateLimit.Enabled = cur.RateLimit.Enabled
	if reflect.DeepEqual(*cur, n) {
		return nil
	}

	var out []string
	cv, nv := reflect.ValueOf(*cur), reflect.ValueOf(n)
	for i := 0; i < cv.NumField(); i++ {
		if reflect.DeepEqual(cv.Field(i).Interface(), nv.Field(i).Interface()) {
			continue
		}
		name := cv.Type().Field(i).Tag.Get("mapstructure")
		if name == "" {
			name = cv.Type().Field(i).Name
		}
		out = append(out, name)
	}
	return out
}
