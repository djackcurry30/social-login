package bootstrap

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/djackcurry30/social-login/internal/interfaces/http/middleware"
)

// 配置热更新的测试重点不是"能读文件"，而是三件事：
//   1. 白名单字段真的生效（且生效到正确的对象上）；
//   2. 非白名单字段被点名"需要重启"，而不是静默忽略；
//   3. 解析失败时不做任何修改（半套配置比旧配置危险）。

const baseYAML = `
server:
  addr: "0.0.0.0:8080"
  callback_base_url: "http://localhost:8080"
database:
  dsn: "postgres://postgres:postgres@127.0.0.1:5432/social_login?sslmode=disable"
cache:
  addr: "127.0.0.1:6379"
log:
  level: "info"
ratelimit:
  enabled: true
  notify_per_minute: 120
  app_ip_per_minute: 600
  identity_per_minute: 30
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写临时配置失败: %v", err)
	}
	return path
}

func newTestReloader(t *testing.T, path string) (*Reloader, *LimiterHandle) {
	t.Helper()
	cur, err := Load(path)
	if err != nil {
		t.Fatalf("初始配置不合法: %v", err)
	}
	levelHandle := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	atomicLevel := &levelHandle
	lim := middleware.NewLimiter(nil, middleware.LimitConfig{
		Enabled:         cur.RateLimit.Enabled,
		NotifyPerMinute: cur.RateLimit.NotifyPerMinute,
		AppIPPerMinute:  cur.RateLimit.AppIPPerMinute,
	})
	r := NewReloader(path, cur, atomicLevel, lim, nil)
	return r, &LimiterHandle{limiter: lim, level: atomicLevel}
}

func TestReloadAppliesLogLevel(t *testing.T) {
	body := baseYAML + "\n# 改成 debug\n"
	path := writeConfig(t, body)
	r, h := newTestReloader(t, path)

	// 覆盖文件内容后再 reload。
	body2 := replaceLine(body, "  level: \"info\"", "  level: \"debug\"")
	writeFile(t, path, body2)

	res, err := r.Reload()
	if err != nil {
		t.Fatalf("热更新失败: %v", err)
	}
	if !contains(res.Applied, "log.level") {
		t.Fatalf("log.level 应生效，实际 applied=%v", res.Applied)
	}
	if got := h.level.Level(); got != zapcore.DebugLevel {
		t.Fatalf("日志级别应变为 debug，实际 %v", got)
	}
	if got := r.Current().Log.Level; got != "debug" {
		t.Fatalf("当前配置应记录新级别，实际 %q", got)
	}
}

func TestReloadAppliesRateLimits(t *testing.T) {
	body := baseYAML
	path := writeConfig(t, body)
	r, h := newTestReloader(t, path)

	writeFile(t, path, replaceLine(body, "  notify_per_minute: 120", "  notify_per_minute: 240"))

	res, err := r.Reload()
	if err != nil {
		t.Fatalf("热更新失败: %v", err)
	}
	if !contains(res.Applied, "ratelimit.notify_per_minute") {
		t.Fatalf("阈值应生效，实际 applied=%v", res.Applied)
	}
	if got := h.limiter.LimitConfig().NotifyPerMinute; got != 240 {
		t.Fatalf("限流阈值应为 240，实际 %d", got)
	}
}

func TestReloadDisableLimiterTakesEffect(t *testing.T) {
	// true → false 立即生效：中间件已经挂在路由上，Enabled() 变 false 即放行。
	body := baseYAML
	path := writeConfig(t, body)
	r, h := newTestReloader(t, path)

	writeFile(t, path, replaceLine(body, "  enabled: true", "  enabled: false"))
	res, err := r.Reload()
	if err != nil {
		t.Fatalf("热更新失败: %v", err)
	}
	if !contains(res.Applied, "ratelimit.enabled") {
		t.Fatalf("关闭限流应生效，实际 applied=%v", res.Applied)
	}
	if h.limiter.Enabled() {
		t.Fatal("限流应已关闭")
	}
}

func TestReloadEnableLimiterRequiresRestart(t *testing.T) {
	// false → true 只能重启：中间件在装配期没挂上，热更无法补挂。
	// 若这里静默"成功"，运维会以为开了限流，实际全放行。
	body := replaceLine(baseYAML, "  enabled: true", "  enabled: false")
	path := writeConfig(t, body)
	r, _ := newTestReloader(t, path)

	writeFile(t, path, replaceLine(body, "  enabled: false", "  enabled: true"))
	res, err := r.Reload()
	if err != nil {
		t.Fatalf("热更新失败: %v", err)
	}
	if !contains(res.RequiresRestart, "ratelimit.enabled") {
		t.Fatalf("应从 false→true 时需要重启，实际 %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("必须给出告警，否则运维以为限流已开启")
	}
}

func TestReloadReportsRestartRequiredSections(t *testing.T) {
	body := baseYAML
	path := writeConfig(t, body)
	r, _ := newTestReloader(t, path)

	writeFile(t, path, replaceLine(body, `  addr: "127.0.0.1:6379"`, `  addr: "127.0.0.1:6380"`))
	res, err := r.Reload()
	if err != nil {
		t.Fatalf("热更新失败: %v", err)
	}
	if !contains(res.RequiresRestart, "cache") {
		t.Fatalf("cache 改动应要求重启，实际 %+v", res.RequiresRestart)
	}
	if contains(res.Applied, "cache") {
		t.Fatal("cache 不可能热更")
	}
}

func TestReloadInvalidConfigKeepsCurrent(t *testing.T) {
	body := baseYAML
	path := writeConfig(t, body)
	r, h := newTestReloader(t, path)
	before := r.Current().Cache.Addr

	writeFile(t, path, replaceLine(body, `  addr: "127.0.0.1:6379"`, `  addr: ""`))
	if _, err := r.Reload(); err == nil {
		t.Fatal("非法配置必须报错")
	}
	if got := r.Current().Cache.Addr; got != before {
		t.Fatalf("解析失败不应修改当前配置：%q → %q", before, got)
	}
	if got := h.limiter.LimitConfig().NotifyPerMinute; got != 120 {
		t.Fatalf("解析失败不应改动限流阈值，实际 %d", got)
	}
}

// --- 小工具（避免为此引入 testify 之类的依赖）---

type LimiterHandle struct {
	limiter *middleware.Limiter
	level   *zap.AtomicLevel
}

func replaceLine(s, old, new string) string {
	out := []byte{}
	for _, line := range splitLines(s) {
		if line == old {
			line = new
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return string(out)
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("覆盖配置失败: %v", err)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
