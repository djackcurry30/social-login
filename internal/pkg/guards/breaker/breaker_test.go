package breaker

import (
	"sync"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// fakeClock 让"慢请求"与"熔断时长"可以确定性验证，不靠 sleep。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestGuard(t *testing.T, mutate func(*Config)) (*Guard, *fakeClock) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.MinRequests = 20
	if mutate != nil {
		mutate(&cfg)
	}
	g := New(cfg, nil)
	clk := newFakeClock()
	g.now = clk.Now
	return g, clk
}

func connErr() error    { return errs.New(errs.CodeProviderUnavailable, "无法连接三方平台") }
func timeoutErr() error { return errs.New(errs.CodeProviderTimeout, "三方超时") }
func rejectErr() error  { return errs.New(errs.CodeProviderRejected, "code 已使用") }

// call 执行一次被保护调用，fn 返回给定错误；elapsed>0 时推进假时钟模拟耗时。
func call(g *Guard, clk *fakeClock, platform string, wantErr error, elapsed time.Duration) error {
	return g.Do(nil, platform, "app", func() error {
		if elapsed > 0 {
			clk.Advance(elapsed)
		}
		return wantErr
	})
}

// TestBusinessRejectNeverTrips 是 §5.6.4 的核心安全检查。
//
// 攻击者用无效 code 高频打回调接口是极现实的路径。如果业务拒绝计入熔断，
// 一个人就能把整个微信渠道熔断掉 —— 从"平台故障保护"变成"服务级 DoS"。
func TestBusinessRejectNeverTrips(t *testing.T) {
	g, clk := newTestGuard(t, nil)

	for i := 0; i < 500; i++ {
		_ = call(g, clk, "wechat", rejectErr(), 0)
	}
	st, ok := g.StateOf("wechat")
	if !ok {
		t.Fatal("熔断器应已创建")
	}
	if st.CircuitState != "closed" {
		t.Fatalf("业务拒绝不得触发熔断，实际状态=%s", st.CircuitState)
	}
	if st.Counted != 0 {
		t.Fatalf("业务拒绝不应进入统计分母，实际 counted=%d", st.Counted)
	}
}

// TestSlowBusinessRejectNotCountedAsSlow 是 §5.6.4b 的第二个攻击面。
// 业务拒绝即使耗时 5s 也不能计入慢请求率，否则攻击者换一个入口照样能远程熔断。
func TestSlowBusinessRejectNotCountedAsSlow(t *testing.T) {
	g, clk := newTestGuard(t, func(c *Config) {
		c.SlowThreshold = 2 * time.Second
		c.SlowRatio = 0.5
	})

	for i := 0; i < 40; i++ {
		_ = call(g, clk, "wechat", rejectErr(), 5*time.Second)
	}
	st, _ := g.StateOf("wechat")
	if st.CircuitState != "closed" {
		t.Fatalf("慢的业务拒绝不得触发熔断，实际=%s", st.CircuitState)
	}
	if st.SlowRatio != 0 {
		t.Fatalf("慢请求率应只统计成功的慢请求，实际=%v", st.SlowRatio)
	}
}

// TestFailureRatioTrips 验证错误率阈值。
func TestFailureRatioTrips(t *testing.T) {
	g, clk := newTestGuard(t, func(c *Config) {
		c.ConsecutiveFailures = 1000 // 隔离比率阈值
		c.ConsecutiveTimeouts = 1000
	})

	// 20 次里 12 次连接失败 = 60% ≥ 50%
	for i := 0; i < 20; i++ {
		if i < 12 {
			_ = call(g, clk, "alipay", connErr(), 0)
		} else {
			_ = call(g, clk, "alipay", nil, 0)
		}
	}
	st, _ := g.StateOf("alipay")
	if st.CircuitState != "open" {
		t.Fatalf("错误率 60%% 应触发熔断，实际=%s", st.CircuitState)
	}
}

// TestTimeoutRatioTripsEarlierThanFailureRatio 验证超时阈值故意更低（30%）。
func TestTimeoutRatioTripsEarlierThanFailureRatio(t *testing.T) {
	g, clk := newTestGuard(t, func(c *Config) {
		c.ConsecutiveFailures = 1000
		c.ConsecutiveTimeouts = 1000
	})

	// 20 次里 7 次超时 = 35%：超过 timeout_ratio(0.3)，但低于 failure_ratio(0.5)
	for i := 0; i < 20; i++ {
		if i < 7 {
			_ = call(g, clk, "apple", timeoutErr(), 0)
		} else {
			_ = call(g, clk, "apple", nil, 0)
		}
	}
	st, _ := g.StateOf("apple")
	if st.CircuitState != "open" {
		t.Fatalf("超时率 35%% 应触发熔断（阈值 30%%），实际=%s", st.CircuitState)
	}
}

// TestConsecutiveTimeoutsTripsBelowMinRequests 验证低流量兜底。
//
// 这是 §5.6.4b 里连续计数器存在的唯一理由：流量小到比率阈值永不触发，
// 但每次都在超时。
func TestConsecutiveTimeoutsTripsBelowMinRequests(t *testing.T) {
	g, clk := newTestGuard(t, nil) // MinRequests=20

	for i := 0; i < 5; i++ { // 只有 5 个请求，远低于 min_requests
		_ = call(g, clk, "wechat", timeoutErr(), 0)
	}
	st, _ := g.StateOf("wechat")
	if st.CircuitState != "open" {
		t.Fatalf("连续 5 次超时应触发熔断（不受 min_requests 约束），实际=%s", st.CircuitState)
	}
}

// TestSlowSuccessTrips 验证"平台变慢但没报错"也能熔断。
// 只看错误率的熔断防不住平台半死。
func TestSlowSuccessTrips(t *testing.T) {
	g, clk := newTestGuard(t, func(c *Config) {
		c.SlowThreshold = 2 * time.Second
		c.SlowRatio = 0.5
		c.ConsecutiveFailures = 1000
		c.ConsecutiveTimeouts = 1000
	})

	for i := 0; i < 20; i++ {
		if i < 12 {
			_ = call(g, clk, "wechat", nil, 3*time.Second) // 成功但慢
		} else {
			_ = call(g, clk, "wechat", nil, 100*time.Millisecond)
		}
	}
	st, _ := g.StateOf("wechat")
	if st.CircuitState != "open" {
		t.Fatalf("慢请求率 60%% 应触发熔断，实际=%s", st.CircuitState)
	}
}

// TestOpenShortCircuits 验证熔断打开后不再调用下游（不占连接、不等超时）。
func TestOpenShortCircuits(t *testing.T) {
	g, clk := newTestGuard(t, nil)
	for i := 0; i < 5; i++ {
		_ = call(g, clk, "wechat", timeoutErr(), 0)
	}

	called := false
	err := g.Do(nil, "wechat", "app", func() error {
		called = true
		return nil
	})
	if called {
		t.Fatal("熔断打开时不得调用下游")
	}
	if !errs.Is(err, errs.CodeProviderCircuitOpen) {
		t.Fatalf("应返回 CIRCUIT_OPEN，实际=%v", err)
	}
	e, ok := errs.As(err)
	if !ok {
		t.Fatal("错误应可归一化为 *errs.Error")
	}
	if e.RetryAfterMs <= 0 {
		t.Fatalf("熔断错误应带 retry_after_ms，实际=%d", e.RetryAfterMs)
	}
}

// TestResetClearsWindow 验证手工复位会把统计窗口一起清空。
//
// 只替换 gobreaker 实例而保留窗口的话，复位后窗口里的旧失败会立刻把它
// 重新熔断，"复位"就成了摆设。
func TestResetClearsWindow(t *testing.T) {
	g, clk := newTestGuard(t, nil)
	for i := 0; i < 5; i++ {
		_ = call(g, clk, "wechat", timeoutErr(), 0)
	}
	if st, _ := g.StateOf("wechat"); st.CircuitState != "open" {
		t.Fatalf("前置条件失败：应为 open，实际=%s", st.CircuitState)
	}

	if !g.Reset("wechat") {
		t.Fatal("Reset 应返回 true")
	}
	st, _ := g.StateOf("wechat")
	if st.CircuitState != "closed" {
		t.Fatalf("复位后应为 closed，实际=%s", st.CircuitState)
	}
	if st.Counted != 0 {
		t.Fatalf("复位后统计窗口应清空，实际 counted=%d", st.Counted)
	}
}

// TestCancelledRequestNotCounted 验证"调用方主动取消"不计入熔断。
// 它同样是 Unavailable，但 retryable=false —— 是我们的请求被撤销，不是平台故障。
func TestCancelledRequestNotCounted(t *testing.T) {
	g, clk := newTestGuard(t, nil)
	cancelled := errs.New(errs.CodeProviderUnavailable, "请求已被取消").WithRetryable(false)

	for i := 0; i < 100; i++ {
		_ = call(g, clk, "wechat", cancelled, 0)
	}
	st, _ := g.StateOf("wechat")
	if st.CircuitState != "closed" {
		t.Fatalf("调用方取消不得触发熔断，实际=%s", st.CircuitState)
	}
	if st.Counted != 0 {
		t.Fatalf("调用方取消不应进入统计，实际 counted=%d", st.Counted)
	}
}
