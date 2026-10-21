// Package breaker 实现渠道熔断（架构 §5.6）。
//
// 设计要点与本包的职责边界：
//
//	状态机        → 交给 sony/gobreaker/v2（并发安全的三态迁移不值得自研）
//	失败分类统计  → 本包自己维护（gobreaker 的 ReadyToTrip 拿不到失败分类）
//
// 两条必须写死的规则（写错会变成服务级 DoS）：
//
//	① 只有 retryable 的错误计入熔断。PROVIDER.REJECTED 是"业务语义的正常返回"
//	   （比如 code 已使用），攻击者可以用无效 code 高频打回调来远程熔断渠道。
//	② 慢请求率只统计【成功】的慢请求。业务拒绝即使耗时 3s 也不计入，理由同上。
package breaker

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Granularity 是熔断粒度。
//
// 默认按 platform：微信的 code2session / sns/oauth2/access_token / sns/qrconnect
// 都在 api.weixin.qq.com 同一域名下，故障域是"平台"而不是"场景"。
// 按场景熔断会出现"小程序已熔断，app 场景还在打同一个故障域名"。
const (
	GranularityPlatform = "platform"
	GranularityScene    = "platform_scene"
)

// Config 是熔断配置（服务级，不放 applications.policy）。
//
// 为什么不放应用级：熔断保护的是所有应用共享的连接池与 goroutine。
// 若允许某个应用关掉熔断，它就能替所有应用关掉保护。
type Config struct {
	Enabled       bool
	Granularity   string
	WindowSeconds int
	BucketSeconds int
	MinRequests   int

	// 四类独立阈值，任一触发即 Open（§5.6.4b）。
	FailureRatio        float64
	TimeoutRatio        float64
	SlowRatio           float64
	SlowThreshold       time.Duration
	ConsecutiveTimeouts int
	ConsecutiveFailures int

	OpenDuration     time.Duration
	HalfOpenRequests uint32
}

// DefaultConfig 返回架构 §5.6.5 的默认值。
func DefaultConfig() Config {
	return Config{
		Enabled:             true,
		Granularity:         GranularityPlatform,
		WindowSeconds:       60,
		BucketSeconds:       10,
		MinRequests:         20,
		FailureRatio:        0.5,
		TimeoutRatio:        0.3, // 故意低于错误率：超时对连接的消耗是 5xx 的数十倍
		SlowRatio:           0.5,
		SlowThreshold:       2 * time.Second,
		ConsecutiveTimeouts: 5,
		ConsecutiveFailures: 10,
		OpenDuration:        30 * time.Second,
		HalfOpenRequests:    3,
	}
}

// 归一化非法配置，避免除零与"永不熔断"这类静默失效。
func (c Config) normalized() Config {
	d := DefaultConfig()
	if c.Granularity != GranularityScene {
		c.Granularity = GranularityPlatform
	}
	if c.WindowSeconds <= 0 {
		c.WindowSeconds = d.WindowSeconds
	}
	if c.BucketSeconds <= 0 || c.BucketSeconds > c.WindowSeconds {
		c.BucketSeconds = d.BucketSeconds
	}
	if c.MinRequests <= 0 {
		c.MinRequests = d.MinRequests
	}
	if c.FailureRatio <= 0 {
		c.FailureRatio = d.FailureRatio
	}
	if c.TimeoutRatio <= 0 {
		c.TimeoutRatio = d.TimeoutRatio
	}
	if c.SlowRatio <= 0 {
		c.SlowRatio = d.SlowRatio
	}
	if c.SlowThreshold <= 0 {
		c.SlowThreshold = d.SlowThreshold
	}
	if c.ConsecutiveTimeouts <= 0 {
		c.ConsecutiveTimeouts = d.ConsecutiveTimeouts
	}
	if c.ConsecutiveFailures <= 0 {
		c.ConsecutiveFailures = d.ConsecutiveFailures
	}
	if c.OpenDuration <= 0 {
		c.OpenDuration = d.OpenDuration
	}
	if c.HalfOpenRequests == 0 {
		c.HalfOpenRequests = d.HalfOpenRequests
	}
	return c
}

// Outcome 是一次渠道调用的分类结果。
//
// 分类的意义不只是统计：它决定了该次调用是否计入熔断，
// 也就决定了外部攻击者能否通过构造请求远程触发熔断。
type Outcome int

const (
	// Success 成功且未超过慢阈值。
	Success Outcome = iota
	// Slow 成功但耗时超过 slow_threshold。平台拥塞的最早期信号。
	Slow
	// Timeout 超时。慢失败，占满整个超时窗口。
	Timeout
	// ConnErr 连接失败 / 三方 5xx / 响应不可读。
	ConnErr
	// ServerErr 三方明确返回服务端错误。
	ServerErr
	// ConfigErr 是我们的凭据或配置错误（AUTH.INVALID_CONFIG）。
	// 计入熔断（否则会持续打故障配置），但必须单独告警——它不会自愈。
	ConfigErr
	// BusinessReject 业务语义的正常拒绝（code 无效 / 已使用）。
	// 【不计入任何熔断统计】，否则攻击者可用无效 code 远程熔断渠道。
	BusinessReject
	// Other 与本服务或平台健康无关的错误（调用方取消、解析失败等），不计入。
	Other
)

func (o Outcome) String() string {
	switch o {
	case Success:
		return "success"
	case Slow:
		return "slow"
	case Timeout:
		return "timeout"
	case ConnErr:
		return "conn_err"
	case ServerErr:
		return "server_err"
	case ConfigErr:
		return "config_err"
	case BusinessReject:
		return "business_reject"
	default:
		return "other"
	}
}

// counted 表示该结果是否进入比率类统计的分母。
func (o Outcome) counted() bool {
	switch o {
	case Success, Slow, Timeout, ConnErr, ServerErr, ConfigErr:
		return true
	default:
		return false
	}
}

// failure 表示该结果是否计入失败率。
func (o Outcome) failure() bool {
	switch o {
	case ConnErr, ServerErr, ConfigErr:
		return true
	default:
		return false
	}
}

// Classify 把一次调用的结果归一化为 Outcome。
//
// elapsed 是本次调用的真实耗时。只有【成功】的慢调用才算 Slow——
// 业务拒绝即使慢也不能算（§5.6.4b 的攻击面）。
func Classify(err error, elapsed time.Duration, slowThreshold time.Duration) Outcome {
	if err == nil {
		if slowThreshold > 0 && elapsed >= slowThreshold {
			return Slow
		}
		return Success
	}
	code := errs.CodeOf(err)
	switch code {
	case errs.CodeProviderTimeout:
		return Timeout
	case errs.CodeProviderRejected:
		// 业务拒绝：平台是健康的，问题在请求本身。绝不能计入熔断。
		return BusinessReject
	case errs.CodeAuthInvalidConfig:
		return ConfigErr
	case errs.CodeProviderUnavailable:
		// 同样是 Unavailable，但"调用方主动取消"被标记为 retryable=false，
		// 那是我们的请求被撤销，不是平台故障。
		if errs.Retryable(err) {
			return ConnErr
		}
		return Other
	default:
		return Other
	}
}

// --- 滑动窗口 ---

const numOutcomes = 8

// window 是固定桶数的环形计数器。
//
// 之所以不用 gobreaker 自带的 counts：它只有 Success/Failure 两分类，
// 拿不到"超时 / 连接失败 / 业务拒绝"的区别，也就实现不了四类独立阈值。
type window struct {
	mu        sync.Mutex
	buckets   []bucket
	bucketDur time.Duration
	cur       int
	curStart  time.Time

	// 连续计数器不随窗口滚动清零——它专门解决低流量下比率阈值永不触发的场景。
	consecTimeouts int
	consecFailures int
}

type bucket struct {
	counts [numOutcomes]int64
}

func newWindow(windowDur, bucketDur time.Duration) *window {
	n := int(windowDur / bucketDur)
	if n < 1 {
		n = 1
	}
	return &window{
		buckets:   make([]bucket, n),
		bucketDur: bucketDur,
		curStart:  time.Now(),
	}
}

// rotate 把过期桶清零并推进指针。调用方必须持有锁。
func (w *window) rotate(now time.Time) {
	if w.bucketDur <= 0 {
		return
	}
	// 一次跳过多个桶时逐桶推进，保证每个桶都被清零。
	for !now.Before(w.curStart.Add(w.bucketDur)) {
		w.cur = (w.cur + 1) % len(w.buckets)
		w.buckets[w.cur] = bucket{}
		w.curStart = w.curStart.Add(w.bucketDur)
	}
}

func (w *window) record(o Outcome, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotate(now)

	// 业务拒绝与 Other 不进窗口：它们既不是平台健康的信号，
	// 也可能被攻击者构造，进窗口就等于给了一条远程操纵熔断的路。
	if o.counted() {
		w.buckets[w.cur].counts[o]++
	}

	switch o {
	case Timeout:
		w.consecTimeouts++
		w.consecFailures++
	case ConnErr, ServerErr, ConfigErr:
		w.consecFailures++
		w.consecTimeouts = 0
	case Success, Slow, BusinessReject:
		w.consecTimeouts = 0
		w.consecFailures = 0
	}
}

// Snapshot 是窗口的只读视图。
type Snapshot struct {
	Counted        int
	Success        int
	Slow           int
	Timeout        int
	ConnErr        int
	ServerErr      int
	ConfigErr      int
	FailureRatio   float64
	TimeoutRatio   float64
	SlowRatio      float64
	ConsecTimeouts int
	ConsecFailures int
}

func (w *window) snapshot(now time.Time) Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotate(now)

	var s Snapshot
	for i := range w.buckets {
		for o := Outcome(0); o < numOutcomes; o++ {
			n := int(w.buckets[i].counts[o])
			switch o {
			case Success:
				s.Success += n
			case Slow:
				s.Slow += n
			case Timeout:
				s.Timeout += n
			case ConnErr:
				s.ConnErr += n
			case ServerErr:
				s.ServerErr += n
			case ConfigErr:
				s.ConfigErr += n
			}
		}
	}
	s.Counted = s.Success + s.Slow + s.Timeout + s.ConnErr + s.ServerErr + s.ConfigErr
	s.ConsecTimeouts = w.consecTimeouts
	s.ConsecFailures = w.consecFailures

	if s.Counted > 0 {
		failures := s.ConnErr + s.ServerErr + s.ConfigErr
		s.FailureRatio = ratio(failures, s.Counted)
		s.TimeoutRatio = ratio(s.Timeout, s.Counted)
		s.SlowRatio = ratio(s.Slow, s.Counted)
	}
	return s
}

func ratio(n, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(n) / float64(total)
}

// --- 熔断器 ---

// Guard 是按平台（或平台+场景）维度的熔断器集合。
//
// 状态是进程内的：N 个副本 = N 个独立的熔断器。这是刻意的取舍（§5.6.7）——
// 熔断是降级保护机制，不应该依赖 Redis，否则 Redis 故障时保护也一起失效。
// 副本数超过约 20 时再考虑"熔断事件广播"，而不是每次调用读共享状态。
type Guard struct {
	cfg Config
	log *zap.Logger
	now func() time.Time

	mu    sync.RWMutex
	items map[string]*item
}

type item struct {
	key      string
	platform string
	scene    string

	cb  *gobreaker.CircuitBreaker[struct{}]
	win *window

	stateMu  sync.Mutex
	openedAt time.Time
	everOpen bool
}

// New 构造熔断器集合。logger 可为 nil。
func New(cfg Config, logger *zap.Logger) *Guard {
	c := cfg.normalized()
	if !cfg.Enabled {
		c.Enabled = false
	}
	return &Guard{
		cfg:   c,
		log:   logger,
		now:   time.Now,
		items: make(map[string]*item, 8),
	}
}

// Enabled 返回熔断是否启用。
func (g *Guard) Enabled() bool { return g != nil && g.cfg.Enabled }

// Config 返回归一化后的配置（供启动日志与管理端展示）。
func (g *Guard) Config() Config { return g.cfg }

func (g *Guard) keyOf(platform, scene string) string {
	if g.cfg.Granularity == GranularityScene {
		return platform + ":" + scene
	}
	return platform
}

func (g *Guard) get(platform, scene string) *item {
	key := g.keyOf(platform, scene)

	g.mu.RLock()
	it := g.items[key]
	g.mu.RUnlock()
	if it != nil {
		return it
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if it = g.items[key]; it != nil {
		return it
	}
	it = g.newItem(key, platform, scene)
	g.items[key] = it
	return it
}

func (g *Guard) newItem(key, platform, scene string) *item {
	it := &item{
		key:      key,
		platform: platform,
		scene:    scene,
		win:      newWindow(time.Duration(g.cfg.WindowSeconds)*time.Second, time.Duration(g.cfg.BucketSeconds)*time.Second),
	}

	// ReadyToTrip 读的是【我们自己的分类窗口】，不是 gobreaker 的 counts——
	// 后者没有失败分类，用它做判定就实现不了"超时不与 5xx 混算"。
	readyToTrip := func(_ gobreaker.Counts) bool {
		return g.shouldTrip(it.win.snapshot(g.now()))
	}

	// IsSuccessful 只影响 gobreaker 自身计数（半开探测能否闭合）。
	// 业务拒绝必须算"成功"：平台回答了，说明它是活的。
	isSuccessful := func(err error) bool {
		switch Classify(err, 0, 0) {
		case BusinessReject, Other, Success:
			return true
		default:
			return false
		}
	}

	onStateChange := func(name string, from, to gobreaker.State) {
		it.stateMu.Lock()
		if to == gobreaker.StateOpen {
			it.openedAt = g.now()
			it.everOpen = true
		}
		it.stateMu.Unlock()

		if g.log != nil {
			g.log.Warn("渠道熔断状态变化",
				zap.String("platform", it.platform),
				zap.String("scene", it.scene),
				zap.String("from", from.String()),
				zap.String("to", to.String()),
				zap.String("granularity", g.cfg.Granularity))
		}
	}

	it.cb = gobreaker.NewCircuitBreaker[struct{}](gobreaker.Settings{
		Name:          key,
		MaxRequests:   g.cfg.HalfOpenRequests,
		Interval:      0, // 0 = 不按时间重置：窗口统计由我们自己负责
		Timeout:       g.cfg.OpenDuration,
		ReadyToTrip:   readyToTrip,
		OnStateChange: onStateChange,
		IsSuccessful:  isSuccessful,
	})
	return it
}

// shouldTrip 判定当前窗口是否达到熔断条件（§5.6.4b 的四类信号）。
func (g *Guard) shouldTrip(s Snapshot) bool {
	// 连续超时 / 连续失败不受 min_requests 约束：它们存在的意义
	// 正是"流量小到比率阈值永不触发，但每次都超时"的场景。
	if s.ConsecTimeouts >= g.cfg.ConsecutiveTimeouts {
		return true
	}
	if s.ConsecFailures >= g.cfg.ConsecutiveFailures {
		return true
	}
	if s.Counted < g.cfg.MinRequests {
		return false
	}
	if s.FailureRatio >= g.cfg.FailureRatio {
		return true
	}
	if s.TimeoutRatio >= g.cfg.TimeoutRatio {
		return true
	}
	if s.SlowRatio >= g.cfg.SlowRatio {
		return true
	}
	return false
}

// Do 在熔断器保护下执行一次渠道调用。
//
// 熔断打开时【不调用 fn】——这正是熔断的价值：不占连接、不等超时、立即失败。
func (g *Guard) Do(ctx context.Context, platform, scene string, fn func() error) error {
	if !g.Enabled() {
		return fn()
	}
	_ = ctx // 由 fn 自己使用；保留参数以便未来按 ctx 做快速返回

	it := g.get(platform, scene)
	started := g.now()

	_, err := it.cb.Execute(func() (struct{}, error) {
		callErr := fn()
		elapsed := g.now().Sub(started)
		outcome := Classify(callErr, elapsed, g.cfg.SlowThreshold)
		it.win.record(outcome, g.now())

		if outcome == ConfigErr && g.log != nil {
			// 配置错误不会自愈，必须单独告警——否则会一直是"平台不可用"的假象。
			g.log.Error("渠道配置错误（需人工修配置，不会自愈）",
				zap.String("platform", platform),
				zap.String("scene", scene),
				zap.Error(callErr))
		}
		return struct{}{}, callErr
	})

	// 主动评估一遍阈值。
	//
	// 不能只依赖 gobreaker 的 ReadyToTrip：它只在【失败】时被调用。
	// 而"慢但成功"是最典型的平台半死形态——如果一次调用成功了，
	// readyToTrip 根本不会被触发，慢请求率再高也唤不起熔断。
	// 这里的做法是给状态机喂一次合成失败，让它在 Closed 时就地评估窗口。
	if err == nil || !errors.Is(err, gobreaker.ErrOpenState) {
		if it.cb.State() == gobreaker.StateClosed && g.shouldTrip(it.win.snapshot(g.now())) {
			_, _ = it.cb.Execute(func() (struct{}, error) {
				return struct{}{}, errs.New(errs.CodeProviderUnavailable, "熔断阈值已达到")
			})
		}
	}

	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		return g.openError(it, platform)
	}
	return err
}

// openError 构造熔断快速失败的错误（§5.6.8）。
//
// 用 PROVIDER.CIRCUIT_OPEN 而不是文档示例里的 PROVIDER.UNAVAILABLE：
// 两者都是 503 + retryable，但 CIRCUIT_OPEN 能让接入方区分"平台挂了"与
// "我们主动熔断了"，排障时这一条信息很关键。
func (g *Guard) openError(it *item, platform string) *errs.Error {
	it.stateMu.Lock()
	opened := it.openedAt
	it.stateMu.Unlock()

	retryAfter := int(g.cfg.OpenDuration / time.Millisecond)
	if !opened.IsZero() {
		remain := g.cfg.OpenDuration - g.now().Sub(opened)
		if remain > 0 {
			retryAfter = int(remain / time.Millisecond)
		}
	}
	return errs.New(errs.CodeProviderCircuitOpen, "三方平台暂时不可用，请稍后重试").
		WithDetail("platform", platform).
		WithDetail("circuit", "open").
		WithRetryAfter(retryAfter)
}

// StateClosedName 是"闭合"状态的字符串表示，与 State.CircuitState 的取值同源。
//
// 单独导出是因为展示层有一个除它无法表达的语义：**熔断器尚未被创建**。
// 熔断器是首次调用时惰性创建的，服务刚启动时 States() 为空列表，
// 而"没有熔断器"在运维视图里与"闭合"等价——展示层需要一个已知的初值。
var StateClosedName = gobreaker.StateClosed.String()

// State 是单个熔断器的对外视图（管理端展示用）。
type State struct {
	Platform           string     `json:"platform"`
	Scene              string     `json:"scene,omitempty"`
	CircuitState       string     `json:"circuit_state"` // closed | open | half-open
	OpenedAt           *time.Time `json:"opened_at,omitempty"`
	Counted            int        `json:"counted_requests"`
	FailureRatio       float64    `json:"recent_failure_ratio"`
	TimeoutRatio       float64    `json:"recent_timeout_ratio"`
	SlowRatio          float64    `json:"recent_slow_ratio"`
	HalfOpenProbesLeft int        `json:"half_open_probes_left"`
}

// States 返回全部熔断器状态，按平台排序（稳定输出便于比对）。
func (g *Guard) States() []State {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	items := make([]*item, 0, len(g.items))
	for _, it := range g.items {
		items = append(items, it)
	}
	g.mu.RUnlock()

	out := make([]State, 0, len(items))
	for _, it := range items {
		out = append(out, g.stateOf(it))
	}
	// 简单插入排序，避免为一个展示列表引入 sort 依赖的额外分配。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Platform < out[j-1].Platform; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// StateOf 返回指定平台的状态。第二个返回值表示该平台是否已建立熔断器
// （从未被调用过的渠道不会出现在列表里，这是正常现象）。
func (g *Guard) StateOf(platform string) (State, bool) {
	if g == nil {
		return State{}, false
	}
	g.mu.RLock()
	it := g.items[platform]
	g.mu.RUnlock()
	if it == nil {
		return State{}, false
	}
	return g.stateOf(it), true
}

func (g *Guard) stateOf(it *item) State {
	s := it.win.snapshot(g.now())
	st := State{
		Platform:     it.platform,
		Scene:        it.scene,
		CircuitState: it.cb.State().String(),
		Counted:      s.Counted,
		FailureRatio: round4(s.FailureRatio),
		TimeoutRatio: round4(s.TimeoutRatio),
		SlowRatio:    round4(s.SlowRatio),
	}
	if it.cb.State() == gobreaker.StateHalfOpen {
		used := it.cb.Counts().Requests
		left := int(g.cfg.HalfOpenRequests) - int(used)
		if left < 0 {
			left = 0
		}
		st.HalfOpenProbesLeft = left
	}
	it.stateMu.Lock()
	if it.everOpen && !it.openedAt.IsZero() {
		t := it.openedAt
		st.OpenedAt = &t
	}
	it.stateMu.Unlock()
	return st
}

// Reset 手工复位某个平台的熔断器（管理端 circuit-reset）。
//
// gobreaker 没有公开的 Reset，正确做法是替换实例——同时把统计窗口一起清空，
// 否则复位后窗口里的旧失败会立刻把它重新熔断，"复位"就成了摆设。
func (g *Guard) Reset(platform string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	keys := make([]string, 0, 1)
	for k, it := range g.items {
		if it.platform == platform {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		it := g.items[k]
		g.items[k] = g.newItem(it.key, it.platform, it.scene)
	}
	return true
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}
