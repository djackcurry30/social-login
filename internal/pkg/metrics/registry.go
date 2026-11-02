// Package metrics 是一个极小的 Prometheus 文本格式导出实现。
//
// 为什么不用 prometheus/client_golang：
//
//  1. 本服务需要的指标类型只有 counter（累计次数）与 gauge（当前值），
//     直方图用 <name>_sum / <name>_count 两个 counter 就能表达平均值与总量，
//     分位数不是当前的需求（要看 P99 时再加 histogram 也不迟）。
//  2. 引入 SDK 会带来依赖树、与 zap 无关的全局注册表和一套初始化约定，
//     而我们要导出的指标数量是两位数以内。
//  3. 这个包的输出格式可以在测试里逐字节断言，行为完全可预期。
//
// 输出遵循 Prometheus 文本格式（version 0.0.4），采集端无需任何特殊配置。
//
// 命名约定：全部以 social_login_ 开头，指标名与标签名用 snake_case。
// 标签基数必须受控 —— 详见 middleware.Metrics 里对路由模板的处理说明。
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Registry 持有全部指标。
//
// 并发模型：注册发生在启动期（单 goroutine），采集发生在请求期。
// 用 RWMutex 而不是 sync.Map——指标数量小、采集频率低，可读性更重要。
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*GaugeFunc
	registered map[string]string // 指标名 → 类型，用于阻止同名不同类型
}

// NewRegistry 构造注册表。
func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*GaugeFunc),
		registered: make(map[string]string),
	}
}

// Counter 是一个可带标签的累计计数器。
type Counter struct {
	name   string
	help   string
	labels []string

	mu     sync.Mutex
	series map[string]*series
}

type series struct {
	labelValues []string
	value       float64
}

// Counter 返回（或创建）一个计数器。同名重复调用返回同一个实例。
//
// labels 必须与 Inc 的实参个数一致；不一致会 panic —— 那是编程错误，
// 让它在开发期炸出来，而不是在生产里静默记到错误的标签上。
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if typ, ok := r.registered[name]; ok && typ != "counter" {
		panic("metrics: 指标名重复且类型不同: " + name)
	}
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{
		name:   name,
		help:   help,
		labels: labels,
		series: make(map[string]*series),
	}
	r.counters[name] = c
	r.registered[name] = "counter"
	return c
}

// Inc 计数 1。
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add 增加 v。
func (c *Counter) Add(v float64, labelValues ...string) {
	if len(labelValues) != len(c.labels) {
		panic(fmt.Sprintf("metrics: %s 需要 %d 个标签值，实际 %d 个",
			c.name, len(c.labels), len(labelValues)))
	}
	key := seriesKey(labelValues)

	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.series[key]
	if !ok {
		s = &series{labelValues: append([]string(nil), labelValues...)}
		c.series[key] = s
	}
	s.value += v
}

// GaugeFunc 是一个采集时求值的即时值。
//
// 用回调而不是让调用方 Push：并发的业务代码不需要知道指标存在，
// 采集频率也由 Prometheus 决定（默认 15s 一次），避免每次业务动作都写指标。
type GaugeFunc struct {
	name string
	help string
	fn   func() float64
}

// GaugeFunc 注册一个即时值指标。
//
// fn 会在每次采集时被调用，必须自己控制耗时（例如查库要带超时），
// 否则一个慢查询会拖垮整个 /metrics 端点。
func (r *Registry) GaugeFunc(name, help string, fn func() float64) *GaugeFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	if typ, ok := r.registered[name]; ok && typ != "gauge" {
		panic("metrics: 指标名重复且类型不同: " + name)
	}
	if g, ok := r.gauges[name]; ok {
		// 允许重复注册（例如测试里换了个取数函数），以后注册的为准。
		g.fn = fn
		return g
	}
	g := &GaugeFunc{name: name, help: help, fn: fn}
	r.gauges[name] = g
	r.registered[name] = "gauge"
	return g
}

// WriteTo 输出 Prometheus 文本格式。
//
// 排序是为了让输出稳定：同样的数据每次抓取得到同样的字节序，
// 测试可以直接比对全文，抓取端做 diff 时也不会误报。
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	counters := make([]*Counter, 0, len(r.counters))
	for _, c := range r.counters {
		counters = append(counters, c)
	}
	gauges := make([]*GaugeFunc, 0, len(r.gauges))
	for _, g := range r.gauges {
		gauges = append(gauges, g)
	}
	r.mu.RUnlock()

	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })

	var n int64
	write := func(format string, args ...any) error {
		s, err := fmt.Fprintf(w, format, args...)
		n += int64(s)
		return err
	}

	for _, c := range counters {
		if err := write("# HELP %s %s\n", c.name, escapeHelp(c.help)); err != nil {
			return n, err
		}
		if err := write("# TYPE %s counter\n", c.name); err != nil {
			return n, err
		}
		for _, line := range c.render() {
			if err := write("%s\n", line); err != nil {
				return n, err
			}
		}
	}
	for _, g := range gauges {
		if err := write("# HELP %s %s\n", g.name, escapeHelp(g.help)); err != nil {
			return n, err
		}
		if err := write("# TYPE %s gauge\n", g.name); err != nil {
			return n, err
		}
		if err := write("%s %s\n", g.name, formatFloat(g.fn())); err != nil {
			return n, err
		}
	}
	return n, nil
}

// render 把系列渲染成文本行（按标签排序）。
func (c *Counter) render() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]string, 0, len(c.series))
	for k := range c.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		s := c.series[k]
		out = append(out, c.name+formatLabels(c.labels, s.labelValues)+" "+formatFloat(s.value))
	}
	return out
}

// formatFloat 输出不带指数的十进制，避免 1e+06 这种 Prometheus 能接受
// 但人肉排查时不直观的写法。
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// formatLabels 渲染 {k="v",...}；无标签时返回空串（指标行就是 name value）。
func formatLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(name)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(values[i]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabel 按文本格式规范转义标签值：反斜杠、双引号、换行。
//
// 不转义的后果不是"显示难看"，而是整个抓取请求被解析器拒绝——
// 一个带引号的路由参数就能让 /metrics 全站不可用。
func escapeLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func escapeHelp(s string) string {
	return strings.ReplaceAll(s, "\n", `\n`)
}

func seriesKey(values []string) string {
	// 用单元分隔符拼接：标签值里出现它的概率极低，
	// 且即使出现也不会与另一组值拼出相同的 key（长度随之变化）。
	return strings.Join(values, "\x1f")
}

// Handler 返回 /metrics 端点。
//
// 刻意不在这里做鉴权：Prometheus 的抓取端通常不支持复杂鉴权，
// 业界通行做法是"网络层限制来源"。部署时必须确保该路径只对监控网段开放
// （见 docs/implementation-status.md 的说明），不要直接暴露到公网。
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = r.WriteTo(w)
	})
}
