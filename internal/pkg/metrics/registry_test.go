package metrics

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCounterRendersPrometheusFormat(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("social_login_test_total", "测试计数", "platform", "result")
	c.Inc("wechat", "success")
	c.Inc("wechat", "success")
	c.Inc("alipay", "failed")

	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatalf("导出失败: %v", err)
	}

	want := `# HELP social_login_test_total 测试计数
# TYPE social_login_test_total counter
social_login_test_total{platform="alipay",result="failed"} 1
social_login_test_total{platform="wechat",result="success"} 2
`
	// 逐字节比对：输出顺序必须稳定，否则抓取端每次 diff 都会误报变化。
	if b.String() != want {
		t.Fatalf("输出不符\nwant:\n%s\ngot:\n%s", want, b.String())
	}
}

func TestCounterWithoutLabels(t *testing.T) {
	r := NewRegistry()
	r.Counter("social_login_plain_total", "无标签").Add(3.5)

	var b strings.Builder
	_, _ = r.WriteTo(&b)
	if !strings.Contains(b.String(), "social_login_plain_total 3.5\n") {
		t.Fatalf("无标签指标渲染错误:\n%s", b.String())
	}
}

func TestGaugeFuncEvaluatedAtScrapeTime(t *testing.T) {
	r := NewRegistry()
	v := 1.0
	r.GaugeFunc("social_login_open", "即时值", func() float64 { return v })

	scrape := func() string {
		var b strings.Builder
		_, _ = r.WriteTo(&b)
		return b.String()
	}

	if !strings.Contains(scrape(), "social_login_open 1\n") {
		t.Fatal("首次采集值不符")
	}
	v = 7
	// 关键语义：值在采集时求值，不是注册时快照。
	if !strings.Contains(scrape(), "social_login_open 7\n") {
		t.Fatal("gauge 必须在采集时重新求值")
	}
}

// 标签值里的引号/换行/反斜杠必须转义，否则一个带引号的路由参数
// 就能让整个 /metrics 输出被 Prometheus 解析器拒绝。
func TestLabelEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("social_login_esc_total", "转义", "path")
	c.Inc(`a"b\c` + "\nd")

	var b strings.Builder
	_, _ = r.WriteTo(&b)
	out := b.String()
	if !strings.Contains(out, `path="a\"b\\c\nd"`) {
		t.Fatalf("转义不符:\n%s", out)
	}
	// 转义后不能出现裸换行把一行拆成两行。
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "social_login_esc_total{") && strings.Count(line, "{") != 1 {
			t.Fatalf("标签被换行截断: %q", line)
		}
	}
}

func TestSameNameDifferentTypePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("同名不同类型必须 panic")
		}
	}()
	r := NewRegistry()
	r.Counter("dup", "x")
	r.GaugeFunc("dup", "x", func() float64 { return 0 })
}

func TestLabelCountMismatchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("标签数量不符必须 panic（编程错误应在测试期暴露）")
		}
	}()
	r := NewRegistry()
	r.Counter("c", "x", "a", "b").Inc("only-one")
}

// 并发累加不能丢计数。
func TestCounterConcurrent(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("social_login_conc_total", "并发", "k")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Inc("v")
			}
		}()
	}
	wg.Wait()

	var b strings.Builder
	_, _ = r.WriteTo(&b)
	if !strings.Contains(b.String(), `social_login_conc_total{k="v"} 10000`) {
		t.Fatalf("并发计数丢失:\n%s", b.String())
	}
}

func TestHandlerContentType(t *testing.T) {
	r := NewRegistry()
	r.Counter("social_login_h_total", "x").Inc()

	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))

	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type 不符: %s", ct)
	}
	if !strings.Contains(w.Body.String(), "social_login_h_total 1") {
		t.Fatalf("响应体不符: %s", w.Body.String())
	}
}
