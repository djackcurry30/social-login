// Command loadgen 是最小压测工具：固定并发打一个 URL，输出延迟分位与错误分布。
//
// 为什么自己写而不是用 hey / wrk：
//
//  1. 只想回答一个问题——"这版实现能扛多少、P99 是多少"，不需要完整压测平台；
//  2. 压测里最容易被忽略的是【错误分布】：平均延迟好看但 30% 请求拿到
//     AUTH.NEED_REGISTER 的话，那个 QPS 毫无意义。所以这里按状态码 + 错误码
//     分别计数；
//  3. 依赖零：go run 就能跑，不需要在目标机器装工具（生产压测常在受限环境）。
//
// 用法：
//
//	go run ./cmd/loadgen -url http://127.0.0.1:8080/v1/jwks -n 20000 -c 50
//	go run ./cmd/loadgen -url ... -H "Authorization: Bearer xxx" -n 5000 -c 20
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		url     = flag.String("url", "", "目标 URL（必填）")
		total   = flag.Int("n", 1000, "总请求数")
		conc    = flag.Int("c", 10, "并发数")
		timeout = flag.Duration("timeout", 5*time.Second, "单请求超时")
		headers headerList
	)
	flag.Var(&headers, "H", "附加请求头，可重复：-H 'Authorization: Bearer xxx'")
	flag.Parse()

	if *url == "" || *total <= 0 || *conc <= 0 {
		fmt.Fprintln(os.Stderr, "用法: loadgen -url <URL> [-n 请求数] [-c 并发数] [-H 'K: V']")
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			MaxIdleConns:        *conc * 2,
			MaxIdleConnsPerHost: *conc * 2,
			IdleConnTimeout:     30 * time.Second,
		},
		// 压测不跟随重定向：跟随会让"302 到错误页"看起来像成功。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	var (
		ok, failed int64
		latMu      sync.Mutex
		latencies  = make([]time.Duration, 0, *total)
		statusMu   sync.Mutex
		statuses   = map[int]int{}
	)

	jobs := make(chan struct{}, *conc*2)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				req, err := http.NewRequest(http.MethodGet, *url, nil)
				if err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				for _, h := range headers {
					req.Header.Set(h[0], h[1])
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(t0)
				if err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()

				latMu.Lock()
				latencies = append(latencies, elapsed)
				latMu.Unlock()

				statusMu.Lock()
				statuses[resp.StatusCode]++
				statusMu.Unlock()

				// 只有 2xx/3xx 算成功：压测里把 4xx 算成功是最常见的自欺。
				if resp.StatusCode < 400 {
					atomic.AddInt64(&ok, 1)
				} else {
					atomic.AddInt64(&failed, 1)
				}
			}
		}()
	}

	for i := 0; i < *total; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()

	wall := time.Since(start)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Printf("URL        %s\n", *url)
	fmt.Printf("并发/总数   %d / %d\n", *conc, *total)
	fmt.Printf("总耗时      %s\n", wall.Round(time.Millisecond))
	fmt.Printf("QPS         %.1f\n", float64(*total)/wall.Seconds())
	fmt.Printf("成功/失败   %d / %d\n", ok, failed)
	if len(latencies) > 0 {
		fmt.Printf("P50/P95/P99 %s / %s / %s（max %s）\n",
			pct(latencies, 50).Round(time.Microsecond),
			pct(latencies, 95).Round(time.Microsecond),
			pct(latencies, 99).Round(time.Microsecond),
			latencies[len(latencies)-1].Round(time.Microsecond))
	}
	if len(statuses) > 0 {
		fmt.Println("状态码分布")
		codes := make([]int, 0, len(statuses))
		for c := range statuses {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Printf("  %d  %d\n", c, statuses[c])
		}
	}
}

// pct 返回第 p 百分位延迟（最近秩法，样本量足够时足够准）。
func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p*len(sorted) + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

// headerList 解析可重复的 -H 参数。
type headerList [][2]string

func (h *headerList) String() string { return fmt.Sprint([][2]string(*h)) }

func (h *headerList) Set(v string) error {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("请求头格式应为 'Key: Value'，收到 %q", v)
	}
	*h = append(*h, [2]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
	return nil
}
