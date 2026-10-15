// Package adminobs 是管理端"观测与健康（I 组，本期精简）"用例。
//
// 本期只交付 3 个接口（去掉 §15.4 中的 circuit-reset，留给第四期）：
//   - GET    /admin/v1/providers               已注册渠道清单
//   - GET    /admin/v1/providers/health        渠道健康探测
//   - GET    /admin/v1/health/overview         关键指标摘要
//
// circuit-reset 的依赖（熔断器状态/最近失败比）§5.6 还在演进，暂不交付。
package adminobs

import (
	"context"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// ProviderHealth 是单渠道的健康结果。
type ProviderHealth struct {
	Platform  string        `json:"platform"`
	Scene     string        `json:"scene"`
	DisplayName string      `json:"display_name"`
	APIVersion string        `json:"api_version"`
	OK         bool          `json:"ok"`
	LatencyMs  int64         `json:"latency_ms"`
	Error      string        `json:"error,omitempty"`
	// CircuitState / OpenedAt / RecentFailureRatio 留到 §5.6 第四期联动实现。
}

// Deps 是用例依赖。
type Deps struct {
	// Provider 列表用 provider.Global() 拿，但允许测试注入。
	ProviderLister func() []provider.Metadata
	// PingHTTP 是单渠道 ping 的 HTTP 入口。
	// 默认实现 ping token_url 的 client_credentials（同 adminchan.VerifyHTTPDefault）。
	PingHTTP func(ctx context.Context, p provider.Metadata) (latency time.Duration, err error)
	// Overview 摘要是简单的"渠道数 + 注册应用数"，由调用方注入。
	OverviewGetter func(ctx context.Context) (OverviewStats, error)
	Logger         *zap.Logger
}

// Service 是 I 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	return &Service{deps: d}
}

// ListProviders 返回已注册渠道清单。
func (s *Service) ListProviders() []provider.Metadata {
	lister := s.deps.ProviderLister
	if lister == nil {
		lister = func() []provider.Metadata { return provider.Global().List() }
	}
	out := lister()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].Scene < out[j].Scene
	})
	return out
}

// HealthResult 是 providers/health 的出参。
type HealthResult struct {
	ProbedAt time.Time         `json:"probed_at"`
	Items    []ProviderHealth  `json:"items"`
}

// PingProviders 并发探测全部渠道可达性。
//
// 超时 3s/渠道；并发数 = 渠道数（一般 4-8 个，足够）。
func (s *Service) PingProviders(ctx context.Context) (*HealthResult, error) {
	ps := s.ListProviders()
	out := &HealthResult{
		ProbedAt: time.Now().UTC(),
		Items:    make([]ProviderHealth, 0, len(ps)),
	}
	if len(ps) == 0 {
		return out, nil
	}
	ping := s.deps.PingHTTP
	if ping == nil {
		ping = defaultPingHTTP()
	}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, p := range ps {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			lat, err := ping(pingCtx, p)
			item := ProviderHealth{
				Platform:    p.Platform,
				Scene:       p.Scene,
				DisplayName: p.DisplayName,
				APIVersion:  p.APIVersion,
				OK:          err == nil,
				LatencyMs:   lat.Milliseconds(),
			}
			if err != nil {
				item.Error = err.Error()
			}
			mu.Lock()
			out.Items = append(out.Items, item)
			mu.Unlock()
		}()
	}
	wg.Wait()
	// 让结果稳定有序
	sort.Slice(out.Items, func(i, j int) bool {
		if out.Items[i].Platform != out.Items[j].Platform {
			return out.Items[i].Platform < out.Items[j].Platform
		}
		return out.Items[i].Scene < out.Items[j].Scene
	})
	return out, nil
}

// OverviewStats 是 health/overview 的摘要。
type OverviewStats struct {
	ProviderCount     int                    `json:"provider_count"`
	AppsCount         int                    `json:"apps_count"`
	HealthyProviders  int                    `json:"healthy_providers"`
	UnhealthyProviders int                   `json:"unhealthy_providers"`
	ByPlatform        map[string]int         `json:"by_platform"`
}

// Overview 关键指标摘要。
func (s *Service) Overview(ctx context.Context) (OverviewStats, error) {
	stats := OverviewStats{
		ByPlatform: make(map[string]int),
	}
	ps := s.ListProviders()
	stats.ProviderCount = len(ps)
	for _, p := range ps {
		stats.ByPlatform[p.Platform]++
	}
	health, err := s.PingProviders(ctx)
	if err != nil {
		return stats, err
	}
	for _, h := range health.Items {
		if h.OK {
			stats.HealthyProviders++
		} else {
			stats.UnhealthyProviders++
		}
	}
	if s.deps.OverviewGetter != nil {
		// 让调用方把 apps_count 等额外指标补上
		extra, err := s.deps.OverviewGetter(ctx)
		if err == nil {
			stats.AppsCount = extra.AppsCount
		}
	}
	return stats, nil
}

// defaultPingHTTP 是默认的渠道 ping：调一次 token_url 的 client_credentials。
//
// 这里不解析 access_token——只看 HTTP 200/401/4xx/5xx 区分"通了但凭据错"和"根本没通"。
func defaultPingHTTP() func(ctx context.Context, p provider.Metadata) (time.Duration, error) {
	c := httpx.New(httpx.Config{
		Name:         "admin-ping",
		TotalTimeout: 3 * time.Second,
	})
	return func(ctx context.Context, _ provider.Metadata) (time.Duration, error) {
		// 注意：渠道的 token_url 来自 ProviderConfig.extra，不是 Metadata 本身。
		// 这里取不到 extra，所以仅做"直连 base URL"——base URL 也来自 extra，
		// Metadata 没有。I 组 ping 在生产中需要"按已注册配置 ping"——本期先返回 SKIP。
		// 详见下一期：providers/health 改成走 adminchan.VerifyConfig 的批量版本。
		_ = c
		return 0, errs.New(errs.CodeInternal, "providers/health 暂未接入（下一期）")
	}
}
