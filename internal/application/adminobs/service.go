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
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/guards/breaker"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// ProviderHealth 是单渠道的健康结果。
type ProviderHealth struct {
	Platform    string `json:"platform"`
	Scene       string `json:"scene"`
	DisplayName string `json:"display_name"`
	APIVersion  string `json:"api_version"`
	OK          bool   `json:"ok"`
	LatencyMs   int64  `json:"latency_ms"`
	Error       string `json:"error,omitempty"`

	// 熔断状态（架构 §5.6.9 的扩展要求）。
	//
	// 健康探测与熔断是两套机制：探测是主动的、仅用于展示；熔断是被动统计
	// 真实业务调用。放在同一个响应里只是为了让运维一屏看到全貌，
	// 绝不意味着探测结果参与熔断决策。
	CircuitState       string     `json:"circuit_state,omitempty"`
	CircuitOpenedAt    *time.Time `json:"circuit_opened_at,omitempty"`
	RecentFailureRatio float64    `json:"recent_failure_ratio"`
	RecentTimeoutRatio float64    `json:"recent_timeout_ratio"`
}

// Deps 是用例依赖。
type Deps struct {
	// Provider 列表用 provider.Global() 拿，但允许测试注入。
	ProviderLister func() []provider.Metadata
	// PingHTTP 是单渠道 ping 的 HTTP 入口。
	PingHTTP func(ctx context.Context, p provider.Metadata) (latency time.Duration, err error)
	// PingSource 走适配器自己的 HealthChecker（推荐）。
	//
	// 与 PingHTTP 的分工：PingSource 知道该平台的真实健康端点与协议
	// （微信的稳定 token、Apple 的 JWKS 端点），而通用 PingHTTP 只能猜。
	PingSource func(ctx context.Context, platform, scene string) error
	// Overview 摘要是简单的"渠道数 + 注册应用数"，由调用方注入。
	OverviewGetter func(ctx context.Context) (OverviewStats, error)
	// CircuitStates 返回熔断器快照（nil 表示未启用熔断）。
	CircuitStates func() []breaker.State
	// ResetCircuit 手工复位某个平台的熔断器。
	ResetCircuit func(platform string) bool
	// AdminAudit 写管理审计（circuit-reset 是写操作，必须留痕）。
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
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
	ProbedAt time.Time        `json:"probed_at"`
	Items    []ProviderHealth `json:"items"`
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
	// 优先走适配器自己的 HealthChecker：它知道该平台真正的健康端点。
	// PingHTTP 只作为兜底（配置驱动的通用渠道没有固定端点可探测）。
	pingSource := s.deps.PingSource

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

			started := time.Now()
			var err error
			if pingSource != nil {
				err = pingSource(pingCtx, p.Platform, p.Scene)
			} else {
				_, err = ping(pingCtx, p)
			}
			lat := time.Since(started)

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
			// 熔断器是【首次调用时惰性创建】的（架构 D7：注册在 init，建表在运行期），
			// 因此服务刚启动、还没任何业务流量时，States() 返回空列表。
			// 这时如果直接照抄空结果，运维会看到"熔断状态字段缺失"，误以为没装配。
			// 正确的默认值是 closed：没有失败记录，等价于闭合。
			if states := s.circuitStates(); states != nil {
				item.CircuitState = breaker.StateClosedName
				for _, cs := range states {
					if cs.Platform != p.Platform {
						continue
					}
					// 按场景粒度时只取同场景的那条；平台粒度时 Scene 为空。
					if cs.Scene != "" && cs.Scene != p.Scene {
						continue
					}
					item.CircuitState = cs.CircuitState
					item.CircuitOpenedAt = cs.OpenedAt
					item.RecentFailureRatio = cs.FailureRatio
					item.RecentTimeoutRatio = cs.TimeoutRatio
					break
				}
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
	ProviderCount      int            `json:"provider_count"`
	AppsCount          int            `json:"apps_count"`
	HealthyProviders   int            `json:"healthy_providers"`
	UnhealthyProviders int            `json:"unhealthy_providers"`
	ByPlatform         map[string]int `json:"by_platform"`
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

// ResetCircuitInput 是 POST /admin/v1/providers/{platform}:circuit-reset 的入参。
type ResetCircuitInput struct {
	Platform  string
	Reason    string
	Principal *admin.Principal
	ClientIP  string
}

// ResetCircuit 手工复位熔断器（架构 §5.6.9）。
//
// 适用场景是【误熔断】：比如我们自己的凭据配错了，导致连续失败被判定为
// 平台故障。修好配置后不必等 open_seconds 自然过期。
//
// 复位会同时清空统计窗口——只替换状态机而保留窗口的话，复位后窗口里的
// 旧失败会立刻把它重新熔断，"复位"就成了摆设。
func (s *Service) ResetCircuit(ctx context.Context, in ResetCircuitInput) error {
	if strings.TrimSpace(in.Platform) == "" {
		return errs.New(errs.CodeInvalidRequest, "缺少 platform").
			WithDetail("field", "platform")
	}
	// 与其它高危写操作一致：reason ≥ 4 字符，否则审计里只是一句空话。
	reason := strings.TrimSpace(in.Reason)
	if len(reason) < 4 {
		return errs.New(errs.CodeAdminReasonRequired, "高危操作必须填写 reason（至少 4 个字符）").
			WithDetail("field", "reason")
	}
	if s.deps.ResetCircuit == nil {
		return errs.New(errs.CodeProviderNotSupported, "熔断器未启用（provider_guard.circuit_breaker.enabled=false）")
	}

	before := s.circuitStateOf(in.Platform)
	if !s.deps.ResetCircuit(in.Platform) {
		// 从未被调用过的渠道没有熔断器实例。这不是错误，但也没有可复位的东西，
		// 需要明确告知，否则运维会以为"点了没反应"。
		return errs.Newf(errs.CodeProviderNotFound,
			"渠道 %s 尚未建立熔断器（可能是从未被调用过），无需复位", in.Platform).
			WithDetail("platform", in.Platform)
	}

	if s.deps.AdminAudit != nil {
		ev := &admin.AuditEvent{
			Action:     "provider.circuit.reset",
			TargetType: "provider",
			TargetID:   in.Platform,
			Reason:     reason,
			BeforeState: map[string]any{
				"circuit_state": before,
			},
			AfterState: map[string]any{
				"circuit_state": "closed",
			},
			Result:   "success",
			ClientIP: in.ClientIP,
		}
		if in.Principal != nil && in.Principal.User != nil {
			ev.SubjectID = "admin:" + strconv.FormatInt(in.Principal.User.ID, 10)
		} else {
			ev.SubjectID = "admin:anonymous"
		}
		if err := s.deps.AdminAudit.Write(ctx, ev); err != nil && s.deps.Logger != nil {
			// 审计是旁路：写失败不阻断操作，但必须留日志。
			s.deps.Logger.Error("写管理审计失败", zap.String("action", ev.Action), zap.Error(err))
		}
	}
	return nil
}

// CircuitStates 返回全部熔断器快照（供 /providers/health 与管理端展示）。
func (s *Service) CircuitStates() []breaker.State { return s.circuitStates() }

func (s *Service) circuitStates() []breaker.State {
	if s.deps.CircuitStates == nil {
		return nil
	}
	return s.deps.CircuitStates()
}

func (s *Service) circuitStateOf(platform string) string {
	for _, cs := range s.circuitStates() {
		if cs.Platform == platform {
			return cs.CircuitState
		}
	}
	return "unknown"
}

// defaultPingHTTP 是默认的渠道 ping：调一次 token_url 的 client_credentials。//
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
