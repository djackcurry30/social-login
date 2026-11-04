// Package accountsync 把本地应用注册到用户中心（契约 v1.1 §2.6）。
//
// 为什么需要这个包：用户中心把账号按 app_key 隔离，未注册的 app_key 一律
// 400 APP.UNKNOWN。也就是说"应用已注册"是登录的前置条件，不是配置装饰——
// 一个没同步过去的应用，表现是该应用【所有】登录都失败。而建应用与登录是
// 两条独立链路，同步必须是旁路，不能反过来让建应用依赖用户中心可用。
//
// 两条路径，一快一慢：
//
//  1. 即时同步 —— 建应用 / 启停后入队，几百毫秒内完成。运维刚建完就能登录。
//  2. 定时对账 —— 每 5 分钟把全部应用重放一遍。自愈三类问题：
//     "建应用时用户中心正好不可用"、"用户中心上线前就存在的存量应用"、
//     "对端数据被回滚或被清理"。
//
// 三条纪律：
//
//  1. 全部旁路：同步失败绝不影响建应用（失败只记录状态 + warn）。
//  2. 全部幂等：对端 upsert，重复同步无副作用，所以可以对账时无脑重放。
//  3. 状态落库：失败要能被看见。只打日志等于没做——日志会滚掉，
//     而"这个应用到底注册上没有"是运维每天都要回答的问题。
package accountsync

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/tracing"
)

const (
	// DefaultInterval 是全量对账周期。
	//
	// 5 分钟是"故障自愈足够快"与"对端不至于被无意义的重复写入打扰"之间的
	// 折中。它同时是本服务对"对端数据漂移"的最长无感时间，所以不能太长。
	DefaultInterval = 5 * time.Minute

	// DefaultTimeout 是单次远端注册调用的超时。
	//
	// 与登录链路一样取 3s（HTTPAccountProvider 的默认值）：后台任务虽然没有
	// 用户在等，但一个卡住的调用会占住 worker，把整轮对账拖过周期。
	DefaultTimeout = 3 * time.Second

	// defaultWorkers 是单轮对账的并发数。
	//
	// 为什么不是 1：串行在应用多时跑不完一个周期（假设 500 个应用、每个都
	// 超时 3s，一轮要 25 分钟，下一轮会追上上一轮，形成堆积）。
	// 为什么不是"有多少开多少"：启动瞬间会对对端形成几十个并发请求的尖峰，
	// 而那正好是用户中心最不该被打扰的时刻（它可能刚重启）。
	// 4 个 worker × 3s 上限 ≈ 每分钟 80 个应用，500 个应用约 6 分钟一轮。
	defaultWorkers = 4

	// maxWorkers 是并发上限。再大对端收益很小，对我方只是多占连接。
	maxWorkers = 16

	// queueSize 是即时同步队列长度。
	//
	// 队列满时【丢弃】，不阻塞调用方：丢弃只意味着要等下一轮对账（≤5 分钟），
	// 而阻塞会让"用户中心故障"升级成"建应用卡住"——后者严重得多。
	queueSize = 256

	// listLimit 是单轮对账拉取的应用上限，与仓储的默认值一致。
	listLimit = 500

	// statusWriteTimeout 是写同步状态的超时。
	//
	// 写状态用的是 context.WithoutCancel，没有任何上游取消能兜住它，
	// 所以必须自己设一个上限，否则库抖动会让 worker 挂在这里。
	statusWriteTimeout = 3 * time.Second
)

// Report 是一轮对账的统计。
//
// 返回统计而不是只返回 error：部分应用失败时"总数 / 成功 / 失败"才是运维
// 要看的数字（"160 个应用里 3 个同步失败"与"同步全挂了"是两回事），
// 只返回第一个 error 会把这种区别抹掉。
type Report struct {
	Total     int
	Succeeded int
	Failed    int
}

// Deps 是用例依赖。
type Deps struct {
	Apps AppSource
	// Registrar 是用户中心的注册端口。为 nil 表示"没有用户中心"
	// （stub 模式或显式关闭），此时整个同步能力不启用。
	Registrar account.AppRegistrar
	Recorder  SyncRecorder
	Logger    *zap.Logger

	// Interval / Timeout / Workers 留空时取默认值。
	Interval time.Duration
	Timeout  time.Duration
	Workers  int

	// Now 用于测试注入时间。
	Now func() time.Time
}

// Service 是注册同步用例入口。
type Service struct {
	deps  Deps
	queue chan string
}

// New 构造服务。
//
// 不做"Registrar 为 nil 就自动禁用"的隐式处理是刻意的：调用方（bootstrap）
// 必须自己判断"有没有用户中心"，这样"该同步却没同步"这件事在装配处就能
// 看出来，而不是运行起来才发现所有应用都没注册。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.Interval <= 0 {
		d.Interval = DefaultInterval
	}
	if d.Timeout <= 0 {
		d.Timeout = DefaultTimeout
	}
	if d.Workers <= 0 {
		d.Workers = defaultWorkers
	}
	if d.Workers > maxWorkers {
		d.Workers = maxWorkers
	}
	return &Service{deps: d, queue: make(chan string, queueSize)}
}

// NotifyAppChanged 把某个应用排入即时同步队列。
//
// ⚠️ 必须【非阻塞】：它是在建应用 / 启停应用的请求链路里被调用的。
// 用户中心故障时如果这里阻塞或返回错误，就变成"用户中心挂了 → 建不了应用"，
// 而建应用恰恰是恢复期最需要的操作。
//
// 只传 app_code 不传应用结构体，有两个原因：
//   - 避免快照过期：建完立刻改名/停用，队列里那份就是错的。
//   - 避免把请求 ctx 带进后台：请求结束即取消，后台任务会用到一个已取消的
//     context，表现是"同步永远失败但不报错"。
func (s *Service) NotifyAppChanged(appCode string) {
	if appCode == "" {
		return
	}
	select {
	case s.queue <- appCode:
	default:
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("应用同步队列已满，跳过即时同步（下一轮对账会覆盖）",
				zap.String("app_code", appCode))
		}
	}
}

// Run 启动同步循环，阻塞直到 ctx 取消。
func (s *Service) Run(ctx context.Context) {
	if s.deps.Registrar == nil {
		if s.deps.Logger != nil {
			s.deps.Logger.Info("未接用户中心，应用注册同步不启用")
		}
		return
	}

	ticker := time.NewTicker(s.deps.Interval)
	defer ticker.Stop()

	// 启动即对账一次。理由不是"图省事"，而是服务重启后不该有一个空窗：
	// 停机期间新建的应用、以及用户中心上线前的存量应用，都要尽快可用。
	s.reconcileLogged(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case appCode := <-s.queue:
			s.syncByCode(ctx, appCode)
		case <-ticker.C:
			s.reconcileLogged(ctx)
		}
	}
}

// Reconcile 执行一轮全量对账（同步调用，供测试与手工触发使用）。
func (s *Service) Reconcile(ctx context.Context) (Report, error) {
	if s.deps.Registrar == nil {
		// 没有注册能力（stub 模式）。返回零值而不是错误："未接用户中心"
		// 是合法配置，调用方不需要为此走错误分支。
		return Report{}, nil
	}

	apps, err := s.deps.Apps.ListForSync(ctx, listLimit)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Total: len(apps)}
	if len(apps) == 0 {
		return rep, nil
	}

	var okCount, failCount int64
	idx := make(chan int)
	var wg sync.WaitGroup

	for i := 0; i < s.workers(len(apps)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range idx {
				if err := s.syncApp(ctx, &apps[j]); err != nil {
					atomic.AddInt64(&failCount, 1)
					continue
				}
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}

dispatch:
	for i := range apps {
		select {
		case idx <- i:
		case <-ctx.Done():
			// 退出中：不再投递新任务，等已投递的收敛（每次调用自带超时）。
			break dispatch
		}
	}
	close(idx)
	wg.Wait()

	rep.Succeeded = int(atomic.LoadInt64(&okCount))
	rep.Failed = int(atomic.LoadInt64(&failCount))

	if err := ctx.Err(); err != nil {
		// 退出导致的中断不是"对账失败"，把 ctx 的错误如实带出去，
		// 让调用方能区分"对端有问题"和"我们在关闭"。
		return rep, err
	}
	return rep, nil
}

// --- 内部 ---

// reconcileLogged 跑一轮对账并按结果分级打日志。
//
// 分级的意义：全部失败时打 Error（多半是全链路故障或配置错，要人看）；
// 部分失败打 Warn（单个应用的问题，下一轮可能自愈）；全部成功打 Info，
// 且只在确实同步了应用时打，避免空库环境每 5 分钟刷一行。
func (s *Service) reconcileLogged(ctx context.Context) {
	rep, err := s.Reconcile(ctx)
	if err != nil {
		if s.deps.Logger != nil && ctx.Err() == nil {
			s.deps.Logger.Error("应用注册对账失败", zap.Error(err))
		}
		return
	}
	if s.deps.Logger == nil {
		return
	}
	switch {
	case rep.Total == 0:
		return
	case rep.Failed == 0:
		s.deps.Logger.Info("应用注册对账完成",
			zap.Int("total", rep.Total), zap.Int("succeeded", rep.Succeeded))
	case rep.Succeeded == 0:
		s.deps.Logger.Error("应用注册对账全部失败：这些应用在用户中心不可用，登录会被拒绝",
			zap.Int("total", rep.Total), zap.Int("failed", rep.Failed))
	default:
		s.deps.Logger.Warn("应用注册对账部分失败",
			zap.Int("total", rep.Total),
			zap.Int("succeeded", rep.Succeeded),
			zap.Int("failed", rep.Failed))
	}
}

// syncByCode 按 app_code 读最新状态后同步一次。
func (s *Service) syncByCode(ctx context.Context, appCode string) {
	app, err := s.deps.Apps.FindByAppCode(ctx, appCode)
	switch {
	case errors.Is(err, tenant.ErrNotFound):
		// 入队之后被删掉了。不需要同步一个不存在的应用，也不是错误。
		if s.deps.Logger != nil {
			s.deps.Logger.Debug("应用已删除，跳过同步", zap.String("app_code", appCode))
		}
		return
	case err != nil:
		if s.deps.Logger != nil {
			s.deps.Logger.Warn("即时同步未能读取应用", zap.String("app_code", appCode), zap.Error(err))
		}
		return
	}
	_ = s.syncApp(ctx, app)
}

// syncApp 同步单个应用，并把结果写回状态。
//
// 开一个后台任务 span：这一轮对账里"哪个应用同步失败、卡在哪一步"，
// 靠日志要在几百行里 grep，靠 trace 一眼能看到（出站调用是它的子 span）。
func (s *Service) syncApp(ctx context.Context, app *tenant.Application) (err error) {
	ctx, span := tracing.Start(ctx, "job.appsync.sync",
		attribute.String("app.code", app.AppCode))
	defer func() {
		tracing.Fail(span, err)
		span.End()
	}()

	reg := account.AppRegistration{
		AppKey:         app.AppCode,
		Name:           app.Name,
		Status:         statusOf(app.Status),
		LocalUpdatedAt: app.UpdatedAt,
	}

	// 后台任务没有入站请求的 deadline 可继承，必须自己设上限：
	// HTTP 客户端的 timeout 只覆盖单次往返，重定向链与慢 DNS 都可能超出。
	callCtx, cancel := context.WithTimeout(ctx, s.deps.Timeout)
	defer cancel()

	if err := s.deps.Registrar.RegisterApp(callCtx, reg); err != nil {
		s.markFailed(ctx, app, err)
		return err
	}
	s.markSynced(ctx, app)
	return nil
}

// markSynced 记录成功。
func (s *Service) markSynced(ctx context.Context, app *tenant.Application) {
	if s.deps.Recorder == nil {
		return
	}
	writeCtx, cancel := detachedCtx(ctx)
	defer cancel()
	if err := s.deps.Recorder.MarkUCSynced(writeCtx, app.ID, s.deps.Now()); err != nil && s.deps.Logger != nil {
		// 状态写失败不影响"同步本身成功"，但要说出来：管理端会显示成未同步。
		s.deps.Logger.Warn("记录应用同步成功状态失败",
			zap.Int64("app_id", app.ID), zap.Error(err))
	}
}

// markFailed 记录失败。
func (s *Service) markFailed(ctx context.Context, app *tenant.Application, cause error) {
	if s.deps.Logger != nil {
		// 文案必须点明后果：只说"同步失败"没人知道这意味着这个应用登录全挂。
		s.deps.Logger.Warn("应用注册同步失败：该应用在用户中心的登录会被拒绝（APP.UNKNOWN），等待下一轮对账重试",
			zap.String("app_code", app.AppCode),
			zap.Int64("app_id", app.ID),
			zap.Error(cause))
	}
	if s.deps.Recorder == nil {
		return
	}
	writeCtx, cancel := detachedCtx(ctx)
	defer cancel()
	if err := s.deps.Recorder.MarkUCSyncFailed(writeCtx, app.ID, cause.Error()); err != nil && s.deps.Logger != nil {
		s.deps.Logger.Warn("记录应用同步失败状态失败",
			zap.Int64("app_id", app.ID), zap.Error(err))
	}
}

// detachedCtx 构造一个"不随请求/进程取消"的写上下文，并自带超时。
//
// 为什么写状态要用 WithoutCancel：进程关闭时 bgCtx 已经取消，但"这一轮同步
// 的结果"仍应落库——否则运维看到的最后一个状态会是上一轮的，重启后要再等
// 5 分钟才知道到底通不通。既然没了取消，就必须自己兜住超时。
func detachedCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
}

func (s *Service) workers(total int) int {
	if total < s.deps.Workers {
		return total
	}
	return s.deps.Workers
}

// statusOf 把本地行状态映射成契约里的字符串。
//
// 只有 1 是启用，其余（0 与任何历史脏值）都按停用同步：宁可让对端认为
// 应用已停用（业务会因此不可用、但会被立刻发现），也不要让一个状态不明的
// 应用在对端保持启用。
func statusOf(status int16) account.AppStatus {
	if status == 1 {
		return account.AppStatusActive
	}
	return account.AppStatusDisabled
}
