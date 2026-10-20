// Package auditexport 执行审计异步导出任务（§15.4 H 组的后台侧）。
//
// 为什么单独成包而不是塞进 adminaudit：
//   - 用例侧只做"提交 / 查询"，不碰文件系统；
//   - 执行侧要能被独立 goroutine 启动、独立单测，且将来若拆成独立进程，
//     只需要换 main 里的装配，用例代码不动。
//
// 与 outbox 的相似与不同：
//   - 相同：都是"表里排队 + 后台循环领取"，多副本靠 SQL 原子领取不重复处理；
//   - 不同：事件投递失败要退避重试（对外有副作用，丢了就是事故），
//     导出失败只需如实记录（重跑由用户重新提交），因此没有退避序列。
package auditexport

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Config 是执行参数。
type Config struct {
	// Dir 是导出文件落盘目录。必须可写。
	Dir string
	// Interval 是轮询间隔。导出是低频操作，2 秒足够。
	Interval time.Duration
	// MaxPerRound 是单轮最多执行的任务数（防止一次把 CPU 全占满）。
	MaxPerRound int
	// Batch 是流式读取的批次大小。
	Batch int
	// FileTTL 是文件保留期。
	FileTTL time.Duration
	// Timeout 是单个任务的执行上限。
	Timeout time.Duration
	// PurgeInterval 是清理过期文件的间隔。
	PurgeInterval time.Duration
}

// DefaultConfig 返回默认参数。
func DefaultConfig(dir string) Config {
	return Config{
		Dir:           dir,
		Interval:      2 * time.Second,
		MaxPerRound:   3,
		Batch:         500,
		FileTTL:       7 * 24 * time.Hour,
		Timeout:       10 * time.Minute,
		PurgeInterval: time.Hour,
	}
}

// Service 是导出执行器。
type Service struct {
	query  audit.Query
	store  audit.ExportStore
	cfg    Config
	logger *zap.Logger
	now    func() time.Time
}

// New 构造执行器。
func New(query audit.Query, store audit.ExportStore, cfg Config, logger *zap.Logger) *Service {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	if cfg.MaxPerRound <= 0 {
		cfg.MaxPerRound = 3
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 500
	}
	if cfg.FileTTL <= 0 {
		cfg.FileTTL = 7 * 24 * time.Hour
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	if cfg.PurgeInterval <= 0 {
		cfg.PurgeInterval = time.Hour
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{query: query, store: store, cfg: cfg, logger: logger, now: time.Now}
}

// Run 启动循环，直到 ctx 结束。
func (s *Service) Run(ctx context.Context) {
	if s.cfg.Dir == "" {
		// 没有目录就不启动：静默空转会让"提交了却永远 pending"变成谜案。
		s.logger.Error("审计导出未配置落盘目录，worker 不启动")
		return
	}
	if err := os.MkdirAll(s.cfg.Dir, 0o750); err != nil {
		s.logger.Error("创建审计导出目录失败，worker 不启动",
			zap.String("dir", s.cfg.Dir), zap.Error(err))
		return
	}
	// 启动期可写探测。
	//
	// 不探测的后果很具体：目录存在但属主不对（典型场景是 Docker named volume
	// 以 root:root 初始化，而进程以非 root 运行）时，MkdirAll 会成功，
	// worker 照常启动，直到用户第一次点导出才以 "permission denied" 失败——
	// 排查成本远高于启动时一条 Error。
	if err := probeWritable(s.cfg.Dir); err != nil {
		s.logger.Error("审计导出目录不可写，worker 不启动",
			zap.String("dir", s.cfg.Dir),
			zap.String("hint", "检查目录属主与进程运行用户；Docker 下需确保卷的属主是运行用户"),
			zap.Error(err))
		return
	}

	// 上次进程留下的 running 任务退回 pending：不这么做它们会永远卡住
	// （导出没有租约，见仓储层注释）。
	if rq, ok := s.store.(audit.StaleRequeuer); ok {
		if n, err := rq.RequeueStale(ctx); err != nil {
			s.warn("重置遗留导出任务失败", err)
		} else if n > 0 {
			s.logger.Warn("发现上次进程遗留的导出任务，已重新入队", zap.Int64("count", n))
		}
	}

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	purge := time.NewTicker(s.cfg.PurgeInterval)
	defer purge.Stop()

	if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
		s.warn("审计导出首轮失败", err)
	}
	s.purgeOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.RunOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.warn("审计导出执行失败", err)
			}
		case <-purge.C:
			s.purgeOnce(ctx)
		}
	}
}

// RunOnce 执行本轮待办任务，返回执行成功的任务数。可单测直接调用。
func (s *Service) RunOnce(ctx context.Context) (int, error) {
	done := 0
	for i := 0; i < s.cfg.MaxPerRound; i++ {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		t, err := s.store.ClaimPending(ctx)
		if err != nil {
			return done, err
		}
		if t == nil {
			return done, nil
		}
		if err := s.ExportOne(ctx, t); err != nil {
			// 单个任务失败不回写状态失败的情况下，这里只记录；
			// 真正的失败原因已经写进任务记录。
			s.warn("导出任务执行失败", err, zap.String("task_id", t.ID))
			continue
		}
		done++
	}
	return done, nil
}

// ExportOne 执行单个导出任务。
//
// 无论成功失败都回写状态：这是"任务"能查得到的唯一依据，
// 卡在 running 的任务对使用者来说等同于"没反应"。
func (s *Service) ExportOne(ctx context.Context, t *audit.ExportTask) error {
	runCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	name := fmt.Sprintf("audit-%s.csv", t.ID)
	path := filepath.Join(s.cfg.Dir, name)

	// 预先判存：同名文件存在时直接失败，绝不继续往下走。
	// task_id 随机且唯一，同名只可能是逻辑异常或有人手工放了文件，
	// 此时覆盖等于毁掉别人已经导出的数据。
	if _, statErr := os.Stat(path); statErr == nil {
		err := errs.New(errs.CodeInternal, "导出文件已存在，拒绝覆盖").
			WithDetail("file", name)
		s.markFailed(ctx, t.ID, err)
		return err
	}

	size, rows, created, err := s.writeCSV(runCtx, path, t.Criteria.ToFilter())
	if err != nil {
		// 只删【本次创建】的半成品：O_EXCL 失败说明文件不是我们的，
		// 删掉它就是误伤。
		if created {
			_ = os.Remove(path)
		}
		s.markFailed(ctx, t.ID, err)
		return err
	}

	expires := s.now().UTC().Add(s.cfg.FileTTL)
	if err := s.store.MarkSucceeded(ctx, t.ID, rows, size, name, expires); err != nil {
		_ = os.Remove(path)
		return err
	}
	s.logger.Info("审计导出完成",
		zap.String("task_id", t.ID), zap.Int64("rows", rows), zap.Int64("bytes", size))
	return nil
}

// markFailed 回写失败状态，失败本身只记日志（任务记录已能表达结果）。
func (s *Service) markFailed(ctx context.Context, taskID string, cause error) {
	code := string(errs.CodeInternal)
	if ee, ok := errs.As(cause); ok {
		code = string(ee.Code)
	}
	if err := s.store.MarkFailed(ctx, taskID, code, cause.Error()); err != nil {
		s.warn("回写导出失败状态失败", err, zap.String("task_id", taskID))
	}
}

// csvHeader 是导出列。顺序按"排查时最常看的字段"排：时间与动作在前，
// detail 这种大字段放最后，方便直接用 less / cut 看前面几列。
var csvHeader = []string{
	"id", "created_at", "app_id", "action", "result", "error_code",
	"external_user_id", "platform", "scene", "client",
	"client_ip", "trace_id", "user_agent", "detail",
}

// writeCSV 流式写文件，返回文件大小与行数（不含表头）。
//
// created 表示文件是否由本次调用创建：调用方据此决定失败时要不要删除——
// O_EXCL 失败说明同名文件早已存在，删它会把别人的数据一起删掉。
func (s *Service) writeCSV(ctx context.Context, path string, f audit.Filter) (size int64, rows int64, created bool, err error) {
	// O_EXCL：同名文件已存在说明这不是"重跑"，而是逻辑出了问题
	// （task_id 随机且唯一）。宁可失败也不要静默覆盖别人的导出。
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return 0, 0, false, errs.Wrap(errs.CodeInternal, "创建导出文件失败", err)
	}
	created = true
	defer fh.Close()

	// UTF-8 BOM：不带它时 Excel 会把中文按本地编码解释，打开就是乱码。
	// 这是"导出给运营看"的场景里最常见的一个坑。
	if _, err := fh.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return 0, 0, created, errs.Wrap(errs.CodeInternal, "写导出文件失败", err)
	}

	w := csv.NewWriter(fh)
	if err := w.Write(csvHeader); err != nil {
		return 0, 0, created, errs.Wrap(errs.CodeInternal, "写导出表头失败", err)
	}

	err = s.query.Stream(ctx, f, s.cfg.Batch, func(batch []audit.Record) error {
		for i := range batch {
			r := &batch[i]
			detail := "{}"
			if len(r.Detail) > 0 {
				if raw, e := json.Marshal(r.Detail); e == nil {
					detail = string(raw)
				}
			}
			rec := []string{
				fmt.Sprintf("%d", r.ID),
				r.CreatedAt.UTC().Format(time.RFC3339),
				fmt.Sprintf("%d", r.AppID),
				r.Action,
				r.Result,
				r.ErrorCode,
				r.ExternalUserID,
				r.Platform,
				r.Scene,
				r.Client,
				r.ClientIP,
				r.TraceID,
				r.UserAgent,
				detail,
			}
			if err := w.Write(rec); err != nil {
				return errs.Wrap(errs.CodeInternal, "写导出数据失败", err)
			}
			rows++
		}
		return nil
	})
	if err != nil {
		return 0, 0, created, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return 0, 0, created, errs.Wrap(errs.CodeInternal, "刷新导出数据失败", err)
	}
	// 先刷盘再取大小：否则 stat 可能拿到还没落盘的长度。
	if err := fh.Sync(); err != nil {
		return 0, 0, created, errs.Wrap(errs.CodeInternal, "落盘导出文件失败", err)
	}
	st, err := fh.Stat()
	if err != nil {
		return 0, 0, created, errs.Wrap(errs.CodeInternal, "读取导出文件信息失败", err)
	}
	return st.Size(), rows, created, nil
}

// purgeOnce 清理到期任务与文件。
func (s *Service) purgeOnce(ctx context.Context) {
	tasks, err := s.store.PurgeExpired(ctx, s.now().UTC(), 200)
	if err != nil {
		s.warn("清理过期导出任务失败", err)
		return
	}
	for _, t := range tasks {
		if t.FilePath == "" {
			continue
		}
		// 只删本目录下的文件：FilePath 由 worker 写成纯文件名，
		// 这里再取 Base 是为了防止历史数据里出现路径穿越。
		if err := os.Remove(filepath.Join(s.cfg.Dir, filepath.Base(t.FilePath))); err != nil &&
			!os.IsNotExist(err) {
			s.warn("删除过期导出文件失败", err, zap.String("task_id", t.ID))
		}
	}
	if len(tasks) > 0 {
		s.logger.Info("清理过期导出任务完成", zap.Int("count", len(tasks)))
	}
}

func (s *Service) warn(msg string, err error, fields ...zap.Field) {
	if s.logger == nil {
		return
	}
	s.logger.Warn(msg, append(fields, zap.Error(err))...)
}

// probeWritable 探测目录是否真的可写。
//
// 用实际建文件而不是 unix.Access：后者在挂载点、ACL、只读卷上的判定
// 与真正的 open(O_CREAT) 并不总一致，而我们要的正是"能不能建文件"。
func probeWritable(dir string) error {
	p := filepath.Join(dir, ".write-probe")
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = fh.Close()
	return os.Remove(p)
}
