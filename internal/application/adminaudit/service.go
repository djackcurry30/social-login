// Package adminaudit 是管理端"审计日志（H 组）"用例。
//
// 交付范围（架构 §15.4 H 组）：
//   - 业务审计查询（auth_audit_logs）
//   - 管理端审计查询（admin_audit_logs）
//   - 审计异步导出：提交任务 + 查状态 + 下载
//
// 为什么查询与导出拆成"提交 / 执行"两半：见 migrations/00004 与 §5.5 ①——
// 导出可能涉及几十万行，同步等待会占死连接。本包只负责"提交与查询"，
// 真正的落盘在 application/auditexport 的后台循环里。
package adminaudit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Deps 是用例依赖。
type Deps struct {
	Query      audit.Query
	Exports    audit.ExportStore
	AdminAudit admin.AuditWriter
	// Logger 目前只在 worker 侧使用；用例内不记录失败分支（审计写入失败由 auditx 兜底）。
	Now        func() time.Time
	// ExportTTL 是导出文件保留期，默认 7 天。
	ExportTTL time.Duration
	// ExportDir 是导出文件落盘目录（与 auditexport worker 共用同一配置）。
	//
	// 下载时由本包拼出绝对路径而不是信任任务里的 file_path：任务行里的
	// 路径只是"文件名"，即便历史数据被写入异常值，也不会被拼出目录之外的路径。
	ExportDir string
}

// Service 是 H 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.ExportTTL <= 0 {
		d.ExportTTL = 7 * 24 * time.Hour
	}
	return &Service{deps: d}
}

// --- 业务审计查询 ---

// ListInput 是 GET /admin/v1/audit-logs 的入参。
type ListInput struct {
	AppID          int64
	Action         string
	Result         string
	ExternalUserID string
	TraceID        string
	Platform       string
	Client         string
	From           string
	To             string
	Page           int
	PageSize       int
}

// Item 是一条业务审计的对外视图。
type Item struct {
	ID             int64          `json:"id"`
	AppID          int64          `json:"app_id"`
	ExternalUserID string         `json:"external_user_id,omitempty"`
	Platform       string         `json:"platform,omitempty"`
	Scene          string         `json:"scene,omitempty"`
	Client         string         `json:"client,omitempty"`
	Action         string         `json:"action"`
	Result         string         `json:"result"`
	ErrorCode      string         `json:"error_code,omitempty"`
	ClientIP       string         `json:"client_ip,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	TraceID        string         `json:"trace_id,omitempty"`
	Detail         map[string]any `json:"detail,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// ListOutput 是列表出参。
type ListOutput struct {
	Items    []Item `json:"items"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// List 查询业务审计。
func (s *Service) List(ctx context.Context, in ListInput) (*ListOutput, error) {
	f, err := parseFilter(in.AppID, in.Action, in.Result, in.ExternalUserID,
		in.TraceID, in.Platform, in.Client, in.From, in.To, in.Page, in.PageSize)
	if err != nil {
		return nil, err
	}
	rows, total, err := s.deps.Query.List(ctx, f)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(rows))
	for i := range rows {
		items = append(items, toItem(&rows[i]))
	}
	return &ListOutput{Items: items, Total: total, Page: maxInt(f.Page, 1), PageSize: f.PageSize}, nil
}

// --- 管理端审计查询 ---

// AdminListInput 是 GET /admin/v1/audit-logs/admin 的入参。
type AdminListInput struct {
	SubjectID  string
	Action     string
	TargetType string
	TargetID   string
	AppID      int64
	Result     string
	From       string
	To         string
	Page       int
	PageSize   int
}

// AdminItem 是一条管理端审计的对外视图。
type AdminItem struct {
	ID          int64          `json:"id"`
	SubjectID   string         `json:"subject_id"`
	Action      string         `json:"action"`
	TargetType  string         `json:"target_type"`
	TargetID    string         `json:"target_id"`
	AppID       *int64         `json:"app_id,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	BeforeState map[string]any `json:"before_state,omitempty"`
	AfterState  map[string]any `json:"after_state,omitempty"`
	ClientIP    string         `json:"client_ip,omitempty"`
	TraceID     string         `json:"trace_id,omitempty"`
	Result      string         `json:"result"`
	ErrorCode   string         `json:"error_code,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// AdminListOutput 是管理端审计列表出参。
type AdminListOutput struct {
	Items    []AdminItem `json:"items"`
	Total    int64       `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

// ListAdmin 查询管理端审计。
func (s *Service) ListAdmin(ctx context.Context, in AdminListInput) (*AdminListOutput, error) {
	f := audit.AdminFilter{
		SubjectID:  in.SubjectID,
		Action:     in.Action,
		TargetType: in.TargetType,
		TargetID:   in.TargetID,
		AppID:      in.AppID,
		Result:     in.Result,
		Page:       in.Page,
		PageSize:   in.PageSize,
	}
	if in.From != "" {
		t, err := parseTime(in.From)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "from 时间格式非法，应为 RFC3339")
		}
		f.From = &t
	}
	if in.To != "" {
		t, err := parseTime(in.To)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "to 时间格式非法，应为 RFC3339")
		}
		f.To = &t
	}
	rows, total, err := s.deps.Query.ListAdmin(ctx, f)
	if err != nil {
		return nil, err
	}
	items := make([]AdminItem, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		items = append(items, AdminItem{
			ID:          r.ID,
			SubjectID:   r.SubjectID,
			Action:      r.Action,
			TargetType:  r.TargetType,
			TargetID:    r.TargetID,
			AppID:       r.AppID,
			Reason:      r.Reason,
			BeforeState: r.BeforeState,
			AfterState:  r.AfterState,
			ClientIP:    r.ClientIP,
			TraceID:     r.TraceID,
			Result:      r.Result,
			ErrorCode:   r.ErrorCode,
			CreatedAt:   r.CreatedAt,
		})
	}
	return &AdminListOutput{
		Items:    items,
		Total:    total,
		Page:     maxInt(f.Page, 1),
		PageSize: f.PageSize,
	}, nil
}

// --- 异步导出 ---

// ExportInput 是 POST /admin/v1/audit-logs/export 的入参。
type ExportInput struct {
	AppID          int64  `json:"app_id,omitempty"`
	Action         string `json:"action,omitempty"`
	Result         string `json:"result,omitempty"`
	ExternalUserID string `json:"external_user_id,omitempty"`
	TraceID        string `json:"trace_id,omitempty"`
	Platform       string `json:"platform,omitempty"`
	Client         string `json:"client,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Principal      *admin.Principal `json:"-"`
}

// ExportView 是导出任务视图。
type ExportView struct {
	TaskID       string         `json:"task_id"`
	Status       string         `json:"status"`
	RowCount     int64          `json:"row_count"`
	FileSize     int64          `json:"file_size"`
	ErrorCode    string         `json:"error_code,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	Criteria     map[string]any `json:"criteria"`
	CreatedAt    time.Time      `json:"created_at"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	FinishedAt   *time.Time     `json:"finished_at,omitempty"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	// DownloadPath 只在任务成功时给出。用受鉴权的接口路径而不是直链：
	// 审计数据是敏感数据，直链一旦泄露就等于永久公开（对象存储预签名 URL
	// 也只在有对象存储时才成立，本地文件存储给不了直链）。
	DownloadPath string `json:"download_path,omitempty"`
}

// SubmitExport 提交导出任务。
//
// 这里不做"是否已有同条件在跑"的去重：导出是只读操作，重复提交的代价
// 只是多一个文件；而去重需要引入"条件指纹"，反而容易因为指标准不准
// 导致用户明明点了导出却什么都没发生。
func (s *Service) SubmitExport(ctx context.Context, in ExportInput) (*ExportView, error) {
	crit := audit.ExportCriteria{
		AppID:          in.AppID,
		Action:         in.Action,
		Result:         in.Result,
		ExternalUserID: in.ExternalUserID,
		TraceID:        in.TraceID,
		Platform:       in.Platform,
		Client:         in.Client,
	}
	if in.From != "" {
		t, err := parseTime(in.From)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "from 时间格式非法，应为 RFC3339")
		}
		crit.From = &t
	}
	if in.To != "" {
		t, err := parseTime(in.To)
		if err != nil {
			return nil, errs.New(errs.CodeInvalidRequest, "to 时间格式非法，应为 RFC3339")
		}
		crit.To = &t
	}
	// 导出是读操作但会落盘、会消耗数据库资源，属于"需要留痕"的动作；
	// 与高危写操作的差别是 reason 非必填。
	if in.Result != "" && in.Result != audit.ResultSuccess && in.Result != audit.ResultFailure {
		return nil, errs.Newf(errs.CodeInvalidRequest, "result 不合法: %s", in.Result)
	}

	id, err := newTaskID()
	if err != nil {
		return nil, err
	}
	now := s.deps.Now()
	task := &audit.ExportTask{
		ID:        id,
		SubjectID: subjectOf(in.Principal),
		Criteria:  crit,
		Status:    audit.ExportPending,
		CreatedAt: now,
	}
	if err := s.deps.Exports.Create(ctx, task); err != nil {
		return nil, err
	}

	s.writeAudit(ctx, in.Principal, "audit.export", task.ID, in.Reason,
		map[string]any{
			"app_id":           crit.AppID,
			"action":           crit.Action,
			"result":           crit.Result,
			"external_user_id": crit.ExternalUserID,
			"from":             crit.From,
			"to":               crit.To,
		})

	v := toExportView(task)
	return v, nil
}

// GetExport 查询导出任务状态。
//
// 归属校验：只能看自己提交的任务。super_admin 可以看全部——运维排障时
// 需要确认"这个导出到底跑完没有"，而导出内容本身仍然是按权限控制的。
func (s *Service) GetExport(ctx context.Context, taskID string, p *admin.Principal) (*ExportView, error) {
	if taskID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "task_id 不能为空")
	}
	t, err := s.deps.Exports.Get(ctx, taskID)
	if err != nil {
		return nil, exportErr(err, taskID)
	}
	if !canAccess(t, p) {
		// 不区分"不存在"与"无权访问"：可枚举性已经用随机 ID 消掉了，
		// 这里再区分只会给出额外的探测信号。
		return nil, exportErr(audit.ErrExportNotFound, taskID)
	}
	return toExportView(t), nil
}

// ListExports 列出当前管理员的导出任务（GET /admin/v1/audit-logs/exports）。
//
// §15.4 只写了 4 个 H 组端点，但没有"我的导出任务"列表，前端刷新页面后
// 就找不到刚提交的任务了（task_id 只在响应里出现过一次）。这个补充端点
// 不改变权限模型，属于必要的最小补齐。
func (s *Service) ListExports(ctx context.Context, p *admin.Principal, limit int) ([]ExportView, error) {
	rows, err := s.deps.Exports.ListBySubject(ctx, subjectOf(p), limit)
	if err != nil {
		return nil, err
	}
	out := make([]ExportView, 0, len(rows))
	for _, t := range rows {
		out = append(out, *toExportView(t))
	}
	return out, nil
}

// DownloadTarget 是下载所需的文件位置。
type DownloadTarget struct {
	Path     string
	FileName string
	FileSize int64
}

// PrepareDownload 校验任务并返回可下载的文件位置。
func (s *Service) PrepareDownload(ctx context.Context, taskID string, p *admin.Principal) (*DownloadTarget, error) {
	v, err := s.GetExport(ctx, taskID, p)
	if err != nil {
		return nil, err
	}
	switch v.Status {
	case audit.ExportSucceeded:
	case audit.ExportFailed:
		return nil, errs.New(errs.CodeInvalidRequest, "导出任务失败，无可下载文件").
			WithDetail("error_code", v.ErrorCode)
	default:
		return nil, errs.Newf(errs.CodeAdminConflict, "导出任务尚未完成（当前 %s）", v.Status)
	}
	if v.ExpiresAt != nil && v.ExpiresAt.Before(s.deps.Now()) {
		return nil, errs.New(errs.CodeNotFound, "导出文件已过期，请重新导出")
	}
	t, err := s.deps.Exports.Get(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if t.FilePath == "" {
		return nil, errs.New(errs.CodeNotFound, "导出文件不存在")
	}
	if s.deps.ExportDir == "" {
		return nil, errs.New(errs.CodeInternal, "服务未配置导出目录，无法下载")
	}
	return &DownloadTarget{
		Path:     filepath.Join(s.deps.ExportDir, filepath.Base(t.FilePath)),
		FileName: fmt.Sprintf("audit-%s.csv", t.ID),
		FileSize: t.FileSize,
	}, nil
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action, targetID, reason string, detail map[string]any) {
	if s.deps.AdminAudit == nil {
		return
	}
	e := &admin.AuditEvent{
		Action:     action,
		TargetType: "audit_export",
		TargetID:   targetID,
		Reason:     reason,
		AfterState: detail,
		Result:     "success",
	}
	e.SubjectID = subjectOf(p)
	_ = s.deps.AdminAudit.Write(ctx, e)
}

// --- helpers ---

func subjectOf(p *admin.Principal) string {
	if p != nil && p.User != nil {
		return fmt.Sprintf("admin:%d", p.User.ID)
	}
	return "admin:anonymous"
}

func canAccess(t *audit.ExportTask, p *admin.Principal) bool {
	if p == nil || p.User == nil {
		return false
	}
	if p.User.Role == admin.RoleSuperAdmin {
		return true
	}
	return t.SubjectID == subjectOf(p)
}

func parseFilter(appID int64, action, result, externalUserID, traceID, platform, client, from, to string,
	page, size int,
) (audit.Filter, error) {
	f := audit.Filter{
		AppID:          appID,
		Action:         action,
		Result:         result,
		ExternalUserID: externalUserID,
		TraceID:        traceID,
		Platform:       platform,
		Client:         client,
		Page:           page,
		PageSize:       size,
	}
	if result != "" && result != audit.ResultSuccess && result != audit.ResultFailure {
		return f, errs.Newf(errs.CodeInvalidRequest, "result 不合法: %s", result)
	}
	if from != "" {
		t, err := parseTime(from)
		if err != nil {
			return f, errs.New(errs.CodeInvalidRequest, "from 时间格式非法，应为 RFC3339")
		}
		f.From = &t
	}
	if to != "" {
		t, err := parseTime(to)
		if err != nil {
			return f, errs.New(errs.CodeInvalidRequest, "to 时间格式非法，应为 RFC3339")
		}
		f.To = &t
	}
	if f.From != nil && f.To != nil && f.To.Before(*f.From) {
		return f, errs.New(errs.CodeInvalidRequest, "to 不能早于 from")
	}
	return f, nil
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func toItem(r *audit.Record) Item {
	return Item{
		ID:             r.ID,
		AppID:          r.AppID,
		ExternalUserID: r.ExternalUserID,
		Platform:       r.Platform,
		Scene:          r.Scene,
		Client:         r.Client,
		Action:         r.Action,
		Result:         r.Result,
		ErrorCode:      r.ErrorCode,
		ClientIP:       r.ClientIP,
		UserAgent:      r.UserAgent,
		TraceID:        r.TraceID,
		Detail:         r.Detail,
		CreatedAt:      r.CreatedAt,
	}
}

func toExportView(t *audit.ExportTask) *ExportView {
	v := &ExportView{
		TaskID:       t.ID,
		Status:       t.Status,
		RowCount:     t.RowCount,
		FileSize:     t.FileSize,
		ErrorCode:    t.ErrorCode,
		ErrorMessage: t.ErrorMessage,
		Criteria: map[string]any{
			"app_id":           t.Criteria.AppID,
			"action":           t.Criteria.Action,
			"result":           t.Criteria.Result,
			"external_user_id": t.Criteria.ExternalUserID,
			"trace_id":         t.Criteria.TraceID,
			"platform":         t.Criteria.Platform,
			"client":           t.Criteria.Client,
			"from":             t.Criteria.From,
			"to":               t.Criteria.To,
		},
		CreatedAt:  t.CreatedAt,
		StartedAt:  t.StartedAt,
		FinishedAt: t.FinishedAt,
		ExpiresAt:  t.ExpiresAt,
	}
	if t.Status == audit.ExportSucceeded {
		v.DownloadPath = fmt.Sprintf("/admin/v1/audit-logs/export/%s/download", t.ID)
	}
	return v
}

// newTaskID 生成不可枚举的任务 ID。
func newTaskID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errs.Wrap(errs.CodeInternal, "生成导出任务 ID 失败", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// exportErr 把仓储层的领域错误归一化成对外错误。
//
// 不直接把 audit.ErrExportNotFound 上抛：httputil.Fail 只认 errs.Error，
// 裸 error 会被折算成 500——"任务不存在"明明是 404。
func exportErr(err error, taskID string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, audit.ErrExportNotFound) {
		return errs.New(errs.CodeNotFound, "导出任务不存在").
			WithDetail("task_id", taskID)
	}
	return err
}
