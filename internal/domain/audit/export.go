package audit

import (
	"context"
	"errors"
	"time"
)

// 导出任务状态。
//
// 只有四个状态，不再加 cancelling 之类的中间态：导出是只读操作，
// 用户最关心的是"好了没 / 为什么没成"，多一个状态就要多一条前端分支。
const (
	ExportPending   = "pending"
	ExportRunning   = "running"
	ExportSucceeded = "succeeded"
	ExportFailed    = "failed"
)

// ErrExportNotFound 表示导出任务不存在。
var ErrExportNotFound = errors.New("audit: export task not found")

// ExportCriteria 是导出条件的【快照】。
//
// 独立于 Filter：Filter 带 Page/PageSize，而导出是全量的——把分页字段
// 也存进 JSONB 会让人误以为导出只导一页。这里显式只留过滤维度。
type ExportCriteria struct {
	AppID          int64      `json:"app_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Result         string     `json:"result,omitempty"`
	ExternalUserID string     `json:"external_user_id,omitempty"`
	TraceID        string     `json:"trace_id,omitempty"`
	Platform       string     `json:"platform,omitempty"`
	Client         string     `json:"client,omitempty"`
	From           *time.Time `json:"from,omitempty"`
	To             *time.Time `json:"to,omitempty"`
}

// ToFilter 把导出条件还原成查询条件（导出不分页，Page/PageSize 留零值）。
func (c ExportCriteria) ToFilter() Filter {
	return Filter{
		AppID:          c.AppID,
		Action:         c.Action,
		Result:         c.Result,
		ExternalUserID: c.ExternalUserID,
		TraceID:        c.TraceID,
		Platform:       c.Platform,
		Client:         c.Client,
		From:           c.From,
		To:             c.To,
	}
}

// ExportTask 是一次异步导出任务。
type ExportTask struct {
	ID           string
	SubjectID    string
	Criteria     ExportCriteria
	Status       string
	RowCount     int64
	FilePath     string
	FileSize     int64
	ErrorCode    string
	ErrorMessage string
	CreatedAt    time.Time
	StartedAt    *time.Time
	FinishedAt   *time.Time
	ExpiresAt    *time.Time
}

// Done 判断任务是否已结束（成功或失败）。
func (t *ExportTask) Done() bool {
	return t != nil && (t.Status == ExportSucceeded || t.Status == ExportFailed)
}

// ExportStore 是导出任务的持久化端口。
type ExportStore interface {
	Create(ctx context.Context, t *ExportTask) error
	Get(ctx context.Context, id string) (*ExportTask, error)
	// ListBySubject 返回某管理员最近的导出任务。
	ListBySubject(ctx context.Context, subjectID string, limit int) ([]*ExportTask, error)
	// ClaimPending 领取一条待执行的导出任务并置为 running。
	//
	// 返回 (nil, nil) 表示当前没有待办。用 UPDATE ... WHERE status='pending'
	// 的原子领取（见实现），多副本 worker 同时跑也不会重复导出。
	ClaimPending(ctx context.Context) (*ExportTask, error)
	MarkSucceeded(ctx context.Context, id string, rows, size int64, path string, expiresAt time.Time) error
	MarkFailed(ctx context.Context, id string, code, message string) error
	// PurgeExpired 删除到期任务的元数据并返回被删任务的 id（调用方负责删文件）。
	PurgeExpired(ctx context.Context, now time.Time, limit int) ([]*ExportTask, error)
}

// StaleRequeuer 是可选能力：把进程崩溃时遗留的 running 任务退回 pending。
//
// 做成可选接口而不是塞进 ExportStore：这是"启动时的一次性修复"，
// 不是任务状态机的组成部分。测试用的内存实现不实现它也能跑。
type StaleRequeuer interface {
	RequeueStale(ctx context.Context) (int64, error)
}
