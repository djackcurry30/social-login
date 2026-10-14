// Package auditx 提供审计写入的安全包装。
//
// 审计是旁路：写不进去不能影响用户登录。但"不影响"不等于"不关心"——
// 写入失败必须留下错误日志与指标，否则合规审计出现空洞时无人察觉。
package auditx

import (
	"context"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/audit"
)

// Emit 写入审计事件；失败只记录日志，不返回错误。
//
// 之所以故意不返回 error：调用方（登录/绑定流程）在成功路径上不该因为
// 审计存储抖动而失败。如果需要感知审计可用性，看日志与指标，不要在业务链路上做分支。
func Emit(ctx context.Context, w audit.Writer, log *zap.Logger, e *audit.Event) {
	if w == nil || e == nil {
		return
	}
	if err := w.Write(ctx, e); err != nil {
		if log != nil {
			log.Error("写入审计日志失败（不影响主流程）",
				zap.String("action", e.Action),
				zap.String("result", e.Result),
				zap.Int64("app_id", e.AppID),
				zap.String("trace_id", e.TraceID),
				zap.Error(err))
		}
	}
}
