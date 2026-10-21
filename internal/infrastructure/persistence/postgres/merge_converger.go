package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// MergeConverger 在一个数据库事务内完成合并的本地收敛（§7.3 第 3 步）。
//
// 为什么单独实现而不是依次调用 BindingRepository / token 仓储 / EventRepository：
// 那三个仓储各自持有独立的 *gorm.DB，每次调用都在自己的连接上自动提交。
// 在它们之上包一层 db.Transaction 只是幻觉——事务是连接级的，不是 context 级的。
// 要做到真正同事务，只能是"同一个 *gorm.DB 实例（tx）操作四张表"。
//
// 四张表必须同生共死的原因：
//   - 改挂绑定与撤销令牌是"账号已合并"这个事实的两半，只做一半会让用户
//     持着 source 账号的令牌访问一个已经没有绑定的账号；
//   - outbox 事件必须与业务变更同事务（§5.4），否则业务方可能永远不知道
//     账号被合并——R4 红线 2 的"必须通知"就落空了。
type MergeConverger struct {
	db *gorm.DB
}

// NewMergeConverger 构造收敛器。
func NewMergeConverger(db *gorm.DB) *MergeConverger {
	return &MergeConverger{db: db}
}

var _ merge.Converger = (*MergeConverger)(nil)

// Converge 执行本地收敛。
func (c *MergeConverger) Converge(ctx context.Context, in merge.ConvergeInput) error {
	ctx = appctx.WithAppScope(ctx, in.AppID)

	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()

		// ① 把 source 的活跃绑定改挂到 target。
		//
		// 注意是"改挂"不是"删除"：§7.3 要求可回溯——合并后仍要能回答
		// "这条绑定原来是哪个账号的"。删除会把这个信息永久抹掉。
		// 历史信息保存在 merge_operations 与 bind_source='merge' 两个地方。
		res := tx.Model(&bindingModel{}).
			Where("app_id = ? AND external_user_id = ? AND status = ?",
				in.AppID, in.SourceUserID, "active").
			Updates(map[string]any{
				"external_user_id": in.TargetUserID,
				"bind_source":      "merge",
				"bound_at":         now,
			})
		if res.Error != nil {
			return errs.Wrap(errs.CodeInternal, "改挂绑定失败", res.Error)
		}

		// ② 撤销 source 的全部 refresh token。
		//
		// 不撤销的话，持有 source 会话的客户端会继续正常刷新——而它的账号
		// 已经没有绑定了，形成一个"能登录但什么都绑不上"的僵尸会话。
		if err := tx.Model(&refreshTokenModel{}).
			Where("app_id = ? AND external_user_id = ? AND revoked = ?",
				in.AppID, in.SourceUserID, false).
			Updates(map[string]any{
				"revoked":        true,
				"revoked_reason": "account_merged",
			}).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "撤销源账号令牌失败", err)
		}

		// ③ 合并操作置为 done。
		updates := map[string]any{
			"status":     merge.StatusDone,
			"updated_at": now,
		}
		if in.RemoteResult != nil {
			updates["remote_result"] = JSONMap(in.RemoteResult)
		}
		if err := tx.Model(&mergeOperationModel{}).
			Where("id = ?", in.OperationID).
			Updates(updates).Error; err != nil {
			return errs.Wrap(errs.CodeInternal, "回写合并状态失败", err)
		}

		// ④ 写 outbox 事件（同事务）。
		if in.Event != nil {
			ev := &eventOutboxModel{
				AppID:         in.AppID,
				EventID:       in.Event.EventID,
				EventType:     in.Event.Type,
				SchemaVersion: in.Event.SchemaVersion,
				Payload:       jsonNotNull(in.Event.Payload),
				Status:        "pending",
				Attempts:      0,
				CreatedAt:     now,
			}
			if err := tx.Create(ev).Error; err != nil {
				return errs.Wrap(errs.CodeInternal, "写入合并事件失败", err)
			}
		}

		// ⑤ 写业务审计（同事务）。
		if in.Audit != nil {
			a := &auditLogModel{
				AppID:          in.AppID,
				ExternalUserID: in.Audit.ExternalUserID,
				Platform:       in.Audit.Platform,
				Scene:          in.Audit.Scene,
				Client:         in.Audit.Client,
				Action:         in.Audit.Action,
				Result:         "success",
				TraceID:        in.Audit.TraceID,
				Detail:         jsonNotNull(in.Audit.Detail),
				CreatedAt:      now,
			}
			if err := tx.Create(a).Error; err != nil {
				return errs.Wrap(errs.CodeInternal, "写入合并审计失败", err)
			}
		}
		return nil
	})
}
