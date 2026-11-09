package service

import (
	"context"
	"time"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// claimInvalidated 构造一条"凭证已失效"的出站事件。
//
// 为什么要通知登录侧：它维护的 identity_claims 记录的是"某次授权中，
// 某平台证明过这个身份拥有该手机号"。用户中心这边换号/注销后，那条记录
// 就过期了；登录侧会拿它做归并判定，从而把两个不该合并的账号并起来。
//
// payload 里【没有】新旧号码：
//
//	接收方只需要知道"这个用户的 phone 变了"，然后按 user_id 反查自己的绑定、
//	撤销本地 claim。把新号码带过去等于让一条内网消息多一份明文，而它并不需要。
//	claim_type 为空表示"全部类型"（注销 / 合并），这样接收方一次清干净。
func (s *Service) claimInvalidated(_ context.Context, app domain.App, userID, claimType, reason string) *postgres.OutboxInput {
	return &postgres.OutboxInput{
		AppID:     app.ID,
		EventType: postgres.OutboxClaimInvalidated,
		Payload: map[string]any{
			"app_key":     app.Key,
			"user_id":     userID,
			"claim_type":  claimType,
			"reason":      reason,
			"occurred_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
}
