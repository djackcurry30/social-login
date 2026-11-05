package service

import (
	"context"

	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// auditFor 构造一条审计输入。
//
// 审计的"谁"在本服务这一侧只能是【调用方】，因为用户中心的每个写操作都
// 来自 social-login 而不是终端用户。所以：
//
//	actor     —— HTTP 中间件从 X-Actor 头取（缺省 "service"）
//	trace_id  —— 与 social-login 同一条链路的 trace id
//
// 真实的人在 social-login 的审计表里（auth_audit_logs 有 user 与 platform），
// 用 trace_id 关联。这是"两服务各管一半责任"的必然结果，也是不在本服务
// 复制一份用户身份的理由：那会让同一事实有两个可能不一致的来源。
func (s *Service) auditFor(ctx context.Context, app domain.App, action, userID string,
	detail map[string]any,
) *postgres.AuditInput {
	meta := reqmeta.From(ctx)
	actor := meta.Actor
	if actor == "" {
		actor = "service"
	}
	return &postgres.AuditInput{
		AppID:     app.ID,
		UserID:    userID,
		Action:    action,
		Actor:     actor,
		TraceID:   meta.TraceID,
		ClientIP:  meta.ClientIP,
		UserAgent: meta.UserAgent,
		Detail:    detail,
	}
}

// claimTypesOf 提取凭证类型列表（去重、保序）。
//
// 审计只记"建号时带了哪些类型"，不记值：审计表的保留期比业务数据更长、
// 可查的人更多，把手机号抄进去等于换一个系统继续泄漏。
func claimTypesOf(claims []domain.Claim) []string {
	seen := make(map[string]struct{}, len(claims))
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		if _, ok := seen[c.Type]; ok {
			continue
		}
		seen[c.Type] = struct{}{}
		out = append(out, c.Type)
	}
	return out
}
