// Package acceptance 中的 binding_admin_test.go：C 组干预操作的真实依赖验收。
//
// 关注点不是 HTTP 层（薄壳已有单测），而是两件只能在真库上验证的事：
//  1. 强制解绑 / transfer 与 outbox 事件在【同一事务】；
//  2. 改挂后仍满足 uk_bindings_active（一个身份同期只有一条生效绑定）。
package acceptance

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
)

// seedActiveBinding 造一条"identity 已绑在某账号上"的现场。
func (h *harness) seedActiveBinding(t *testing.T, userID string) (*identity.Identity, *binding.Binding) {
	t.Helper()
	ctx := context.Background()

	identityRepo := postgres.NewIdentityRepository(h.app.DB())
	bindingRepo := postgres.NewBindingRepository(h.app.DB())

	idn, err := identityRepo.Upsert(ctx, identity.UpsertInput{
		AppID:         h.appID,
		Platform:      provider.PlatformGenericOAuth2,
		ProviderAppID: testProviderClientID,
		OpenID:        "bind-admin-openid-" + newAppCode("z"),
		Profile:       map[string]any{},
	})
	if err != nil {
		t.Fatalf("写入 identity 失败: %v", err)
	}
	b, already, err := bindingRepo.Activate(ctx, binding.ActivateInput{
		AppID:          h.appID,
		ExternalUserID: userID,
		IdentityID:     idn.ID,
		BindSource:     binding.SourceExplicit,
		At:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("写入绑定失败: %v", err)
	}
	if already {
		t.Fatal("这是新 identity，不应命中已存在")
	}
	return idn, b
}

// countEvents 统计某应用下指定类型的事件条数。
func (h *harness) countEvents(t *testing.T, eventType string) int64 {
	t.Helper()
	ctx := appctx.WithAppScope(context.Background(), h.appID)
	var n int64
	if err := h.app.DB().WithContext(ctx).Table("event_outbox").
		Where("app_id = ? AND event_type = ?", h.appID, eventType).
		Count(&n).Error; err != nil {
		t.Fatalf("统计事件失败: %v", err)
	}
	return n
}

// lastEventPayload 取最近一条指定类型事件的 payload。
func (h *harness) lastEventPayload(t *testing.T, eventType string) string {
	t.Helper()
	ctx := appctx.WithAppScope(context.Background(), h.appID)
	var payload string
	if err := h.app.DB().WithContext(ctx).Table("event_outbox").
		Select("payload").
		Where("app_id = ? AND event_type = ?", h.appID, eventType).
		Order("id DESC").Limit(1).Scan(&payload).Error; err != nil {
		t.Fatalf("查询事件失败: %v", err)
	}
	return payload
}

func TestForceUnbindWritesEventInSameTransaction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, b := h.seedActiveBinding(t, "user-unbind-target")

	before := h.countEvents(t, "binding.removed")

	repo := postgres.NewBindingAdminRepository(h.app.DB())
	out, err := repo.ForceUnbind(ctx, binding.AdminUnbindInput{
		BindingID: b.ID,
		Reason:    "验收：客服申诉强制解绑",
		Event: &binding.AdminEvent{
			EventID: gotEventID(t), Type: "binding.removed", SchemaVersion: 1,
			Payload: map[string]any{"binding_id": b.ID, "reason": "admin_force_unbind"},
		},
	})
	if err != nil {
		t.Fatalf("强制解绑失败: %v", err)
	}
	if out.Status != binding.StatusUnbound || out.UnboundAt == nil {
		t.Fatalf("绑定应置为 unbound 并记录时间: %+v", out)
	}

	// 事件条数必须 +1：没有事件，业务方的 user 表就永远留着这条绑定。
	if after := h.countEvents(t, "binding.removed"); after != before+1 {
		t.Fatalf("应新增 1 条 binding.removed 事件，before=%d after=%d", before, after)
	}

	// 幂等：再解一次不应产生新事件。
	if _, err := repo.ForceUnbind(ctx, binding.AdminUnbindInput{
		BindingID: b.ID, Reason: "重复点击",
		Event: &binding.AdminEvent{
			EventID: gotEventID(t), Type: "binding.removed", SchemaVersion: 1,
			Payload: map[string]any{},
		},
	}); err != nil {
		t.Fatalf("重复解绑应幂等成功: %v", err)
	}
	if after := h.countEvents(t, "binding.removed"); after != before+1 {
		t.Fatalf("已解绑的绑定不应再产生事件，after=%d", after)
	}
}

func TestTransferMovesIdentityWithoutDroppingOldAccount(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	idn, b := h.seedActiveBinding(t, "user-from")

	repo := postgres.NewBindingAdminRepository(h.app.DB())
	out, err := repo.Transfer(ctx, binding.AdminTransferInput{
		BindingID:  b.ID,
		TargetUser: "user-to",
		Reason:     "验收：客服核实渠道归属",
		Event: &binding.AdminEvent{
			EventID: gotEventID(t), Type: "binding.removed", SchemaVersion: 1,
			Payload: map[string]any{"binding_id": b.ID, "reason": "admin_transfer"},
		},
	})
	if err != nil {
		t.Fatalf("transfer 失败: %v", err)
	}
	if out.ExternalUserID != "user-to" {
		t.Fatalf("应挂到新账号，实际 %s", out.ExternalUserID)
	}
	if out.BindSource != binding.SourceAdmin {
		t.Fatalf("来源应为 admin，实际 %s", out.BindSource)
	}

	// 事件体必须能回答"从谁到谁"。
	raw := h.lastEventPayload(t, "binding.removed")
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("事件体不是合法 JSON: %v", err)
	}
	if payload["from_user_id"] != "user-from" || payload["to_user_id"] != "user-to" {
		t.Fatalf("事件体缺少 from/to: %v", payload)
	}

	// 旧账号仍然存在（只是少了这一个登录方式），新账号持有该 identity。
	bindings, _, err := postgres.NewBindingAdminRepository(h.app.DB()).ListAdmin(ctx, binding.AdminFilter{
		AppID: h.appID, ExternalUserID: "user-to", Status: binding.StatusActive,
	})
	if err != nil {
		t.Fatalf("查询新账号绑定失败: %v", err)
	}
	if len(bindings) != 1 || bindings[0].IdentityID != idn.ID {
		t.Fatalf("新账号应持有该 identity: %+v", bindings)
	}

	// 一个身份同期只能有一条生效绑定（uk_bindings_active）。
	all, _, err := postgres.NewBindingAdminRepository(h.app.DB()).ListAdmin(ctx, binding.AdminFilter{
		AppID: h.appID, IdentityID: idn.ID, Status: binding.StatusActive,
	})
	if err != nil {
		t.Fatalf("查询身份绑定失败: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("同一 identity 应只有 1 条生效绑定，实际 %d", len(all))
	}
}

// gotEventID 生成唯一事件 ID（测试内用）。
func gotEventID(t *testing.T) string {
	t.Helper()
	return "evt_" + newAppCode("t")
}
