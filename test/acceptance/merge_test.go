// Package acceptance 中的 merge_test.go：账号合并链路的真实依赖验收。
//
// 对应架构 §13 第三期的核心验收项（R1 + P0-3 专项）：
//
//	R1   同一业务应用内，两个账号因同一 identity 冲突而合并，最终只剩一个账号
//	P0-3 远端成功、本地收敛时，绑定改挂 / 令牌撤销 / 事件 / 审计必须同生共死
//
// 为什么必须连真库：本用例要验证的正是"事务边界"——部分唯一索引
// uk_bindings_active、UPDATE 的影响范围、outbox 与审计是否在同一事务里。
// 这些全都不可能用内存桩验证。
package acceptance

import (
	"context"
	"strings"
	"testing"
	"time"

	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	mergex "github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/domain/tenant"
	infraaccount "github.com/djackcurry30/social-login/internal/infrastructure/account"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
)

// stubProvider 取出 harness 里的内存账号实现，用于造 source/target 两个账号。
func (h *harness) stubProvider() *infraaccount.StubProvider {
	h.t.Helper()
	sp, ok := h.app.Accounts().(*infraaccount.StubProvider)
	if !ok {
		h.t.Fatalf("验收需要 stub 账号实现，实际 %T", h.app.Accounts())
	}
	return sp
}

func TestAccountMergeConvergesLocally(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// 1) 用户中心侧两个账号。
	stub := h.stubProvider()
	accB, err := stub.Create(ctx, domainaccount.CreateRequest{
		IdempotencyKey: "merge-acc-b", Nickname: "账号B",
	})
	if err != nil {
		t.Fatalf("创建 source 账号失败: %v", err)
	}
	accC, err := stub.Create(ctx, domainaccount.CreateRequest{
		IdempotencyKey: "merge-acc-c", Nickname: "账号C",
	})
	if err != nil {
		t.Fatalf("创建 target 账号失败: %v", err)
	}

	// 2) 本地：一个 identity 已绑在 B 上，并有一个未撤销的 refresh token。
	identityRepo := postgres.NewIdentityRepository(h.app.DB())
	bindingRepo := postgres.NewBindingRepository(h.app.DB())
	sessionRepo := postgres.NewSessionRepository(h.app.DB())

	idn, err := identityRepo.Upsert(ctx, identity.UpsertInput{
		AppID:         h.appID,
		Platform:      provider.PlatformGenericOAuth2,
		ProviderAppID: testProviderClientID,
		OpenID:        "merge-openid-" + newAppCode("x"),
		Profile:       map[string]any{"name": "验收用户"},
	})
	if err != nil {
		t.Fatalf("写入 identity 失败: %v", err)
	}
	if _, _, err := bindingRepo.Activate(ctx, binding.ActivateInput{
		AppID:          h.appID,
		ExternalUserID: accB.UserID,
		IdentityID:     idn.ID,
		BindSource:     binding.SourceExplicit,
		At:             time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入绑定失败: %v", err)
	}
	if _, err := sessionRepo.Create(ctx, session.CreateInput{
		AppID:          h.appID,
		ExternalUserID: accB.UserID,
		TokenHash:      "merge-token-" + newAppCode("h"),
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
		At:             time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入刷新令牌失败: %v", err)
	}

	// 3) 合并：auto 模式、bind 触发（用户已登录 C，主动绑定该 identity）。
	//    这里直接调用用例而不是走 HTTP：HTTP 层三条分支已有单测覆盖，
	//    本用例要验的是"三次事务 + 本地收敛"的真实效果。
	svc := appmerge.New(appmerge.Deps{
		Ops:              postgres.NewMergeRepository(h.app.DB()),
		Converger:        postgres.NewMergeConverger(h.app.DB()),
		Accounts:         stub,
		Locker:           nil, // 单实例验收，锁的语义由 Redis 单测覆盖
		RemoteIdempotent: true,
		Logger:           nil,
	})

	policy := tenant.DefaultPolicy()
	policy.Merge.Mode = tenant.MergeModeAuto
	app := &tenant.Application{ID: h.appID, AppCode: h.appCode, Policy: policy}

	res, err := svc.Execute(ctx, appmerge.Request{
		App:          app,
		TargetUserID: accC.UserID,
		SourceUserID: accB.UserID,
		Identity:     idn,
		Trigger:      appmerge.TriggerBind,
		Reason:       "验收：绑定冲突触发自动合并",
	})
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if res == nil || res.OperationID == 0 {
		t.Fatal("合并应返回操作 ID")
	}

	// 4) 断言本地收敛：绑定已改挂到 target。
	cur, err := bindingRepo.FindActiveByIdentity(ctx, h.appID, idn.ID)
	if err != nil {
		t.Fatalf("查询绑定失败: %v", err)
	}
	if cur.ExternalUserID != accC.UserID {
		t.Fatalf("绑定应改挂到 target(%s)，实际 %s", accC.UserID, cur.ExternalUserID)
	}
	if cur.BindSource != binding.SourceMerge {
		t.Fatalf("改挂后 bind_source 应为 merge，实际 %s", cur.BindSource)
	}

	// 5) 断言令牌已撤销：否则 source 会话会变成"能登录但绑不上"的僵尸。
	// 裸查询也要给作用域：scope 回调对 refresh_tokens 强制要求 app_id 条件，
	// 这是约束 C1 的机制，不是可选项。
	scoped := appctx.WithAppScope(ctx, h.appID)
	var revoked int64
	if err := h.app.DB().WithContext(scoped).Table("refresh_tokens").
		Where("app_id = ? AND external_user_id = ? AND revoked = ?", h.appID, accB.UserID, false).
		Count(&revoked).Error; err != nil {
		t.Fatalf("统计令牌失败: %v", err)
	}
	if revoked != 0 {
		t.Fatalf("source 账号的令牌应全部撤销，仍有 %d 条未撤销", revoked)
	}

	// 6) 断言 outbox 事件：R4 红线 2 的通知依赖它。
	var payload string
	if err := h.app.DB().WithContext(scoped).Table("event_outbox").
		Select("payload").
		Where("app_id = ? AND event_type = ?", h.appID, "account.merged").
		Order("id DESC").Limit(1).Scan(&payload).Error; err != nil {
		t.Fatalf("查询事件失败: %v", err)
	}
	if payload == "" {
		t.Fatal("合并必须写入 account.merged 事件")
	}
	if !strings.Contains(payload, accC.UserID) || !strings.Contains(payload, accB.UserID) {
		t.Fatalf("事件体缺少双方账号: %s", payload)
	}

	// 7) 断言合并操作已置为 done。
	op, err := postgres.NewMergeRepository(h.app.DB()).Get(ctx, res.OperationID)
	if err != nil {
		t.Fatalf("查询合并操作失败: %v", err)
	}
	if op.Status != mergex.StatusDone {
		t.Fatalf("合并操作应为 done，实际 %s（last_error=%s）", op.Status, op.LastError)
	}

	// 8) 幂等：同一请求重复执行应命中"已合并"，且不再调远端。
	if _, err := svc.Execute(ctx, appmerge.Request{
		App:          app,
		TargetUserID: accC.UserID,
		SourceUserID: accB.UserID,
		Identity:     idn,
		Trigger:      appmerge.TriggerBind,
		Reason:       "验收：重复请求",
	}); err != nil {
		t.Fatalf("重复请求应幂等成功: %v", err)
	}
	var ops int64
	if err := h.app.DB().WithContext(scoped).Table("merge_operations").
		Where("app_id = ? AND target_user_id = ? AND source_user_id = ?",
			h.appID, accC.UserID, accB.UserID).
		Count(&ops).Error; err != nil {
		t.Fatalf("统计合并操作失败: %v", err)
	}
	if ops != 1 {
		t.Fatalf("幂等键应保证只有一条记录，实际 %d 条", ops)
	}
}

// TestMergeImpactReportsCounts 验证管理端二次确认依赖的影响面数字。
func TestMergeImpactReportsCounts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	stub := h.stubProvider()
	accB, err := stub.Create(ctx, domainaccount.CreateRequest{IdempotencyKey: "impact-b"})
	if err != nil {
		t.Fatalf("创建账号失败: %v", err)
	}

	identityRepo := postgres.NewIdentityRepository(h.app.DB())
	bindingRepo := postgres.NewBindingRepository(h.app.DB())
	sessionRepo := postgres.NewSessionRepository(h.app.DB())

	idn, err := identityRepo.Upsert(ctx, identity.UpsertInput{
		AppID:         h.appID,
		Platform:      provider.PlatformGenericOAuth2,
		ProviderAppID: testProviderClientID,
		OpenID:        "impact-openid-" + newAppCode("y"),
		Profile:       map[string]any{},
	})
	if err != nil {
		t.Fatalf("写入 identity 失败: %v", err)
	}
	if _, _, err := bindingRepo.Activate(ctx, binding.ActivateInput{
		AppID: h.appID, ExternalUserID: accB.UserID, IdentityID: idn.ID,
		BindSource: binding.SourceExplicit, At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入绑定失败: %v", err)
	}
	if _, err := sessionRepo.Create(ctx, session.CreateInput{
		AppID: h.appID, ExternalUserID: accB.UserID,
		TokenHash: "impact-token-" + newAppCode("h"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour), At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入令牌失败: %v", err)
	}

	impact, err := postgres.NewMergeImpactor(h.app.DB()).Estimate(ctx, h.appID, accB.UserID)
	if err != nil {
		t.Fatalf("计算影响面失败: %v", err)
	}
	if impact.Bindings != 1 {
		t.Fatalf("应统计到 1 条待改挂绑定，实际 %d", impact.Bindings)
	}
	if impact.Tokens != 1 {
		t.Fatalf("应统计到 1 条待撤销令牌，实际 %d", impact.Tokens)
	}
	if len(impact.Identities) != 1 || !strings.Contains(impact.Identities[0], "generic_oauth2") {
		t.Fatalf("渠道摘要不符: %+v", impact.Identities)
	}
}
