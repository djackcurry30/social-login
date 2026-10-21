// Package acceptance 中的 session_admin_test.go：E 组强制下线的真实依赖验收。
//
// 验证的是修正 P0-5 的核心承诺：
//
//	强制下线后，already-issued 的 access_token 在 check_revocation=true 时
//	【立即】失效；在默认（纯本地验签）模式下仍有 ≤ 15 分钟的生效窗口。
//
// 第二条同样重要：如果黑名单把默认模式也一起打掉，业务方的每个请求都会
// 变成"下线后 15 分钟内全部 401"，那是另一种事故。
package acceptance

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/application/adminsession"
	"github.com/djackcurry30/social-login/internal/infrastructure/cache"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
	"github.com/djackcurry30/social-login/internal/pkg/appctx"
)

func TestForceOfflineInvalidatesAccessToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	const userID = "u_offline_1"
	_, tokens := h.bindOnce(t, userID)
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" {
		t.Fatal("绑定应返回 access_token")
	}

	// 1) 下线前：强校验应通过。
	resp, body := h.postJSON("/v1/introspect", h.appHeaders(), map[string]any{
		"token": accessToken, "check_revocation": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect 期望 200，实际 %d：%v", resp.StatusCode, body)
	}
	if body["active"] != true {
		t.Fatalf("下线前应 active=true，实际 %v", body)
	}

	// 2) 管理员强制下线。
	svc := adminsession.New(adminsession.Deps{
		Sessions:       postgres.NewSessionRepository(h.app.DB()),
		AdminList:      postgres.NewSessionAdminRepository(h.app.DB()),
		Revocation:     cache.NewRevocationStore(h.app.Redis()),
		AccessTokenTTL: h.app.Config().JWT.AccessTokenTTL,
	})
	out, err := svc.Revoke(ctx, adminsession.RevokeInput{
		AppID:          h.appID,
		ExternalUserID: userID,
		Reason:         "验收：账号被盗强制下线",
	})
	if err != nil {
		t.Fatalf("强制下线失败: %v", err)
	}
	if out.RevokedTokens < 1 {
		t.Fatalf("应撤销至少 1 条 refresh_token，实际 %d", out.RevokedTokens)
	}

	// 3) 下线后：强校验必须立即失效（这就是 jti/水位存在的理由）。
	resp, body = h.postJSON("/v1/introspect", h.appHeaders(), map[string]any{
		"token": accessToken, "check_revocation": true,
	})
	if resp.StatusCode != http.StatusOK || body["active"] != false {
		t.Fatalf("强制下线后强校验应 active=false，实际 %d：%v", resp.StatusCode, body)
	}

	// 4) 默认模式（不查撤销）仍为 active——这是文档明确写出的设计权衡：
	//    绝大多数业务请求由业务方本地验签，不该被一次 Redis 往返拖慢。
	if _, plain := h.postJSON("/v1/introspect", h.appHeaders(), map[string]any{
		"token": accessToken,
	}); plain["active"] != true {
		t.Fatalf("默认 introspect 应仍为 active（≤15 分钟窗口），实际 %v", plain)
	}

	// 5) refresh_token 也必须失效：两个通道缺一不可。
	//    这里直接查库确认（HTTP 刷新会消耗轮转链，断言不如查状态直接）。
	var active int64
	scoped := appctx.WithAppScope(ctx, h.appID)
	if err := h.app.DB().WithContext(scoped).Table("refresh_tokens").
		Where("app_id = ? AND external_user_id = ? AND revoked = ?", h.appID, userID, false).
		Count(&active).Error; err != nil {
		t.Fatalf("统计会话失败: %v", err)
	}
	if active != 0 {
		t.Fatalf("强制下线后不应有未撤销的 refresh_token，实际 %d 条", active)
	}

	// 6) 撤销状态可查（排查"用户说自己被莫名登出"）。
	//    h.appID 用的是显式跨应用作用域。
	view, err := svc.GetRevocation(ctx, adminsession.RevocationInput{
		AppID: h.appID, ExternalUserID: userID,
	})
	if err != nil {
		t.Fatalf("查询撤销状态失败: %v", err)
	}
	if view.RevokedAt == nil {
		t.Fatal("应能查到账号撤销水位")
	}
	if !view.RevokedAt.Before(time.Now().Add(time.Second)) {
		t.Fatalf("水位不应在未来: %v", view.RevokedAt)
	}
}
