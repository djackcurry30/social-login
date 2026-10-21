package adminsession

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/domain/session"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

type fakeRepo struct {
	revoked   int64
	lastUser  string
	revokeErr error
}

func (f *fakeRepo) Create(context.Context, session.CreateInput) (*session.RefreshToken, error) {
	return nil, nil
}
func (f *fakeRepo) FindByHash(context.Context, int64, string) (*session.RefreshToken, error) {
	return nil, session.ErrNotFound
}
func (f *fakeRepo) Revoke(context.Context, int64, int64, string) error { return nil }
func (f *fakeRepo) RevokeChainFrom(context.Context, int64, int64, string) (int, error) {
	return 0, nil
}
func (f *fakeRepo) RevokeAllByUser(_ context.Context, _ int64, userID, _ string) (int64, error) {
	f.lastUser = userID
	if f.revokeErr != nil {
		return 0, f.revokeErr
	}
	return f.revoked, nil
}

type fakeLister struct {
	rows     []session.RefreshToken
	lastFilt session.AdminFilter
}

func (f *fakeLister) ListAdmin(_ context.Context, flt session.AdminFilter) ([]session.RefreshToken, int64, error) {
	f.lastFilt = flt
	return f.rows, int64(len(f.rows)), nil
}

type fakeRevocation struct {
	userAt     time.Time
	jti        bool
	revokeUser int
	lastTTL    time.Duration
}

func (f *fakeRevocation) RevokeJTI(context.Context, string, time.Duration) error { return nil }
func (f *fakeRevocation) IsJTIRevoked(context.Context, string) (bool, error) {
	return f.jti, nil
}
func (f *fakeRevocation) RevokeUser(_ context.Context, _ int64, _ string, _ time.Time, ttl time.Duration) error {
	f.revokeUser++
	f.lastTTL = ttl
	return nil
}
func (f *fakeRevocation) RevokedAt(context.Context, int64, string) (time.Time, error) {
	return f.userAt, nil
}

func newSvc() (*Service, *fakeRepo, *fakeLister, *fakeRevocation) {
	repo := &fakeRepo{revoked: 3}
	lister := &fakeLister{}
	rl := &fakeRevocation{}
	return New(Deps{
		Sessions:       repo,
		AdminList:      lister,
		Revocation:     rl,
		AccessTokenTTL: 15 * time.Minute,
	}), repo, lister, rl
}

func operator() *admin.Principal {
	return &admin.Principal{User: &admin.User{ID: 2, Role: admin.RoleOperator}}
}

// --- 查询 ---

func TestListRequiresValidActive(t *testing.T) {
	svc, _, _, _ := newSvc()
	_, err := svc.List(context.Background(), ListInput{Active: "yes"})
	if err == nil {
		t.Fatal("非法 active 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

// TestListActiveIsTriState：空串表示"全部"，true/false 才过滤。
func TestListActiveIsTriState(t *testing.T) {
	svc, _, lister, _ := newSvc()

	if _, err := svc.List(context.Background(), ListInput{Active: ""}); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if lister.lastFilt.Active != nil {
		t.Fatal("空 active 应表示不过滤")
	}

	if _, err := svc.List(context.Background(), ListInput{Active: "true"}); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if lister.lastFilt.Active == nil || !*lister.lastFilt.Active {
		t.Fatal("active=true 应透传")
	}
}

// TestListNeverExposesTokenHash：会话列表不返回 token_hash。
func TestListNeverExposesTokenHash(t *testing.T) {
	svc, _, lister, _ := newSvc()
	now := time.Now().UTC()
	lister.rows = []session.RefreshToken{{
		ID: 1, AppID: 3, ExternalUserID: "u-1",
		TokenHash: "deadbeefdeadbeef", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}}
	out, err := svc.List(context.Background(), ListInput{})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("应返回 1 条，实际 %d", len(out.Items))
	}
	// TokenItem 结构里根本没有 TokenHash 字段——这条断言靠类型系统保证，
	// 这里再确认派生字段 Active 计算正确。
	if !out.Items[0].Active {
		t.Fatal("未撤销且未过期的会话应标记 active")
	}
}

// --- 强制下线 ---

func TestRevokeRequiresAppID(t *testing.T) {
	svc, _, _, _ := newSvc()
	// 不指定应用就可能把用户在其他应用里的会话一起踢掉（约束 C1）。
	_, err := svc.Revoke(context.Background(), RevokeInput{
		ExternalUserID: "u-1", Reason: "账号被盗", Principal: operator(),
	})
	if err == nil {
		t.Fatal("缺 app_id 必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestRevokeRequiresReason(t *testing.T) {
	svc, repo, _, rl := newSvc()
	_, err := svc.Revoke(context.Background(), RevokeInput{
		AppID: 3, ExternalUserID: "u-1", Reason: "x", Principal: operator(),
	})
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if repo.lastUser != "" || rl.revokeUser != 0 {
		t.Fatal("校验失败不得产生任何副作用")
	}
}

// TestRevokeDoesBothSteps 是本组的关键断言：
// 只撤 refresh_token 不写水位 = "下线"只挡住下一次刷新，
// 攻击者手里的 access_token 还能用满 15 分钟。
func TestRevokeDoesBothSteps(t *testing.T) {
	svc, repo, _, rl := newSvc()
	out, err := svc.Revoke(context.Background(), RevokeInput{
		AppID: 3, ExternalUserID: "u-1", Reason: "账号被盗，紧急下线", Principal: operator(),
	})
	if err != nil {
		t.Fatalf("强制下线失败: %v", err)
	}
	if repo.lastUser != "u-1" {
		t.Fatal("应撤销该账号的全部 refresh_token")
	}
	if rl.revokeUser != 1 {
		t.Fatal("必须同时写入账号撤销水位")
	}
	if out.RevokedTokens != 3 {
		t.Fatalf("应返回撤销条数，实际 %d", out.RevokedTokens)
	}
	// 水位 TTL 必须覆盖 access_token 寿命（+1 分钟余量），
	// 否则会在"刚下线 10 分钟"时水位就没了。
	if rl.lastTTL < 15*time.Minute {
		t.Fatalf("水位 TTL 应覆盖 access TTL，实际 %v", rl.lastTTL)
	}
	// 必须如实告知生效窗口。
	if out.EffectiveWindowSeconds != int((15 * time.Minute).Seconds()) {
		t.Fatalf("应返回 900 秒生效窗口，实际 %d", out.EffectiveWindowSeconds)
	}
}

func TestRevokeFailsWithoutRevocationList(t *testing.T) {
	svc := New(Deps{Sessions: &fakeRepo{}, AdminList: &fakeLister{}})
	// 没有撤销名单就兑现不了"立即失效"，宁可失败也不做半套。
	_, err := svc.Revoke(context.Background(), RevokeInput{
		AppID: 3, ExternalUserID: "u-1", Reason: "账号被盗", Principal: operator(),
	})
	if err == nil {
		t.Fatal("未装配撤销名单时应失败")
	}
}

// --- 撤销状态查询 ---

func TestGetRevocationRequiresIdentifier(t *testing.T) {
	svc, _, _, _ := newSvc()
	_, err := svc.GetRevocation(context.Background(), RevocationInput{AppID: 3})
	if err == nil {
		t.Fatal("既无账号也无 jti 必须拒绝")
	}
}

func TestGetRevocationReportsWatermarkAndJTI(t *testing.T) {
	svc, _, _, rl := newSvc()
	at := time.Now().UTC().Add(-time.Minute)
	rl.userAt = at
	rl.jti = true

	out, err := svc.GetRevocation(context.Background(), RevocationInput{
		AppID: 3, ExternalUserID: "u-1", JTI: "jti-9",
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if out.RevokedAt == nil || !out.RevokedAt.Equal(at) {
		t.Fatalf("应返回撤销水位: %+v", out)
	}
	if out.JTIRevoked == nil || !*out.JTIRevoked {
		t.Fatal("应返回 jti 命中状态")
	}
}

func TestGetRevocationEmptyWatermarkOmitted(t *testing.T) {
	svc, _, _, _ := newSvc()
	out, err := svc.GetRevocation(context.Background(), RevocationInput{AppID: 3, ExternalUserID: "u-2"})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	// 没有水位时返回 null 而不是零值时间——零值时间会被前端渲染成 0001 年。
	if out.RevokedAt != nil {
		t.Fatalf("无撤销时不应返回水位: %+v", out.RevokedAt)
	}
}
