package adminidentity

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// --- J 组 fakes ---

type fakeClaimAdmin struct {
	rows    []identity.Claim
	total   int64
	lastQ   identity.ClaimAdminQuery
	queries int
}

func (f *fakeClaimAdmin) ListAdmin(_ context.Context, q identity.ClaimAdminQuery) ([]identity.Claim, int64, error) {
	f.lastQ = q
	f.queries++
	return f.rows, f.total, nil
}

type fakeMismatches struct {
	rows       []identity.Mismatch
	total      int64
	openTotal  int64
	resolved   int64
	lastRes    identity.ResolveInput
	resolveN   int64
	resolveErr error
}

func (f *fakeMismatches) Record(context.Context, identity.MismatchRecordInput) error { return nil }

func (f *fakeMismatches) ListAdmin(_ context.Context, q identity.MismatchAdminQuery) ([]identity.Mismatch, int64, error) {
	if q.Status == identity.MismatchStatusOpen {
		return f.rows, f.openTotal, nil
	}
	return f.rows, f.total, nil
}

func (f *fakeMismatches) ResolveByClaim(_ context.Context, in identity.ResolveInput) (int64, error) {
	f.lastRes = in
	if f.resolveErr != nil {
		return 0, f.resolveErr
	}
	return f.resolveN, nil
}

func newJSvc(claims *fakeClaims, admin *fakeClaimAdmin, mm *fakeMismatches) *Service {
	return New(Deps{
		Identities:  &fakeIdentities{},
		IdentityGet: &fakeIdentityRepo{item: &identity.Identity{ID: 9, AppID: 3}},
		Claims:      claims,
		ClaimAdmin:  admin,
		Mismatches:  mm,
		Bindings:    &fakeBindings{},
		Writer:      &fakeWriter{},
		Now:         func() time.Time { return time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC) },
	})
}

// --- 凭证查询 ---

func TestListClaimsRejectsUnknownStatus(t *testing.T) {
	svc := newJSvc(&fakeClaims{}, &fakeClaimAdmin{}, &fakeMismatches{})
	_, err := svc.ListClaims(context.Background(), ClaimListInput{Status: "weird"})
	if errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("非法 status 应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

// 已撤销记录必须能被查出来：换号排查的第一步就是"旧号什么时候被释放的"。
func TestListClaimsSupportsRevokedFilter(t *testing.T) {
	admin := &fakeClaimAdmin{}
	svc := newJSvc(&fakeClaims{}, admin, &fakeMismatches{})
	if _, err := svc.ListClaims(context.Background(),
		ClaimListInput{AppID: 3, Status: identity.ClaimStatusRevoked}); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if admin.lastQ.Status != identity.ClaimStatusRevoked {
		t.Fatalf("筛选条件未透传，实际 %q", admin.lastQ.Status)
	}
}

func TestListClaimsHidesHashAndComputesStatus(t *testing.T) {
	revoked := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	admin := &fakeClaimAdmin{rows: []identity.Claim{
		{ID: 1, AppID: 3, IdentityID: 9, Type: "phone", ValueHash: "abcdef0123456789",
			Verified: true, Source: identity.SourceSMSVerified, CreatedAt: time.Now()},
		{ID: 2, AppID: 3, IdentityID: 9, Type: "phone", ValueHash: "ffffffffff000000",
			Verified: true, Source: identity.SourceWeChatPhone, RevokedAt: &revoked},
	}}
	svc := newJSvc(&fakeClaims{}, admin, &fakeMismatches{})
	out, err := svc.ListClaims(context.Background(), ClaimListInput{AppID: 3})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if out.Items[0].ValueHash != "abcdef01" || out.Items[1].ValueHash != "ffffffff" {
		t.Fatalf("应只返回哈希前缀: %+v", out.Items)
	}
	// 撤销只置 revoked_at，不改 verified 位；status 必须能正确反映"已撤销"。
	if out.Items[0].Status != identity.ClaimStatusVerified {
		t.Fatalf("有效凭证应为 verified，实际 %q", out.Items[0].Status)
	}
	if out.Items[1].Status != identity.ClaimStatusRevoked {
		t.Fatalf("已撤销凭证应为 revoked，实际 %q", out.Items[1].Status)
	}
}

// --- 漂移记录 ---

func TestListMismatchesValidatesFilters(t *testing.T) {
	svc := newJSvc(&fakeClaims{}, &fakeClaimAdmin{}, &fakeMismatches{})
	if _, err := svc.ListMismatches(context.Background(),
		MismatchListInput{Kind: "???"}); errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("非法 kind 应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
	if _, err := svc.ListMismatches(context.Background(),
		MismatchListInput{Status: "done"}); errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("非法 status 应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
}

// open_total 不受筛选影响：它是"这个应用还有多少条待处理"的全量信号。
func TestListMismatchesReportsOpenTotal(t *testing.T) {
	mm := &fakeMismatches{
		rows:  []identity.Mismatch{{ID: 1, Kind: identity.MismatchAccountMismatch}},
		total: 4, openTotal: 7,
	}
	svc := newJSvc(&fakeClaims{}, &fakeClaimAdmin{}, mm)
	out, err := svc.ListMismatches(context.Background(), MismatchListInput{
		AppID: 3, Status: identity.MismatchStatusResolved,
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if out.Total != 4 {
		t.Fatalf("筛选后 total 应为 4，实际 %d", out.Total)
	}
	if out.OpenTotal != 7 {
		t.Fatalf("open_total 应为未闭环全量 7，实际 %d", out.OpenTotal)
	}
	if len(out.Items) != 1 || out.Items[0].Kind != identity.MismatchAccountMismatch {
		t.Fatalf("出参不符: %+v", out.Items)
	}
}

// --- 撤销凭证 ---

func TestRevokeClaimRequiresAppIDAndReason(t *testing.T) {
	svc := newJSvc(&fakeClaims{}, &fakeClaimAdmin{}, &fakeMismatches{})
	if _, err := svc.RevokeClaim(context.Background(), 1, RevokeClaimInput{
		Reason: "用户申诉换号", Principal: operator(),
	}); errs.CodeOf(err) != errs.CodeInvalidRequest {
		t.Fatalf("缺 app_id 应为 REQUEST.INVALID，实际 %v", errs.CodeOf(err))
	}
	if _, err := svc.RevokeClaim(context.Background(), 1, RevokeClaimInput{
		AppID: 3, Reason: "x", Principal: operator(),
	}); errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("reason 过短应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
}

// 不存在的凭证必须 404，而不是被 errs.From 归一化成 500（G 组踩过一次）。
func TestRevokeClaimNotFoundIs404(t *testing.T) {
	svc := newJSvc(&fakeClaims{byID: map[int64]*identity.Claim{}}, &fakeClaimAdmin{}, &fakeMismatches{})
	_, err := svc.RevokeClaim(context.Background(), 999, RevokeClaimInput{
		AppID: 3, Reason: "用户申诉换号", Principal: operator(),
	})
	if errs.CodeOf(err) != errs.CodeNotFound {
		t.Fatalf("应为 404，实际 %v", errs.CodeOf(err))
	}
}

func TestRevokeClaimRevokesAndResolvesMismatches(t *testing.T) {
	claims := &fakeClaims{byID: map[int64]*identity.Claim{
		7: {ID: 7, AppID: 3, IdentityID: 9, Type: "phone",
			ValueHash: "abcdef0123456789", Verified: true, Source: identity.SourceSMSVerified},
	}}
	mm := &fakeMismatches{resolveN: 2}
	svc := newJSvc(claims, &fakeClaimAdmin{}, mm)

	out, err := svc.RevokeClaim(context.Background(), 7, RevokeClaimInput{
		AppID: 3, Reason: "用户申诉：手机号已换绑", Principal: operator(),
	})
	if err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	if len(claims.revoked) != 1 || claims.revoked[0] != 9 {
		t.Fatalf("应按 claim 所属身份撤销: %+v", claims.revoked)
	}
	if out.AlreadyRevoked {
		t.Fatal("首次撤销不应标记 already_revoked")
	}
	if out.Claim.RevokedAt == nil {
		t.Fatal("出参应带上撤销时间")
	}
	if out.ResolvedMismatches != 2 {
		t.Fatalf("应闭环 2 条漂移，实际 %d", out.ResolvedMismatches)
	}
	// 闭环理由要能看出是撤销动作带来的，否则事后无法区分"人工确认保留"。
	if mm.lastRes.ClaimID != 7 || mm.lastRes.By != "admin:2" {
		t.Fatalf("闭环入参不符: %+v", mm.lastRes)
	}
	if mm.lastRes.Resolution == "" {
		t.Fatal("闭环必须记录理由")
	}
}

// 重复撤销是幂等的，但要如实告知 already_revoked——
// 否则运维分不清"是我撤的"还是"别人已经处理过"。
func TestRevokeClaimIsIdempotent(t *testing.T) {
	revokedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	claims := &fakeClaims{byID: map[int64]*identity.Claim{
		7: {ID: 7, AppID: 3, IdentityID: 9, Type: "phone",
			ValueHash: "abcdef0123456789", Verified: true, RevokedAt: &revokedAt},
	}}
	svc := newJSvc(claims, &fakeClaimAdmin{}, &fakeMismatches{})
	out, err := svc.RevokeClaim(context.Background(), 7, RevokeClaimInput{
		AppID: 3, Reason: "重复点击", Principal: operator(),
	})
	if err != nil {
		t.Fatalf("重复撤销不应报错: %v", err)
	}
	if !out.AlreadyRevoked {
		t.Fatal("应标记 already_revoked")
	}
	if len(claims.revoked) != 0 {
		t.Fatal("已撤销的凭证不应再次调用 Revoke")
	}
}
