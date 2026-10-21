package adminkey

import (
	"context"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/jwtkit"
)

type fakeStore struct {
	saved  int
	lastID string
	states []jwtkit.KeyState
	err    error
}

func (f *fakeStore) Save(activeKID string, states []jwtkit.KeyState) error {
	if f.err != nil {
		return f.err
	}
	f.saved++
	f.lastID = activeKID
	f.states = states
	return nil
}

func newSvc(t *testing.T) (*Service, *fakeStore, *jwtkit.Signer) {
	t.Helper()
	key, err := jwtkit.GenerateKey("k-initial")
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	signer, err := jwtkit.NewSigner(jwtkit.Options{
		Issuer: "https://auth.test", TTL: 15 * time.Minute, Keys: []jwtkit.Key{key},
	})
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}
	store := &fakeStore{}
	return New(Deps{Signer: signer, Store: store}), store, signer
}

func operator() *admin.Principal {
	return &admin.Principal{User: &admin.User{ID: 3, Role: admin.RoleOperator}}
}

func TestRotateRequiresReason(t *testing.T) {
	svc, store, _ := newSvc(t)
	_, err := svc.Rotate(context.Background(), "x", operator())
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
	if store.saved != 0 {
		t.Fatal("校验失败不得落盘")
	}
}

// TestRotateRequiresStore：只改内存的轮换是假象，必须拒绝。
func TestRotateRequiresStore(t *testing.T) {
	key, _ := jwtkit.GenerateKey("k-initial")
	signer, _ := jwtkit.NewSigner(jwtkit.Options{
		Issuer: "https://auth.test", TTL: time.Minute, Keys: []jwtkit.Key{key},
	})
	svc := New(Deps{Signer: signer}) // 未装配 Store
	_, err := svc.Rotate(context.Background(), "泄露应急轮换", operator())
	if err == nil {
		t.Fatal("未配置密钥存储时必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeConfigInvalid {
		t.Fatalf("应为 CONFIG.INVALID，实际 %v", errs.CodeOf(err))
	}
}

func TestRotatePublishesTwoKeys(t *testing.T) {
	svc, store, signer := newSvc(t)
	out, err := svc.Rotate(context.Background(), "季度例行轮换", operator())
	if err != nil {
		t.Fatalf("轮换失败: %v", err)
	}
	if out.NewKID == "" || out.PreviousKID != "k-initial" {
		t.Fatalf("出参不符: %+v", out)
	}
	// §8.3 第 2 步：JWKS 必须同时有两把。
	if out.PublishedKeys != 2 {
		t.Fatalf("应发布 2 把公钥，实际 %d", out.PublishedKeys)
	}
	if out.RetirableAt == nil {
		t.Fatal("应给出旧密钥可下线时间")
	}
	if signer.ActiveKID() != out.NewKID {
		t.Fatal("签名密钥应切换到新 kid")
	}
	// 落盘发生在内存切换之前，且写入的 active 是新 kid。
	if store.saved != 1 || store.lastID != out.NewKID {
		t.Fatalf("应先落盘再切换，实际 saved=%d active=%s", store.saved, store.lastID)
	}
	// 落盘内容里旧密钥必须带 DemotedAt（否则重启后无法判断能否下线）。
	for _, st := range store.states {
		if st.KID == "k-initial" && st.DemotedAt.IsZero() {
			t.Fatal("旧密钥应记录降级时刻")
		}
	}
}

// TestRotateSaveFailureDoesNotSwitch：落盘失败时内存不能切。
//
// 否则会出现"进程里换了、重启后又变回去"的错配，而运维以为已经换过。
func TestRotateSaveFailureDoesNotSwitch(t *testing.T) {
	svc, store, signer := newSvc(t)
	store.err = errs.New(errs.CodeInternal, "磁盘满")

	if _, err := svc.Rotate(context.Background(), "季度例行轮换", operator()); err == nil {
		t.Fatal("落盘失败应返回错误")
	}
	if signer.ActiveKID() != "k-initial" {
		t.Fatalf("落盘失败时内存不得切换，实际 %s", signer.ActiveKID())
	}
}

func TestRetireRequiresReason(t *testing.T) {
	svc, _, _ := newSvc(t)
	err := svc.Retire(context.Background(), "k-initial", "x", operator())
	if err == nil {
		t.Fatal("reason 过短必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminReasonRequired {
		t.Fatalf("应为 ADMIN.REASON_REQUIRED，实际 %v", errs.CodeOf(err))
	}
}

// TestRetireRejectsActiveKey：当前签名密钥不能下线。
func TestRetireRejectsActiveKey(t *testing.T) {
	svc, _, _ := newSvc(t)
	err := svc.Retire(context.Background(), "k-initial", "尝试下线当前密钥", operator())
	if err == nil {
		t.Fatal("下线当前签名密钥必须拒绝")
	}
	if errs.CodeOf(err) != errs.CodeAdminConflict {
		t.Fatalf("应为 ADMIN.CONFLICT，实际 %v", errs.CodeOf(err))
	}
}

// TestRetireTooEarlyRejected：刚轮换就下线旧密钥必须拒绝。
func TestRetireTooEarlyRejected(t *testing.T) {
	svc, _, _ := newSvc(t)
	if _, err := svc.Rotate(context.Background(), "季度例行轮换", operator()); err != nil {
		t.Fatalf("轮换失败: %v", err)
	}
	if err := svc.Retire(context.Background(), "k-initial", "立即下线旧密钥", operator()); err == nil {
		t.Fatal("旧 token 未过期时下线必须拒绝")
	}
}

// TestListExposesNoPrivateMaterial：列表不返回私钥材料。
func TestListExposesNoPrivateMaterial(t *testing.T) {
	svc, _, _ := newSvc(t)
	items, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("应返回 1 把密钥，实际 %d", len(items))
	}
	if items[0].Status != jwtkit.KeyStatusSigning {
		t.Fatalf("初始密钥应为 signing，实际 %s", items[0].Status)
	}
}
