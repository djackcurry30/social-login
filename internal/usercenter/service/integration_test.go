// 集成测试：连真实 PostgreSQL，验证单测无法覆盖的语义。
//
// 为什么必须连真库（与 test/acceptance 的理由相同）：
//
//	本服务的正确性建立在【部分唯一索引】与【行锁重检】上——
//	  · 一个凭证只能属于一个账号
//	  · 一个账号每类凭证只能有一条活跃
//	  · 并发换绑后到者必须失败
//	  · 双向并发合并不能死锁
//	这些全是数据库行为。用内存假仓储测出来的"通过"，换个实现就失效，
//	而失效点恰好是数据越权与账号串号。
//
// 运行方式：
//
//	TEST_USER_CENTER_DSN='postgres://postgres:postgres@127.0.0.1:15432/user_center?sslmode=disable' \
//	    go test ./internal/usercenter/... -run Integration -v
//
// 未设置该变量时全部跳过：默认的 `go test ./...` 不应该因为本机没起 PG 而红。
package service_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
	"github.com/djackcurry30/social-login/internal/usercenter/app"
	"github.com/djackcurry30/social-login/internal/usercenter/cryptox"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/service"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

var (
	initOnce sync.Once
	shared   *service.Service
	// sharedStore 只给审计用例读 account_audit_logs 用：审计是对外的
	// 合规事实，必须从库里读出来验证，而不是断言"我调用过写审计的函数"。
	sharedStore *postgres.Store
	initErr     error
)

// svc 返回共享的服务实例（连接池与迁移只做一次）。
func svc(t *testing.T) *service.Service {
	t.Helper()
	dsn := os.Getenv("TEST_USER_CENTER_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_USER_CENTER_DSN，跳过用户中心集成测试")
	}
	initOnce.Do(func() {
		shared, initErr = build(dsn)
	})
	if initErr != nil {
		t.Fatalf("初始化测试服务失败: %v", initErr)
	}
	return shared
}

func build(dsn string) (*service.Service, error) {
	ctx := context.Background()
	// 测试自己建表：依赖"人先手动跑过迁移"会让 CI 上第一次运行必红。
	if err := app.Migrate(ctx, dsn, "up", nil); err != nil {
		return nil, err
	}
	store, err := postgres.Open(ctx, postgres.Config{DSN: dsn, MaxConns: 10}, nil)
	if err != nil {
		return nil, err
	}
	sharedStore = store

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hasher, err := cryptox.NewClaimHasher(salt)
	if err != nil {
		return nil, err
	}
	key := make([]byte, cryptox.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// 每次测试运行用随机密钥：不同运行之间不能互相解密，
	// 但同一运行内所有用例共用一套，否则跨用例的账号读不出来。
	env, err := cryptox.NewEnvelope("test-kek", key)
	if err != nil {
		return nil, err
	}
	return service.New(store, hasher, env, nil, nil), nil
}

// newApp 注册一个本次测试专用的应用。
//
// 每个用例独立租户，而不是共用 app_test：共用会让"跨应用隔离"这类用例
// 互相污染，且清理时只能清全表（那是测试之间互相打脸的最短路径）。
func newApp(t *testing.T) domain.App {
	t.Helper()
	s := svc(t)

	name := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	if len(name) > 20 {
		name = name[:20]
	}
	// 用【完整】ULID 做后缀，不用前几位：ULID 前 48 位是时间戳，
	// 同一进程内连续调用生成的前 6 个字符几乎必然相同
	// （曾因此让多个用例共用一个应用，数据互相污染，表现为"刚建的号查不到凭证"）。
	key := "it_" + name + "_" + strings.ToLower(ids.ULID())

	got, err := s.RegisterApp(context.Background(), key, "integration", "active")
	if err != nil {
		t.Fatalf("注册测试应用失败: %v", err)
	}
	return got
}

func phone(v string) domain.Claim {
	return domain.Claim{Type: "phone", Value: v, Source: "wechat_phone"}
}
func email(v string) domain.Claim {
	return domain.Claim{Type: "email", Value: v, Source: "apple_email"}
}

func mustCreate(t *testing.T, app domain.App, key string, claims ...domain.Claim) *domain.Account {
	t.Helper()
	out, err := svc(t).Create(context.Background(), app, service.CreateRequest{
		IdempotencyKey: key,
		Claims:         claims,
	})
	if err != nil {
		t.Fatalf("建号失败: %v", err)
	}
	return out.Account
}

// claimValue 取出账号某类型凭证的值。
func claimValue(acc *domain.Account, typ string) string {
	for _, c := range acc.Claims {
		if c.Type == typ {
			return c.Value
		}
	}
	return ""
}

func wantCode(t *testing.T, err error, code domain.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望错误 %s，实际成功", code)
	}
	e, ok := domain.As(err)
	if !ok {
		t.Fatalf("期望领域错误 %s，实际 %T: %v", code, err, err)
	}
	if e.Code != code {
		t.Fatalf("期望错误码 %s，实际 %s: %v", code, e.Code, e)
	}
}

func TestIntegrationCreateAndRead(t *testing.T) {
	s := svc(t)
	appA := newApp(t)

	acc := mustCreate(t, appA, "k1", phone("+86 138-0000-0000"))
	if acc.Status != domain.StatusActive {
		t.Fatalf("新账号状态应为 active，实际 %s", acc.Status)
	}
	// 归一化必须生效：库里存的是 13800000000，不是带区号的原文。
	if got := claimValue(acc, "phone"); got != "13800000000" {
		t.Fatalf("凭证未归一化: %q", got)
	}

	got, err := s.Get(context.Background(), appA, acc.UserID)
	if err != nil {
		t.Fatalf("按 id 查询失败: %v", err)
	}
	if got.UserID != acc.UserID || claimValue(got, "phone") != "13800000000" {
		t.Fatalf("按 id 查询结果不一致: %+v", got)
	}

	// 带上区号的写法必须命中同一个账号——这是两边归一化规则一致的证明。
	byClaim, err := s.GetByClaim(context.Background(), appA, "phone", "8613800000000")
	if err != nil {
		t.Fatalf("按凭证反查失败: %v", err)
	}
	if byClaim.UserID != acc.UserID {
		t.Fatalf("按凭证反查命中另一个账号: %s ≠ %s", byClaim.UserID, acc.UserID)
	}
}

func TestIntegrationCreateIdempotent(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	req := service.CreateRequest{IdempotencyKey: "first-login-42", Claims: []domain.Claim{phone("13900000001")}}
	first, err := s.Create(ctx, appA, req)
	if err != nil {
		t.Fatalf("首次建号失败: %v", err)
	}
	if first.Replayed {
		t.Fatal("首次建号不应标记为重放")
	}

	second, err := s.Create(ctx, appA, req)
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if !second.Replayed {
		t.Fatal("同键重放应标记 Replayed=true")
	}
	if second.Account.UserID != first.Account.UserID {
		t.Fatalf("重放返回了另一个账号: %s ≠ %s", second.Account.UserID, first.Account.UserID)
	}
}

// TestIntegrationIdempotencyKeyReuse 同键不同体必须拒绝。
//
// 返回旧结果等于"静默丢弃了一次请求"——调用方以为建了号，实际拿到的是
// 另一次请求的账号。这类错误在登录链路上表现为"两个用户共用一个账号"。
func TestIntegrationIdempotencyKeyReuse(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, appA, service.CreateRequest{
		IdempotencyKey: "fixed-key",
		Claims:         []domain.Claim{phone("13900000002")},
	}); err != nil {
		t.Fatalf("首次建号失败: %v", err)
	}

	_, err := s.Create(ctx, appA, service.CreateRequest{
		IdempotencyKey: "fixed-key",
		Claims:         []domain.Claim{phone("13900000003")},
	})
	wantCode(t, err, domain.CodeInvalid)
}

// TestIntegrationConcurrentSameKey 10 个并发同键建号只能产生 1 个账号。
//
// 这是 P0-4 的核心：接入方重试与用户连点都会产生并发同键请求。
func TestIntegrationConcurrentSameKey(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 尽量同时发出，制造真实的并发窗口
			out, err := s.Create(ctx, appA, service.CreateRequest{
				IdempotencyKey: "concurrent-key",
				Claims:         []domain.Claim{phone("13900000010")},
			})
			errs[i] = err
			if err == nil {
				ids[i] = out.Account.UserID
			}
		}(i)
	}
	close(start)
	wg.Wait()

	var want string
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			// 允许"幂等处理中"这类可重试错误（当前单事务实现下不会出现），
			// 但不允许"凭证被占用"——同键并发不该走到唯一冲突。
			wantCode(t, errs[i], domain.CodeIdemInProgress)
			continue
		}
		if want == "" {
			want = ids[i]
			continue
		}
		if ids[i] != want {
			t.Fatalf("并发同键建出了多个账号: %s 与 %s", want, ids[i])
		}
	}
	if want == "" {
		t.Fatal("全部并发请求都失败了")
	}

	// 再从数据库侧确认只有一个账号持有该凭证。
	acc, err := s.GetByClaim(ctx, appA, "phone", "13900000010")
	if err != nil || acc.UserID != want {
		t.Fatalf("按凭证反查应命中 %s，实际 %v/%v", want, acc, err)
	}
}

// TestIntegrationConcurrentSameClaim 不同键、同凭证并发：恰好 1 个成功。
//
// 靠唯一索引裁决，而不是"先查后插"——后者有 TOCTOU 窗口，
// 两个请求会双双通过检查，然后写入两个账号。
func TestIntegrationConcurrentSameClaim(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	okCount, takenCount := 0, 0
	var mu sync.Mutex
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := s.Create(ctx, appA, service.CreateRequest{
				IdempotencyKey: fmt.Sprintf("claim-race-%d", i),
				Claims:         []domain.Claim{phone("13900000011")},
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				okCount++
				return
			}
			if e, isDomain := domain.As(err); isDomain && e.Code == domain.CodeClaimTaken {
				takenCount++
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if okCount != 1 {
		t.Fatalf("同凭证并发建号应恰好 1 个成功，实际 %d 个", okCount)
	}
	if takenCount != n-1 {
		t.Fatalf("其余 %d 个应全部是 CLAIM_TAKEN，实际 %d 个", n-1, takenCount)
	}
}

// TestIntegrationCrossAppIsolation v1.1 的核心要求：账号空间按应用隔离。
//
// 同一个手机号在两个应用里必须是两个账号。做不到的话，App2 的用户会
// 登进 App1 的账号——这是数据越权，不是小 bug。
func TestIntegrationCrossAppIsolation(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	appB, err := s.RegisterApp(context.Background(), appA.Key+"_b", "second", "active")
	if err != nil {
		t.Fatalf("注册第二个应用失败: %v", err)
	}
	ctx := context.Background()

	a := mustCreate(t, appA, "iso-a", phone("13900000020"))
	b := mustCreate(t, appB, "iso-b", phone("13900000020"))
	if a.UserID == b.UserID {
		t.Fatal("同一凭证在两个应用里得到了同一个账号：账号空间没隔离")
	}

	// 跨应用按 id 查必须 404（不泄漏另一个租户里有没有这个人）。
	_, err = s.Get(ctx, appB, a.UserID)
	wantCode(t, err, domain.CodeNotFound)

	// 反向：A 里查不到 B 的账号。
	_, err = s.Get(ctx, appA, b.UserID)
	wantCode(t, err, domain.CodeNotFound)

	// 跨应用合并不存在"拒绝"这回事，对外就是查不到（R3）。
	_, err = s.Merge(ctx, appA, service.MergeRequest{
		IdempotencyKey: "cross-app", TargetUserID: a.UserID, SourceUserID: b.UserID,
	})
	wantCode(t, err, domain.CodeNotFound)
}

// TestIntegrationMerge 验证"类型目标优先"与 discarded_claims。
//
// 这是 §12.2 第 1 条：合并会丢手机号。用户的旧号必须能被查出来
// （撤销行保留），否则客服无法解释"我另一个号呢"。
func TestIntegrationMerge(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	target := mustCreate(t, appA, "m-t", phone("13900000030"), email("target@example.com"))
	source := mustCreate(t, appA, "m-s", phone("13900000031"))

	res, err := s.Merge(ctx, appA, service.MergeRequest{
		IdempotencyKey: "merge-1",
		TargetUserID:   target.UserID,
		SourceUserID:   source.UserID,
		Reason:         "同一个人的两个账号",
	})
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if !res.Merged || res.AlreadyMerged {
		t.Fatalf("首次合并应为 merged=true/already_merged=false，实际 %+v", res)
	}
	if len(res.DiscardedClaims) != 1 || res.DiscardedClaims[0].Value != "13900000031" {
		t.Fatalf("应丢弃 source 的手机号，实际 %+v", res.DiscardedClaims)
	}

	// source 已关闭且指向 target。
	src, err := s.Get(ctx, appA, source.UserID)
	if err != nil {
		t.Fatalf("查询已合并的 source 失败: %v", err)
	}
	if src.Status != domain.StatusClosed || src.MergedInto != target.UserID {
		t.Fatalf("source 应 closed 且 merged_into=target，实际 %+v", src)
	}
	if len(src.Claims) != 0 {
		t.Fatalf("已合并 source 不应有活跃凭证，实际 %+v", src.Claims)
	}

	// 被丢弃的号码已释放：现在可以被新账号绑定（否则会永久占用）。
	_, err = s.GetByClaim(ctx, appA, "phone", "13900000031")
	wantCode(t, err, domain.CodeNotFound)

	// target 的邮箱没被 source 覆盖（source 没有邮箱，等于保留 target 的）。
	byEmail, err := s.GetByClaim(ctx, appA, "email", "target@example.com")
	if err != nil || byEmail.UserID != target.UserID {
		t.Fatalf("target 的邮箱应仍可用，实际 %v/%v", byEmail, err)
	}
}

// TestIntegrationMergeAlreadyMerged 重放必须返回 already_merged=true，
// 且**不能**再迁移一次数据。
func TestIntegrationMergeAlreadyMerged(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	target := mustCreate(t, appA, "am-t", phone("13900000040"))
	source := mustCreate(t, appA, "am-s", email("am-s@example.com"))

	req := service.MergeRequest{IdempotencyKey: "merge-replay", TargetUserID: target.UserID, SourceUserID: source.UserID}
	first, err := s.Merge(ctx, appA, req)
	if err != nil || !first.Merged {
		t.Fatalf("首次合并失败: %v %+v", err, first)
	}

	second, err := s.Merge(ctx, appA, req)
	if err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	if second.Merged || !second.AlreadyMerged {
		t.Fatalf("重放应为 merged=false/already_merged=true，实际 %+v", second)
	}
	if len(second.DiscardedClaims) != 0 {
		t.Fatalf("重放不应再丢弃任何凭证，实际 %+v", second.DiscardedClaims)
	}

	// 换一个幂等键、同一对账号：仍然是"已完成"，不能再执行一次。
	third, err := s.Merge(ctx, appA, service.MergeRequest{
		IdempotencyKey: "merge-replay-2", TargetUserID: target.UserID, SourceUserID: source.UserID,
	})
	if err != nil {
		t.Fatalf("不同键重放失败: %v", err)
	}
	if third.Merged || !third.AlreadyMerged {
		t.Fatalf("source 已关闭时不同键也应返回 already_merged，实际 %+v", third)
	}
}

// TestIntegrationMergeConcurrentOpposite 双向并发合并不能死锁。
//
// 没有 ORDER BY id FOR UPDATE 时，A→B 与 B→A 会互相等对方持有的行。
// 这里的断言是"能跑完"（死锁会让查询一直等到 statement_timeout 报错）
// 且恰好一个方向成功。
func TestIntegrationMergeConcurrentOpposite(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	a := mustCreate(t, appA, "opp-a", phone("13900000050"))
	b := mustCreate(t, appA, "opp-b", phone("13900000051"))

	var wg sync.WaitGroup
	results := make([]*service.MergeOutcome, 2)
	errs := make([]error, 2)
	start := make(chan struct{})

	pairs := [][2]string{{a.UserID, b.UserID}, {b.UserID, a.UserID}}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.Merge(ctx, appA, service.MergeRequest{
				IdempotencyKey: fmt.Sprintf("opp-%d", i),
				TargetUserID:   pairs[i][0],
				SourceUserID:   pairs[i][1],
			})
		}(i)
	}
	close(start)
	wg.Wait()

	merged, already, rejected := 0, 0, 0
	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			e, ok := domain.As(errs[i])
			if !ok || (e.Code != domain.CodeConflict && e.Code != domain.CodeMergeRejected) {
				t.Fatalf("并发合并出现非预期错误: %v", errs[i])
			}
			rejected++
			continue
		}
		if results[i].Merged {
			merged++
		}
		if results[i].AlreadyMerged {
			already++
		}
	}
	if merged != 1 {
		t.Fatalf("双向并发合并应恰好 1 个真正执行，实际 merged=%d already=%d rejected=%d",
			merged, already, rejected)
	}
}

// TestIntegrationReplaceClaim 换绑：新值生效、旧值释放、冲突拒绝。
func TestIntegrationReplaceClaim(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	acc := mustCreate(t, appA, "r-1", phone("13900000060"))

	updated, err := s.ReplaceClaim(ctx, appA, acc.UserID, "phone", "139-0000-0061", "sms_verified")
	if err != nil {
		t.Fatalf("换绑失败: %v", err)
	}
	if got := claimValue(updated, "phone"); got != "13900000061" {
		t.Fatalf("换绑后凭证实为 %q", got)
	}

	// 旧号已释放。
	_, err = s.GetByClaim(ctx, appA, "phone", "13900000060")
	wantCode(t, err, domain.CodeNotFound)

	// 旧号可以被另一个账号绑定——释放必须是真释放。
	mustCreate(t, appA, "r-2", phone("13900000060"))

	// 换到已被别人占用的号 → CLAIM_TAKEN，且本账号原值不变。
	other := mustCreate(t, appA, "r-3", phone("13900000062"))
	_, err = s.ReplaceClaim(ctx, appA, other.UserID, "phone", "13900000061", "sms_verified")
	wantCode(t, err, domain.CodeClaimTaken)
	after, err := s.Get(ctx, appA, other.UserID)
	if err != nil || claimValue(after, "phone") != "13900000062" {
		t.Fatalf("冲突换绑后原值不应变化，实际 %+v/%v", after, err)
	}

	// 幂等 no-op：换到当前值不报错。
	if _, err := s.ReplaceClaim(ctx, appA, acc.UserID, "phone", "13900000061", "sms_verified"); err != nil {
		t.Fatalf("换绑到当前值应幂等成功: %v", err)
	}
}

// TestIntegrationClose 注销：撤销全部凭证、状态 closed、重复调用幂等。
func TestIntegrationClose(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	acc := mustCreate(t, appA, "c-1", phone("13900000070"), email("close@example.com"))

	if err := s.Close(ctx, appA, acc.UserID); err != nil {
		t.Fatalf("注销失败: %v", err)
	}

	// 凭证全部释放：号码可以被别人重新注册。
	_, err := s.GetByClaim(ctx, appA, "phone", "13900000070")
	wantCode(t, err, domain.CodeNotFound)

	got, err := s.Get(ctx, appA, acc.UserID)
	if err != nil {
		t.Fatalf("注销后仍应能按 id 查到（业务方需要知道它关了）: %v", err)
	}
	if got.Status != domain.StatusClosed || len(got.Claims) != 0 {
		t.Fatalf("注销后状态应为 closed 且无凭证，实际 %+v", got)
	}

	// 重复注销不报错：用户可能连点。
	if err := s.Close(ctx, appA, acc.UserID); err != nil {
		t.Fatalf("重复注销应幂等成功: %v", err)
	}

	// 已关闭账号不能换绑。
	_, err = s.ReplaceClaim(ctx, appA, acc.UserID, "phone", "13900000071", "sms_verified")
	wantCode(t, err, domain.CodeNotFound)
}

// TestIntegrationAppUnknownAndDisabled 应用未注册 / 已停用都必须拒绝。
func TestIntegrationAppUnknownAndDisabled(t *testing.T) {
	s := svc(t)
	ctx := context.Background()

	_, err := s.ResolveApp(ctx, "app_never_registered_xyz")
	wantCode(t, err, domain.CodeAppUnknown)

	appA := newApp(t)
	if _, err := s.RegisterApp(ctx, appA.Key, "integration", "disabled"); err != nil {
		t.Fatalf("停用应用失败: %v", err)
	}
	_, err = s.ResolveApp(ctx, appA.Key)
	wantCode(t, err, domain.CodeAppDisabled)
}

// TestIntegrationValidation 校验发生在写库之前。
func TestIntegrationValidation(t *testing.T) {
	s := svc(t)
	appA := newApp(t)
	ctx := context.Background()

	// 缺幂等键。
	_, err := s.Create(ctx, appA, service.CreateRequest{Claims: []domain.Claim{phone("13900000080")}})
	wantCode(t, err, domain.CodeInvalid)

	// 同类型两条凭证。
	_, err = s.Create(ctx, appA, service.CreateRequest{
		IdempotencyKey: "dup-type",
		Claims:         []domain.Claim{phone("13900000081"), phone("13900000082")},
	})
	wantCode(t, err, domain.CodeInvalid)

	// 非法号码。
	_, err = s.Create(ctx, appA, service.CreateRequest{
		IdempotencyKey: "bad-phone",
		Claims:         []domain.Claim{phone("123")},
	})
	wantCode(t, err, domain.CodeInvalid)

	// 不支持的类型。
	_, err = s.Create(ctx, appA, service.CreateRequest{
		IdempotencyKey: "bad-type",
		Claims:         []domain.Claim{{Type: "open_id", Value: "oX123"}},
	})
	wantCode(t, err, domain.CodeInvalid)
}

// TestIntegrationAuditTrail 验证"谁在什么时候对哪个账号做了什么"确实落库。
//
// 为什么必须从库里读回来断言：
//
//	审计的价值全在"事后能查"。如果只断言"调用过写审计的函数"，把 INSERT
//	写错一个列名、或事务提前提交，用例照样绿，而合规查询会永远查不到记录。
//
// 顺带守住三条硬要求：trace_id 与调用方同值、actor 可区分调用方、
// detail 里【不含】手机号明文。
func TestIntegrationAuditTrail(t *testing.T) {
	s := svc(t)
	app := newApp(t)

	// 构造一次真实的调用上下文：trace id 与 actor 都由 HTTP 层填入，
	// 这里手工模拟，验证它们能一路传到审计行。
	ctx := reqmeta.With(context.Background(), reqmeta.Meta{
		TraceID:   "tr_it_" + strings.ToLower(ids.ULID()),
		ClientIP:  "10.0.0.8",
		UserAgent: "integration-test",
		Actor:     "social-login",
	})

	const phoneValue = "13900001111"
	created, err := s.Create(ctx, app, service.CreateRequest{
		IdempotencyKey: "audit-1",
		Claims:         []domain.Claim{phone(phoneValue)},
	})
	if err != nil {
		t.Fatalf("建号失败: %v", err)
	}
	userID := created.Account.UserID

	// 换绑：动作应是 "claim.replaced"（不是 claim.bound）。
	if _, err := s.ReplaceClaim(ctx, app, userID, "phone", "13900002222", "wechat_phone"); err != nil {
		t.Fatalf("换绑失败: %v", err)
	}
	// 合并：源账号并进来。用同一个 ctx 建号——必须显式传 ctx，
	// 否则会走 mustCreate 的 context.Background()，那行的 actor 是 "service"，
	// 断言会误报（第一版就是这么红的：把测试自己造的数据当成了被测行为）。
	srcOut, err := s.Create(ctx, app, service.CreateRequest{
		IdempotencyKey: "audit-2",
		Claims:         []domain.Claim{email("audit-src@example.com")},
	})
	if err != nil {
		t.Fatalf("建源账号失败: %v", err)
	}
	src := srcOut.Account
	if _, err := s.Merge(ctx, app, service.MergeRequest{
		IdempotencyKey: "audit-merge",
		TargetUserID:   userID,
		SourceUserID:   src.UserID,
		Reason:         "集成测试",
	}); err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	// 关闭：另建一个账号来关。不能拿 src——它在合并时已被置 closed，
	// close 是幂等 no-op，不会产生审计（合并的审计里已经带了 source_user_id，
	// 再记一条 account.closed 会让"这个账号被关了两次"这种错觉出现在审计里）。
	victimOut, err := s.Create(ctx, app, service.CreateRequest{
		IdempotencyKey: "audit-3",
		Claims:         []domain.Claim{phone("13900003333")},
	})
	if err != nil {
		t.Fatalf("建待关闭账号失败: %v", err)
	}
	victim := victimOut.Account
	if err := s.Close(ctx, app, victim.UserID); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	list, err := sharedStore.ListAudit(context.Background(), postgres.AuditFilter{
		AppID: app.ID, Limit: 100,
	})
	if err != nil {
		t.Fatalf("读取审计失败: %v", err)
	}

	// 按 (user_id, action) 汇总：同一账号上应当出现建号、换绑、合并、关闭。
	type key struct{ user, action string }
	seen := map[key]int{}
	for _, r := range list {
		seen[key{r.UserID, r.Action}]++
		if r.Actor != "social-login" {
			t.Fatalf("actor 应透传调用方，实际 %q（action=%s）", r.Actor, r.Action)
		}
		if r.TraceID != reqmeta.From(ctx).TraceID {
			t.Fatalf("trace_id 应与调用方一致，实际 %q", r.TraceID)
		}
		if r.ClientIP != "10.0.0.8" {
			t.Fatalf("client_ip 应落库，实际 %q", r.ClientIP)
		}
		// detail 不允许出现凭证明文：审计表保留期更长、可查的人更多。
		if strings.Contains(string(r.Detail), phoneValue) {
			t.Fatalf("审计 detail 泄漏了手机号明文: %s", r.Detail)
		}
	}

	// 建号只写一条 account.created：凭证是建号的一部分，不该再记一条
	// claim.bound——否则"账号被创建"与"用户绑了手机号"在审计里看起来
	// 是两次独立操作，客服读起来会以为中间隔了一段时间。
	want := []key{
		{userID, postgres.AuditAccountCreated},
		{userID, postgres.AuditClaimReplaced},
		{userID, postgres.AuditAccountMerged},
		{victim.UserID, postgres.AuditAccountClosed},
	}
	for _, k := range want {
		if seen[k] == 0 {
			t.Fatalf("缺少审计记录 %v，实际: %+v", k, seen)
		}
	}

	// 幂等重放不写审计：它没有改变任何数据，写进来会让"这个账号被改过几次"不可读。
	before := len(list)
	if _, err := s.Create(ctx, app, service.CreateRequest{
		IdempotencyKey: "audit-1",
		Claims:         []domain.Claim{phone(phoneValue)},
	}); err != nil {
		t.Fatalf("重放失败: %v", err)
	}
	after, err := sharedStore.ListAudit(context.Background(), postgres.AuditFilter{
		AppID: app.ID, Limit: 100,
	})
	if err != nil {
		t.Fatalf("重读审计失败: %v", err)
	}
	if len(after) != before {
		t.Fatalf("幂等重放不应新增审计：%d → %d", before, len(after))
	}
}
