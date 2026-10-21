package session

import (
	"context"
	"testing"
	"time"
)

type fakeRevocation struct {
	jti     string
	userAt  time.Time
	jtiErr  error
	userErr error
}

func (f *fakeRevocation) RevokeJTI(context.Context, string, time.Duration) error { return nil }
func (f *fakeRevocation) IsJTIRevoked(context.Context, string) (bool, error) {
	return f.jti != "", f.jtiErr
}
func (f *fakeRevocation) RevokeUser(context.Context, int64, string, time.Time, time.Duration) error {
	return nil
}
func (f *fakeRevocation) RevokedAt(context.Context, int64, string) (time.Time, error) {
	return f.userAt, f.userErr
}

// TestRevokedNilListIsConservative：未装配撤销名单时不声称"已撤销"。
//
// 如果这里返回 true（"安全默认"），一次装配遗漏就会让 check_revocation=true
// 的全部请求被判无效——全站不可用。调用方（introspect）本身默认不查，
// 返回 false 与"没接黑名单"的语义一致。
func TestRevokedNilListIsConservative(t *testing.T) {
	revoked, err := Revoked(context.Background(), nil, 1, "u-1", "jti-1", time.Now())
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if revoked {
		t.Fatal("未装配撤销名单时不应把令牌判为已撤销")
	}
}

func TestRevokedByJTI(t *testing.T) {
	rl := &fakeRevocation{jti: "jti-1"}
	revoked, err := Revoked(context.Background(), rl, 1, "u-1", "jti-1", time.Now())
	if err != nil || !revoked {
		t.Fatalf("命中 jti 黑名单应判撤销: revoked=%v err=%v", revoked, err)
	}
	// 其他 jti 不受影响。
	other := &fakeRevocation{}
	if r, _ := Revoked(context.Background(), other, 1, "u-1", "jti-2", time.Now()); r {
		t.Fatal("未命中的 jti 不应被判撤销")
	}
}

// TestRevokedByUserWatermark：账号级水位裁决"水位之前签发的令牌"。
func TestRevokedByUserWatermark(t *testing.T) {
	checkTime := time.Now().UTC()
	rl := &fakeRevocation{userAt: checkTime}

	// 水位之前签发 → 失效。
	before := checkTime.Add(-time.Minute)
	if r, _ := Revoked(context.Background(), rl, 1, "u-1", "", before); !r {
		t.Fatal("水位之前签发的令牌应失效")
	}
	// 恰好等于水位 → 也失效（用 !After，边界归入撤销一侧：
	// 撤销与签发同毫秒时，宁可多踢一个，不要漏网一个）。
	if r, _ := Revoked(context.Background(), rl, 1, "u-1", "", checkTime); !r {
		t.Fatal("与水位同刻签发的令牌应失效")
	}
	// 水位之后签发（例如用户重新登录）→ 有效。
	after := checkTime.Add(time.Minute)
	if r, _ := Revoked(context.Background(), rl, 1, "u-1", "", after); r {
		t.Fatal("水位之后签发的令牌应仍然有效")
	}
}

// TestRevokedPropagatesError：查询失败要上抛，不能当成"未撤销"。
//
// 把查询失败当成"未撤销"会让一次 Redis 抖动变成一道安全缺口——
// 调用方明确要求了强校验，给不了就必须说给不了。
func TestRevokedPropagatesError(t *testing.T) {
	rl := &fakeRevocation{jtiErr: context.DeadlineExceeded}
	if _, err := Revoked(context.Background(), rl, 1, "u-1", "jti-1", time.Now()); err == nil {
		t.Fatal("查询失败必须上抛错误")
	}
}
