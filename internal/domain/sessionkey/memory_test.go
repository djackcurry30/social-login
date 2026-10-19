package sessionkey

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()

	if _, err := st.Get(ctx, "app-a", "openid-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("空存储应返回 ErrNotFound，实际=%v", err)
	}
	if err := st.Put(ctx, "app-a", "openid-1", "k1", time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "app-a", "openid-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "k1" {
		t.Fatalf("读取值错误: %q", got)
	}
}

// TestMemoryStoreOverwrites：session_key 每次登录都会变，必须是覆盖而不是并存。
// 两份并存的后果是多留了一份能解开历史密文的密钥。
func TestMemoryStoreOverwrites(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	_ = st.Put(ctx, "app-a", "openid-1", "old", time.Hour)
	_ = st.Put(ctx, "app-a", "openid-1", "new", time.Hour)

	got, err := st.Get(ctx, "app-a", "openid-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "new" {
		t.Fatalf("应覆盖为最新密钥，实际=%q", got)
	}
}

// TestMemoryStoreExpires：过期即不可读，避免一份能解开手机号的密钥长期留存。
func TestMemoryStoreExpires(t *testing.T) {
	st := NewMemoryStore()
	now := time.Unix(1700000000, 0)
	st.now = func() time.Time { return now }
	ctx := context.Background()

	if err := st.Put(ctx, "app-a", "openid-1", "k1", time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := st.Get(ctx, "app-a", "openid-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("过期后应返回 ErrNotFound，实际=%v", err)
	}
}

// TestMemoryStoreIsolatesApps 验证约束 C1：不同应用的同名 openid 互不可见。
func TestMemoryStoreIsolatesApps(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	_ = st.Put(ctx, "app-a", "openid-1", "ka", time.Hour)
	_ = st.Put(ctx, "app-b", "openid-1", "kb", time.Hour)

	if got, _ := st.Get(ctx, "app-a", "openid-1"); got != "ka" {
		t.Fatalf("app-a 读到了错误的值: %q", got)
	}
	if got, _ := st.Get(ctx, "app-b", "openid-1"); got != "kb" {
		t.Fatalf("app-b 读到了错误的值: %q", got)
	}
}

func TestMemoryStoreDeleteIsIdempotent(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	_ = st.Put(ctx, "app-a", "openid-1", "k1", time.Hour)

	if err := st.Delete(ctx, "app-a", "openid-1"); err != nil {
		t.Fatal(err)
	}
	// 重复删除不应报错：平台重投 / 并发解密成功都会走到这里。
	if err := st.Delete(ctx, "app-a", "openid-1"); err != nil {
		t.Fatalf("重复删除不应报错: %v", err)
	}
	if _, err := st.Get(ctx, "app-a", "openid-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后应返回 ErrNotFound，实际=%v", err)
	}
}

func TestMemoryStoreIgnoresEmptyKey(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	if err := st.Put(ctx, "app-a", "openid-1", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	// 空密钥不应被写成"存在"，否则后续会把"没有密钥"误判成"密钥有效"。
	if _, err := st.Get(ctx, "app-a", "openid-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("空密钥不应落库，实际=%v", err)
	}
}
