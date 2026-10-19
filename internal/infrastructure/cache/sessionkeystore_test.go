package cache

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/domain/sessionkey"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
)

// newTestKeyManager 构造一把固定的测试主密钥（32 字节）。
func newTestKeyManager(t *testing.T, seed byte) *crypto.KeyManager {
	t.Helper()
	master := make([]byte, crypto.MasterKeySize)
	for i := range master {
		master[i] = seed + byte(i)
	}
	km, err := crypto.NewKeyManager("test-kek", master)
	if err != nil {
		t.Fatal(err)
	}
	return km
}

// openTestRedis 连接本地 Redis；连不上就跳过。
//
// 这是集成用例而不是单测：它验证的正是"多实例共享"这一层语义
// （键空间、TTL、覆盖写、密文形态），用内存假实现是测不出来的。
func openTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	// 默认指向 docker-compose 暴露的回环端口（见 docker-compose.yml 的 redis.ports）。
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:16379"
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		t.Skipf("本地 Redis 不可用（%s），跳过集成用例: %v", addr, err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestSessionKeyStoreRoundTrip(t *testing.T) {
	rdb := openTestRedis(t)
	ctx := context.Background()
	st := NewSessionKeyStore(rdb, newTestKeyManager(t, 1))

	appID := "app-rt"
	openID := "openid-rt"
	t.Cleanup(func() { _ = rdb.Del(ctx, keyPrefixSessionKey+appID+":"+openID).Err() })

	if err := st.Put(ctx, appID, openID, "session-key-material", time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, appID, openID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-key-material" {
		t.Fatalf("读回值错误: %q", got)
	}
}

// TestSessionKeyStoreEncryptsAtRest 是本实现的关键断言：
// Redis 里存的绝不能是明文 session_key，否则拿到 Redis 快照就等于拿到手机号。
func TestSessionKeyStoreEncryptsAtRest(t *testing.T) {
	rdb := openTestRedis(t)
	ctx := context.Background()
	st := NewSessionKeyStore(rdb, newTestKeyManager(t, 2))

	appID, openID, plain := "app-enc", "openid-enc", "PLAINTEXT-SHOULD-NOT-APPEAR"
	t.Cleanup(func() { _ = rdb.Del(ctx, keyPrefixSessionKey+appID+":"+openID).Err() })

	if err := st.Put(ctx, appID, openID, plain, time.Hour); err != nil {
		t.Fatal(err)
	}
	raw, err := rdb.Get(ctx, keyPrefixSessionKey+appID+":"+openID).Result()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, plain) {
		t.Fatalf("会话密钥以明文落库: %s", raw)
	}
}

func TestSessionKeyStoreSetsTTL(t *testing.T) {
	rdb := openTestRedis(t)
	ctx := context.Background()
	st := NewSessionKeyStore(rdb, newTestKeyManager(t, 3))

	appID, openID := "app-ttl", "openid-ttl"
	t.Cleanup(func() { _ = rdb.Del(ctx, keyPrefixSessionKey+appID+":"+openID).Err() })

	if err := st.Put(ctx, appID, openID, "k", 90*time.Second); err != nil {
		t.Fatal(err)
	}
	ttl, err := rdb.TTL(ctx, keyPrefixSessionKey+appID+":"+openID).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 || ttl > 90*time.Second {
		t.Fatalf("TTL 不符预期: %v", ttl)
	}
}

// TestSessionKeyStoreOverwrites 确认覆盖写：最新密钥生效，且不会残留第二份。
func TestSessionKeyStoreOverwrites(t *testing.T) {
	rdb := openTestRedis(t)
	ctx := context.Background()
	st := NewSessionKeyStore(rdb, newTestKeyManager(t, 4))

	appID, openID := "app-ow", "openid-ow"
	t.Cleanup(func() { _ = rdb.Del(ctx, keyPrefixSessionKey+appID+":"+openID).Err() })

	_ = st.Put(ctx, appID, openID, "old", time.Hour)
	_ = st.Put(ctx, appID, openID, "new", time.Hour)

	got, err := st.Get(ctx, appID, openID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "new" {
		t.Fatalf("应取到最新密钥，实际=%q", got)
	}
}

func TestSessionKeyStoreMissingIsNotFound(t *testing.T) {
	rdb := openTestRedis(t)
	st := NewSessionKeyStore(rdb, newTestKeyManager(t, 5))
	if _, err := st.Get(context.Background(), "app-none", "openid-none"); !errors.Is(err, sessionkey.ErrNotFound) {
		t.Fatalf("不存在时应返回 ErrNotFound，实际=%v", err)
	}
}

func TestSessionKeyStoreDelete(t *testing.T) {
	rdb := openTestRedis(t)
	ctx := context.Background()
	st := NewSessionKeyStore(rdb, newTestKeyManager(t, 6))

	appID, openID := "app-del", "openid-del"
	t.Cleanup(func() { _ = rdb.Del(ctx, keyPrefixSessionKey+appID+":"+openID).Err() })

	_ = st.Put(ctx, appID, openID, "k", time.Hour)
	if err := st.Delete(ctx, appID, openID); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, appID, openID); err != nil {
		t.Fatalf("重复删除不应报错: %v", err)
	}
	if _, err := st.Get(ctx, appID, openID); !errors.Is(err, sessionkey.ErrNotFound) {
		t.Fatalf("删除后应返回 ErrNotFound，实际=%v", err)
	}
}

// TestSessionKeyStoreWrongKEKIsNotFound 模拟 KEK 轮换后解不开旧密文。
// 语义必须是"不可用"（让用户重新授权），而不是内部错误（让登录 500）。
func TestSessionKeyStoreWrongKEKIsNotFound(t *testing.T) {
	rdb := openTestRedis(t)
	ctx := context.Background()

	appID, openID := "app-kek", "openid-kek"
	t.Cleanup(func() { _ = rdb.Del(ctx, keyPrefixSessionKey+appID+":"+openID).Err() })

	writer := NewSessionKeyStore(rdb, newTestKeyManager(t, 7))
	if err := writer.Put(ctx, appID, openID, "k", time.Hour); err != nil {
		t.Fatal(err)
	}

	// 另一把主密钥（KEK 轮换后的新版本）读旧密文。
	reader := NewSessionKeyStore(rdb, newTestKeyManager(t, 99))
	if _, err := reader.Get(ctx, appID, openID); !errors.Is(err, sessionkey.ErrNotFound) {
		t.Fatalf("KEK 不匹配时应按不可用处理，实际=%v", err)
	}
}
