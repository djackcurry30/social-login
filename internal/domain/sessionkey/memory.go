package sessionkey

import (
	"context"
	"sync"
	"time"
)

// MemoryStore 是 Store 的进程内实现。
//
// ⚠️ 只适用于单测与单实例本地调试。
//
// 多实例部署下用它会导致【概率性】解密失败：请求被负载均衡打到另一个实例，
// 那边没有这个 key。滚动发布、扩缩容、进程重启都会触发，而单实例本地
// 永远复现不了。生产必须注入 Redis 实现（内部其实是同一个接口）。
//
// 它存在的意义是让适配器的单测不必起 Redis，同时保证测试跑的是与生产
// 完全相同的接口语义（覆盖写、TTL 过期、Delete 幂等）。
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
	now   func() time.Time
}

type memoryItem struct {
	key     string
	expires time.Time
}

// NewMemoryStore 构造内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		items: make(map[string]memoryItem),
		now:   time.Now,
	}
}

var _ Store = (*MemoryStore)(nil)

// Put 写入或覆盖。
func (s *MemoryStore) Put(_ context.Context, appID, openID, key string, ttl time.Duration) error {
	if key == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 覆盖写：同一 (app, open_id) 只保留最新一份密钥。
	s.items[appID+"\x00"+openID] = memoryItem{key: key, expires: s.now().Add(ttl)}
	return nil
}

// Get 读取；过期即视为不存在（惰性删除，不额外起清理协程）。
func (s *MemoryStore) Get(_ context.Context, appID, openID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := appID + "\x00" + openID
	it, ok := s.items[k]
	if !ok {
		return "", ErrNotFound
	}
	if !s.now().Before(it.expires) {
		delete(s.items, k)
		return "", ErrNotFound
	}
	return it.key, nil
}

// Delete 删除，不存在不算错误。
func (s *MemoryStore) Delete(_ context.Context, appID, openID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, appID+"\x00"+openID)
	return nil
}
