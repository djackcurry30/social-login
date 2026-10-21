package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// unlockScript 只删除"自己持有的"锁。
//
// 比较后再删是必须的：如果本次持有已经过期（TTL 到点被 Redis 清掉），
// 而另一个进程刚拿到同名锁，直接 DEL 会把别人的锁删掉——于是两个进程
// 同时进入合并。这类"锁误删"在慢请求下很常见，不是理论问题。
var unlockScript = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
end
return 0
`)

// MergeLocker 是 merge.Locker 的 Redis 实现。
//
// 为什么不用本地互斥：多副本部署时，同一个账号的两次合并可能落到不同实例。
// 幂等键能防止重复插入，但防不住"两次都调用远端"——而那正是必须避免的
// （用户中心若非严格幂等，重复 Merge 会重复迁移数据）。
type MergeLocker struct {
	rdb *redis.Client
}

// NewMergeLocker 构造分布式锁。
func NewMergeLocker(rdb *redis.Client) *MergeLocker {
	return &MergeLocker{rdb: rdb}
}

var _ merge.Locker = (*MergeLocker)(nil)

// Lock 尝试获取锁。
//
// 锁值用 token 而不是固定字符串，配合 unlockScript 实现"只删自己的锁"。
func (l *MergeLocker) Lock(ctx context.Context, key string, ttl time.Duration) (func(), error) {
	if l.rdb == nil {
		// 未装配 Redis 时退化为无锁：合并本身仍有幂等键兜底，
		// 让服务在无 Redis 的测试装配下也能跑通。
		return func() {}, nil
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	fullKey := "lock:" + key
	token := fmt.Sprintf("%d", time.Now().UnixNano())

	ok, err := l.rdb.SetNX(ctx, fullKey, token, ttl).Result()
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "获取合并锁失败", err)
	}
	if !ok {
		return nil, merge.ErrLocked
	}
	return func() {
		// 解锁用独立的短超时 context：调用方的 ctx 可能已经被取消
		// （例如请求超时），但锁仍然必须释放，否则要等 TTL 自然过期。
		unlockCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = unlockScript.Run(unlockCtx, l.rdb, []string{fullKey}, token).Err()
	}, nil
}
