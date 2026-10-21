// Package cache 是 Redis 基础设施：连接管理与一次性票据存储。
//
// Redis 在本服务中的三个用途（架构 §6.3）：
//  1. 一次性票据（state / bind_ticket / auth_code）—— 必须原子"读取即删除"
//  2. 配置缓存与限流计数
//  3. 高危撤销的 jti 黑名单（第四期）
//
// 注意：唯一【不】放 Redis 的是渠道熔断状态。熔断是降级保护机制，不应有强外部
// 依赖——否则 Redis 故障时保护同时失效，用一个可能故障的组件去保护对另一个
// 组件的故障，逻辑是错位的（架构 §5.6.7）。
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Config 是 Redis 连接参数。
type Config struct {
	Addr     string
	Password string
	DB       int
	// PoolSize 连接池大小。票据操作是极轻量的 GET/SET，池不需要很大。
	PoolSize int
}

// NewClient 构造 Redis 客户端并做连通性检查。
func NewClient(ctx context.Context, cfg Config, log *zap.Logger) (*redis.Client, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:6379"
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 20
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
	})
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("Redis 连接就绪", zap.String("addr", cfg.Addr))
	}
	return rdb, nil
}

// Close 关闭客户端。
func Close(rdb *redis.Client) error {
	if rdb == nil {
		return nil
	}
	return rdb.Close()
}

// consumeScript 以单条 Lua 脚本实现"读取即删除"，保证一次性语义的原子性。
//
// 为什么不能用 GET 再 DEL：两步之间进程崩溃，票据仍在 Redis 里，重放窗口依然存在。
// 而 state / auth_code 的防重放正是本机制存在的全部理由。
var consumeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v then
  redis.call('DEL', KEYS[1])
end
return v
`)

// consumeAndDecode 原子取出并反序列化。
// 返回 found=false 表示键不存在（已过期或已被消费）。
func consumeAndDecode(ctx context.Context, rdb *redis.Client, key string, out any) (bool, error) {
	raw, err := consumeScript.Run(ctx, rdb, []string{key}).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return false, nil
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return false, err
	}
	return true, nil
}

// saveJSON 序列化并写入，附带 TTL。
func saveJSON(ctx context.Context, rdb *redis.Client, key string, value any, ttl time.Duration) error {
	buf, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return rdb.Set(ctx, key, buf, ttl).Err()
}

// getJSON 读取并反序列化（不删除）。
//
// 与 consumeAndDecode 分开而不是加个 bool 参数：调用方看到方法名就知道
// 这一步会不会让票据失效。这是"待验证合并票据需要被读两次"的场景前提。
// 返回 found=false 表示键不存在。
func getJSON(ctx context.Context, rdb *redis.Client, key string, out any) (bool, error) {
	raw, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		return false, err
	}
	return true, nil
}
