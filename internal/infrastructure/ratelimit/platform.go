// Package ratelimit 的渠道日配额（架构 §6.3 的 rl:platform:{platform}:day）。
//
// 为什么需要它：所有三方渠道的开放平台都有日调用上限（微信尤其严格）。
// 不做事先拦截时，超限表现为渠道直接返回错误，用户看到的是"登录失败"——
// 一个本该是"今天额度用完了，明天再来"的可解释状态，变成了"这个应用坏了"。
// 更糟的是超限期间每次请求都还要打一次平台，白白消耗重试预算。
//
// 与 rl:app / rl:identity 的区别：
//
//	那两档保护的是「我们」不被单个调用方打爆；
//	这一档保护的是「渠道配额」不被我们整体用光——它失败时的受害者是全部用户。
package ratelimit

import (
	"context"

	"github.com/redis/go-redis/v9"

	pkgratelimit "github.com/djackcurry30/social-login/internal/pkg/ratelimit"
)

// PlatformQuota 是渠道维度的自然日配额。
type PlatformQuota struct {
	window *pkgratelimit.Window
	limits map[string]int
	// fallback 是未单独配置的渠道用的上限。0 表示不限。
	fallback int
	enabled  bool
}

// NewPlatformQuota 构造配额器。
//
// limits 以平台标识为键（wechat / alipay / apple / generic_oauth2…），
// 值为每日上限，<=0 表示该平台不限。未出现在 map 里的平台取 fallback。
func NewPlatformQuota(rdb *redis.Client, enabled bool, limits map[string]int, fallback int) *PlatformQuota {
	var c pkgratelimit.Counter
	if rdb != nil {
		c = pkgratelimit.RedisCounter{RDB: rdb}
	}
	return NewPlatformQuotaWithCounter(c, enabled, limits, fallback)
}

// NewPlatformQuotaWithCounter 供测试注入计数实现。
func NewPlatformQuotaWithCounter(c pkgratelimit.Counter, enabled bool, limits map[string]int, fallback int) *PlatformQuota {
	cp := make(map[string]int, len(limits))
	for k, v := range limits {
		cp[k] = v
	}
	return &PlatformQuota{
		window:   pkgratelimit.NewWindow(c),
		limits:   cp,
		fallback: fallback,
		enabled:  enabled,
	}
}

// Allow 判定某渠道今日是否还有配额。
//
// 返回 (是否放行, 建议重试秒数)。未启用、未配置上限（<=0）或计数故障时放行：
// 配额是成本保护，不是正确性前提——Redis 挂了不该导致所有登录失败。
func (q *PlatformQuota) Allow(ctx context.Context, platform string) (bool, int) {
	if q == nil || !q.enabled || platform == "" {
		return true, 0
	}
	limit := q.fallback
	if v, ok := q.limits[platform]; ok {
		limit = v
	}
	if limit <= 0 {
		return true, 0
	}
	res := q.window.AllowDaily(ctx, "rl:platform:"+platform, limit)
	if res.Allowed {
		return true, 0
	}
	return false, res.RetryAfter
}

// Limit 返回某渠道生效的上限（0 表示不限），供启动日志与排障确认配置生效。
func (q *PlatformQuota) Limit(platform string) int {
	if q == nil {
		return 0
	}
	if v, ok := q.limits[platform]; ok {
		return v
	}
	return q.fallback
}
