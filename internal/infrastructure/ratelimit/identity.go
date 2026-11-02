// Package ratelimit 提供授权流程内部使用的身份维度限流（架构 §6.3 的
// rl:identity:{identityId}）。
//
// 为什么不在接入层的中间件里做：中间件看到的只有 app + IP，而"身份"要等
// 平台返回 open_id、本服务 Upsert 出 identity 之后才知道。所以它只能挂在
// 授权流程内部——代价是平台调用已经发生（那一步无法提前），收益是它拦在
// 用户中心调用与本地写库之前。
//
// 防的是什么：
//
//   - 撞库/暴力绑定：同一身份被反复驱动登录或绑定尝试（脚本重放回调、
//     拿一个泄漏的 open_id 反复试绑定冲突分支）。
//   - 单身份打爆下游：一个异常客户端在一分钟内反复走完整链路时，
//     用户中心的 Create/Get、审计写入、事件投递都会被它占满。
//
// 不防的是什么（这很重要，避免对它产生错误期待）：
//
//   - 分布式撞库（同一批账号换 IP、换身份逐个试）。这需要按客户端 IP /
//     设备指纹做全局风控，属于网关或风控系统的职责，单个身份限流无能为力。
package ratelimit

import (
	"context"
	"strconv"

	"github.com/redis/go-redis/v9"

	pkgratelimit "github.com/djackcurry30/social-login/internal/pkg/ratelimit"
)

// DefaultIdentityPerMinute 是单个身份每分钟的默认上限。
//
// 取 30 的依据：正常用户一分钟内不可能完成 30 次完整的授权往返
// （每次都要跳平台、输密码/扫码）。超过这个量级只可能是脚本重放或
// 前端死循环，两种都该被拦住。阈值偏低的风险是"用户被自己锁住 1 分钟"，
// 而重试一次即可恢复——代价远低于被脚本打穿。
const DefaultIdentityPerMinute = 30

// IdentityLimiter 是身份维度的固定窗口限流器。
type IdentityLimiter struct {
	window    *pkgratelimit.Window
	perMinute int
	enabled   bool
}

// NewIdentityLimiter 构造限流器。
//
// rdb 为 nil 或 enabled=false 时判定恒放行——限流是保护措施，
// 不该成为"没配 Redis 就不能登录"的隐性依赖。
func NewIdentityLimiter(rdb *redis.Client, enabled bool, perMinute int) *IdentityLimiter {
	var c pkgratelimit.Counter
	if rdb != nil {
		c = pkgratelimit.RedisCounter{RDB: rdb}
	}
	return NewIdentityLimiterWithCounter(c, enabled, perMinute)
}

// NewIdentityLimiterWithCounter 供测试注入计数实现。
func NewIdentityLimiterWithCounter(c pkgratelimit.Counter, enabled bool, perMinute int) *IdentityLimiter {
	if perMinute <= 0 {
		perMinute = DefaultIdentityPerMinute
	}
	return &IdentityLimiter{
		window:    pkgratelimit.NewWindow(c),
		perMinute: perMinute,
		enabled:   enabled,
	}
}

// Allow 对某个身份计数并判定。
//
// 返回 (是否放行, 建议重试秒数)。Redis 故障时放行：一次缓存抖动
// 不该让所有正在登录的用户收到 429。
func (l *IdentityLimiter) Allow(ctx context.Context, identityID int64) (bool, int) {
	if l == nil || !l.enabled {
		return true, 0
	}
	res := l.window.Allow(ctx, "rl:identity:"+strconv.FormatInt(identityID, 10), l.perMinute)
	if res.Allowed {
		return true, 0
	}
	return false, res.RetryAfter
}

// PerMinute 返回生效的阈值（供启动日志与排障确认配置真的生效了）。
func (l *IdentityLimiter) PerMinute() int {
	if l == nil {
		return 0
	}
	return l.perMinute
}
