package wechat

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/sessionkey"
)

// 会话密钥的跨请求存储。
//
// 为什么是包级变量而不是适配器字段：适配器由 init() 在包加载时注册（决策 D7
// 编译期注册 + 运行期查找），那一刻配置、Redis、日志都还不存在，构造函数
// 拿不到任何依赖。bootstrap 在装配完成后调用 ConfigureSessionStore 补上。
// 这与 Registry.SetWrapper 的处理方式一致。
//
// 未注入时行为是"安静跳过持久化"：同一次请求内的手机号解密照常工作
// （session_key 直接从 TokenSet 传下来），只是跨请求解密不可用。
var (
	sessionStoreMu  sync.RWMutex
	sessionStore    sessionkey.Store
	sessionStoreLog *zap.Logger
)

// ConfigureSessionStore 注入会话密钥存储。
//
// store 为 nil 时等价于关闭持久化（单测、或不需要跨请求解密的部署）。
func ConfigureSessionStore(store sessionkey.Store, logger *zap.Logger) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()
	sessionStore = store
	sessionStoreLog = logger
}

func sessionStoreRefs() (sessionkey.Store, *zap.Logger) {
	sessionStoreMu.RLock()
	defer sessionStoreMu.RUnlock()
	return sessionStore, sessionStoreLog
}

// putSessionKey 在 code2Session 成功后落库。
//
// 时序要求：必须在登录响应返回【之前】完成。否则客户端拿到登录结果立刻发
// 第二个请求（上报加密手机号），而负载均衡把它打到另一个实例，那边读不到
// 密钥——这类竞态只在多实例 + 高并发下偶发，本地单实例永远复现不了。
//
// 失败不阻断登录：本次登录本身是有效的，受影响的只是"跨请求解密手机号"
// 这一条路径。但必须留痕，否则会退化成无日志的偶发失败。
func putSessionKey(ctx context.Context, appID, openID, key string, expiresIn int) {
	store, logger := sessionStoreRefs()
	if store == nil || key == "" || openID == "" {
		return
	}
	ttl := time.Duration(expiresIn) * time.Second
	if ttl <= 0 {
		ttl = sessionkey.DefaultTTL
	}
	if err := store.Put(ctx, appID, openID, key, ttl); err != nil {
		if logger != nil {
			// 只记 app_id，不记密钥与 open_id：密钥是能解开手机号的材料。
			logger.Warn("写入会话密钥失败，跨请求手机号解密将不可用",
				zap.Error(err), zap.String("app_id", appID))
		}
	}
}

// loadSessionKey 读取上一次登录写入的密钥；不可用时返回空串。
func loadSessionKey(ctx context.Context, appID, openID string) string {
	store, _ := sessionStoreRefs()
	if store == nil || appID == "" || openID == "" {
		return ""
	}
	key, err := store.Get(ctx, appID, openID)
	if err != nil {
		return ""
	}
	return key
}

// dropSessionKey 用完即弃，缩小密钥在库里的存活窗口。
func dropSessionKey(ctx context.Context, appID, openID string) {
	store, _ := sessionStoreRefs()
	if store == nil || appID == "" || openID == "" {
		return
	}
	_ = store.Delete(ctx, appID, openID)
}
