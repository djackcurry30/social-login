// Package sessionkey 定义"平台会话密钥"的跨请求存储契约。
//
// 只有微信小程序需要它：getPhoneNumber 的 encrypted_data 必须用
// code2Session 返回的 session_key 做 AES-128-CBC 解密，而这个密钥
// 只在一次 code2Session 里给出，下一次登录会换新的。
//
// # 为什么必须跨进程共享
//
// 业务方常见的接法是"先拿 code 换登录态，再单独上报加密手机号"。
// 两次请求在负载均衡下可能落到不同实例：用进程内 map 存，第二次请求
// 就取不到密钥，表现为"偶发解密失败"——单实例本地永远复现不了，
// 滚动发布、扩缩容、进程重启都会触发。所以必须放在 Redis 这类共享存储。
//
// # 为什么不在适配器内部直接连 Redis
//
// 适配器是"编译期注册 + 运行期查找"的（决策 D7），构造时拿不到任何依赖。
// 让它直连 Redis 会把渠道实现和基础设施绑死，且单测必须起 Redis。
// 因此这里只定义端口，由 bootstrap 注入实现；未注入时适配器安静跳过
// 持久化（同请求内的解密仍然照常工作）。
package sessionkey

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound 表示密钥不存在、已过期或已失效。
//
// 调用方必须把它与"用户没有提供手机号"区分开：
// 前者要求客户端重新调用 getPhoneNumber 拿新的 encrypted_data，
// 后者是正常业务结果。混为一谈会让 R4 红线 1（手机号可信）被悄悄绕过——
// 解密失败被降级成"没有手机号"，下游就可能拿一个未经校验的号码继续用。
var ErrNotFound = errors.New("sessionkey: 密钥不存在或已过期")

// DefaultTTL 是密钥的默认存活时间。
//
// 微信不返回 session_key 的明确过期时间（只说"有效期由微信维护，可能因为
// 用户重新登录等原因失效"）。取 2 小时与登录态同量级：足够覆盖"换登录态后
// 立刻上报手机号"的窗口，又不会让一份能解开手机号的密钥长期留在库里。
// 实际 TTL 以渠道返回的 ExpiresIn 为准。
const DefaultTTL = 2 * time.Hour

// Store 是会话密钥的存取端口。
//
// appID 是业务应用标识（app_code），openID 是平台侧的用户标识。
// 两者共同构成作用域：约束 C1 要求账号按应用隔离，不同应用即使用户
// 恰好是同一个微信 openid（同主体多应用），密钥也绝不能串。
type Store interface {
	// Put 写入或覆盖密钥。
	//
	// 必须是【覆盖】而不是追加：session_key 每次登录都会变，两份并存
	// 等于多留了一份能解开历史密文的密钥。TTL <= 0 时用 DefaultTTL。
	Put(ctx context.Context, appID, openID, key string, ttl time.Duration) error

	// Get 读取密钥。不存在时返回 ErrNotFound。
	Get(ctx context.Context, appID, openID string) (string, error)

	// Delete 在解密成功后立即丢弃密钥（用完即弃，缩小泄露窗口）。
	// 不存在不算错误。
	Delete(ctx context.Context, appID, openID string) error
}
