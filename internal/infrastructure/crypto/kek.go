// kek.go 定义信封加密的 KEK（Key Encryption Key）端口。
//
// 为什么要这一层抽象：当前实现把主密钥放在配置里，而生产要求它由 KMS 托管
// （架构 §8.3 / 决策 D6）。如果上层直接依赖"本地主密钥"这个事实，换 KMS 就得
// 改调用方；把"包装/解包数据密钥"抽成一个端口后，换的只是这个端口的实现，
// 密文格式、表结构、业务代码都不动。
//
// 信封加密的分层（本轮才真正落地）：
//
//	KEK（KMS 或本地主密钥）  ──包装──►  DEK（每行一把，随机生成）
//	DEK                     ──加密──►  凭据明文
//
// 关键收益在【轮换】：换 KEK 只需要用新 KEK 重新包装 DEK（几十字节），
// 不必重新加密业务数据、也不必读出明文。旧实现没有 DEK，"换密钥"等于
// 把所有密文解密再加密一遍——迁移面随数据量线性增长，这才是"越晚做越贵"
// 的真实含义。
package crypto

import (
	"context"
	"time"
)

// KEK 是密钥加密密钥。
//
// 实现必须满足：
//   - Wrap/Unwrap 互为逆操作，且对同一 DEK 的多次 Wrap 结果可以不同
//     （内含随机 nonce），调用方不得依赖字节相等。
//   - Unwrap 失败必须返回错误，不得返回空密钥——空 DEK 会让数据用全零密钥
//     加密，那是最坏的一种"静默降级"。
type KEK interface {
	// KeyID 是这个 KEK 的稳定标识，写入 secret_dek_id 列供运维核对。
	KeyID() string
	// Wrap 用 KEK 包装一个数据密钥。
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	// Unwrap 还原数据密钥。
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// LegacyDecrypter 是只为兼容 v1 密文而存在的端口。
//
// v1 密文是"主密钥直接加密数据"（没有 DEK），AAD 是当时的 kekID。它无法用
// KMS 解开——KMS 里根本没有这把直接加密数据的密钥。所以只有本地 KEK 实现它。
//
// 一旦所有行都迁到 v2，这个端口就可以删掉了；保留它是为了让"迁移期"能
// 新旧共存，而不是要求停机切换。
type LegacyDecrypter interface {
	// DecryptLegacy 解开 v1 格式密文。kekID 取配置里当前的主密钥版本，
	// 与写入时一致才能解开（换版本后旧密文本来就解不开，这是 v1 的已知缺陷）。
	DecryptLegacy(ciphertext []byte, kekID string) (string, error)
}

// DefaultKMSTimeout 是单次 KEK 调用的超时。
//
// 5 秒的依据：登录链路总预算 8 秒（§5.7），而 KEK 调用只发生在解密渠道凭据时。
// 比它更长的等待只会把"KMS 慢"变成"登录卡住"，不如快速失败。
const DefaultKMSTimeout = 5 * time.Second
