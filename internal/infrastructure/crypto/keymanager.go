// Package crypto 提供渠道凭据的信封加密与凭证哈希。
//
// 密文格式（v2，本轮起）：
//
//	"SLK2" | dekLen(uint16, 大端) | wrappedDEK | nonce(12) | ciphertext+tag
//
// 数据用每行随机生成的 DEK（32 字节）加密，DEK 再由 KEK 包装后与数据密文
// 存在同一列里。这样换 KEK 只需要重新包装 DEK，不必碰数据本身。
//
// v1 兼容：旧密文是"主密钥直接加密数据"，没有 DEK、以 kekID 作 AAD。
// Decrypt 通过魔数区分两种格式，迁移期可以新旧共存；`cmd/keyrewrap` 负责
// 把 v1 就地升级为 v2。一旦全量迁移完成，v1 分支即可删除。
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/djackcurry30/social-login/internal/domain/tenant"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

const (
	// MasterKeySize 是主密钥长度（AES-256）。
	MasterKeySize = 32
	// DEKSize 是每行数据密钥的长度。与主密钥同长度：AES-256。
	DEKSize = 32

	// blobMagic 标记 v2 密文。
	//
	// 用 4 字节魔数区分 v1/v2：v1 的首字节是随机 nonce，撞上这 4 个字节的
	// 概率是 2^-32；即便撞上，v2 解包也会立刻失败，代码会回退去试 v1。
	// 这比"加一列 format_version"更轻：不需要迁移，也不需要双写。
	blobMagic = "SLK2"

	// aadDEK 是包装 DEK 时的附加认证数据，固定值。
	//
	// 刻意不含 KEK 的 keyID：DEK 密文会在轮换时被 rewrap（换 KEK、保留数据密文），
	// 若把 keyID 绑进 AAD，换密钥就得连数据一起重算，"轮换只包装几十字节"
	// 这个核心收益就没了。
	aadDEK = "social-login/dek/v2"
)

// aadData 是加密数据时的 AAD，固定为格式标识。
//
// 同样不含 keyID，理由同上：数据密文在 KEK 轮换后必须仍然可解。
var aadData = []byte(blobMagic)

// Options 是 KeyManager 的运行参数。
type Options struct {
	// Timeout 是单次 KEK 调用超时，留空取 DefaultKMSTimeout。
	Timeout time.Duration
	// DEKCacheTTL 是解包后 DEK 的内存缓存时长。0 表示不缓存。
	//
	// 仅对远程 KEK 有意义：本地 KEK 解包只是一次 AES，缓存反而多一次查表与
	// 一份内存里的密钥副本。远程 KMS 每次 5–20ms，而渠道凭据在每次登录时
	// 都要解密——不缓存等于把 KMS 变成登录链路上的同步依赖。
	DEKCacheTTL time.Duration
	// DEKCacheSize 是缓存条数上限，留空取 512。
	DEKCacheSize int
}

// KeyManager 是上层使用的信封加解密器。
type KeyManager struct {
	kek     KEK
	legacy  LegacyDecrypter
	timeout time.Duration

	cache *dekCache
}

// NewKeyManager 构造信封加密器。
//
// 签名从 (kekID, masterKey) 改为 (keK, opts)：主密钥不再是唯一形态，
// 但上层只认这个类型，看不到具体是本地密钥还是 KMS。
func NewKeyManager(kek KEK, opts Options) (*KeyManager, error) {
	if kek == nil {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "缺少 KEK 实现")
	}
	if kek.KeyID() == "" {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "KEK 的 keyID 不能为空")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultKMSTimeout
	}
	km := &KeyManager{kek: kek, timeout: opts.Timeout}
	// 只有本地 KEK 能解 v1 密文（v1 是主密钥直接加密数据，KMS 里没有那把密钥）。
	if l, ok := kek.(LegacyDecrypter); ok {
		km.legacy = l
	}
	if opts.DEKCacheTTL > 0 {
		size := opts.DEKCacheSize
		if size <= 0 {
			size = 512
		}
		km.cache = newDEKCache(size, opts.DEKCacheTTL)
	}
	return km, nil
}

// KEKID 返回当前 KEK 的标识，写入 app_provider_configs.secret_dek_id。
func (k *KeyManager) KEKID() string { return k.kek.KeyID() }

// KEK 返回底层 KEK，供迁移工具把密文换到另一把 KEK 时使用。
//
// 暴露它意味着"可以拿到密钥"——这在本包里是可接受的：迁移工具本来就需要
// 两把 KEK 同时在手，而它已经能读到全部密文。
func (k *KeyManager) KEK() KEK { return k.kek }

// IsV2 判断一段密文是否已是 v2（信封）格式。
//
// 迁移工具需要它来统计"还有多少行是旧格式"，从而在切换 KEK 之前确认迁移完成。
func IsV2(ciphertext []byte) bool { return looksLikeV2(ciphertext) }

// Encrypt 加密明文，返回 v2 密文。
//
// 调用方写入 secret_dek_id 的值仍取 KEKID()。列名没改（避免一次跨服务改表），
// 但语义已经从"主密钥版本"变成"包装这把 DEK 的 KEK"。
func (k *KeyManager) Encrypt(plaintext string) ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成数据密钥失败", err)
	}
	defer zero(dek)

	wrapped, err := k.wrap(context.Background(), dek)
	if err != nil {
		return nil, err
	}

	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成随机数失败", err)
	}
	sealed := aead.Seal(nil, nonce, []byte(plaintext), aadData)

	out := make([]byte, 0, len(blobMagic)+2+len(wrapped)+len(nonce)+len(sealed))
	out = append(out, blobMagic...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wrapped)))
	out = append(out, lenBuf[:]...)
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt 解密 v2 或 v1 密文。
//
// 对 v1 密文，它只能假定"写入时用的就是当前 KEK"。有 secret_dek_id 列的
// 调用方应当改用 DecryptWithKEKID——那才能给出"由哪把密钥加密"的准确判断。
func (k *KeyManager) Decrypt(ciphertext []byte) (string, error) {
	return k.DecryptWithKEKID(ciphertext, k.kek.KeyID())
}

// DecryptWithKEKID 在已知"这行由哪把 KEK 加密"时解密。
//
// storedKEKID 来自 secret_dek_id 列。它对 v2 密文没有意义（DEK 自带包装，
// 里面有 KEK 的标识），只用于 v1：v1 的 AAD 就是当时的 kekID，用它预先比对
// 才能把"主密钥换过了"与"密文损坏"区分开——这两种故障的处置完全不同。
func (k *KeyManager) DecryptWithKEKID(ciphertext []byte, storedKEKID string) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	if !looksLikeV2(ciphertext) {
		return k.decryptLegacy(ciphertext, storedKEKID)
	}
	plain, err := k.decryptV2(ciphertext)
	if err == nil {
		return plain, nil
	}
	// 魔数撞车（v1 随机 nonce 恰好以 "SLK2" 开头，2^-32）：回退去试 v1，
	// 而不是直接把这条凭据判死。
	if k.legacy != nil {
		if legacy, lerr := k.decryptLegacy(ciphertext, storedKEKID); lerr == nil {
			return legacy, nil
		}
	}
	return "", err
}

func (k *KeyManager) decryptV2(ciphertext []byte) (string, error) {
	const headerLen = len(blobMagic) + 2
	if len(ciphertext) < headerLen {
		return "", errs.New(errs.CodeAuthInvalidConfig, "凭据密文格式非法（头部不完整）")
	}
	dekLen := int(binary.BigEndian.Uint16(ciphertext[len(blobMagic):headerLen]))
	if dekLen <= 0 || len(ciphertext) < headerLen+dekLen {
		return "", errs.New(errs.CodeAuthInvalidConfig, "凭据密文格式非法（数据密钥长度越界）")
	}
	wrapped := ciphertext[headerLen : headerLen+dekLen]
	rest := ciphertext[headerLen+dekLen:]

	dek, err := k.cachedUnwrap(wrapped)
	if err != nil {
		return "", err
	}
	defer zero(dek)

	aead, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	if len(rest) < aead.NonceSize()+aead.Overhead() {
		return "", errs.New(errs.CodeAuthInvalidConfig, "凭据密文格式非法（密文过短）")
	}
	ns := aead.NonceSize()
	plain, err := aead.Open(nil, rest[:ns], rest[ns:], aadData)
	if err != nil {
		return "", errs.Wrap(errs.CodeAuthInvalidConfig, "凭据解密失败（数据密钥不匹配或密文损坏）", err)
	}
	return string(plain), nil
}

// decryptLegacy 处理 v1 密文。
//
// 没有 DEK 就无法脱离主密钥解密，因此远程 KEK 部署下必须先把数据迁完：
// 这里直接给可执行的提示，而不是抛一个 GCM 校验失败。
func (k *KeyManager) decryptLegacy(ciphertext []byte, storedKEKID string) (string, error) {
	if k.legacy == nil {
		return "", errs.New(errs.CodeAuthInvalidConfig,
			"该凭据是旧格式（v1，主密钥直接加密），当前 KEK 为远程 KMS 无法解开；请先运行 cmd/keyrewrap 迁移")
	}
	plain, err := k.legacy.DecryptLegacy(ciphertext, storedKEKID)
	if err != nil {
		return "", err
	}
	return plain, nil
}

// Resolve 实现 tenant.SecretResolver：把渠道配置中的密文解成明文。
//
// previous 用于密钥轮换过渡期（扩展性 E6）：平台侧新旧 secret 同时有效时，
// 校验失败可以再用上一版重试一次。
func (k *KeyManager) Resolve(cfg *tenant.ProviderConfig) (current string, previous string, err error) {
	if cfg == nil {
		return "", "", errs.New(errs.CodeAuthInvalidConfig, "渠道配置为空")
	}
	if len(cfg.SecretCipher) == 0 {
		// 无凭据的渠道是合法的（如 PKCE + 公开客户端、自定义 OAuth2 无需 secret）。
		return "", "", nil
	}
	current, err = k.DecryptWithKEKID(cfg.SecretCipher, cfg.SecretDEKID)
	if err != nil {
		return "", "", err
	}
	if len(cfg.SecretCipherPrev) > 0 {
		if prev, perr := k.DecryptWithKEKID(cfg.SecretCipherPrev, cfg.SecretDEKID); perr == nil {
			previous = prev
		}
		// 上一版解不开不是错误：可能用了不同的 KEK，只影响轮换过渡期能力。
	}
	return current, previous, nil
}

// Rewrap 把一段密文从当前 KEK 换到另一把 KEK。
//
// 只重写 DEK 那几十字节，数据密文原样保留——这是信封加密存在的理由。
// 返回 nil 表示无需处理（空密文或已经是目标 KEK 包装的）。
//
// 对 v1 密文，必须先用 from 解出明文、再用 to 重新加密（无法只换包装）：
// 那正是"没有 DEK 的代价"，也是迁移工具的额外分支。
func (k *KeyManager) Rewrap(ciphertext []byte, to KEK) ([]byte, error) {
	if len(ciphertext) == 0 || to == nil {
		return ciphertext, nil
	}
	if !looksLikeV2(ciphertext) {
		// v1 → v2：解明文、用 to 重新走一遍 Encrypt。
		plain, err := k.decryptLegacy(ciphertext, k.kek.KeyID())
		if err != nil {
			return nil, err
		}
		return rebuildWith(plain, to)
	}
	const headerLen = len(blobMagic) + 2
	dekLen := int(binary.BigEndian.Uint16(ciphertext[len(blobMagic):headerLen]))
	if dekLen <= 0 || len(ciphertext) < headerLen+dekLen {
		return nil, errs.New(errs.CodeAuthInvalidConfig, "凭据密文格式非法（数据密钥长度越界）")
	}
	wrapped := ciphertext[headerLen : headerLen+dekLen]
	rest := ciphertext[headerLen+dekLen:]

	dek, err := k.unwrapWith(context.Background(), k.kek, wrapped)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	newWrapped, err := wrapWith(context.Background(), to, dek, k.timeout)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, headerLen+len(newWrapped)+len(rest))
	out = append(out, blobMagic...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(newWrapped)))
	out = append(out, lenBuf[:]...)
	out = append(out, newWrapped...)
	out = append(out, rest...)
	return out, nil
}

// --- 内部 ---

func looksLikeV2(b []byte) bool {
	return len(b) >= len(blobMagic) && string(b[:len(blobMagic)]) == blobMagic
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "初始化加密算法失败", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "初始化 GCM 失败", err)
	}
	return aead, nil
}

func (k *KeyManager) wrap(ctx context.Context, dek []byte) ([]byte, error) {
	return wrapWith(ctx, k.kek, dek, k.timeout)
}

func wrapWith(ctx context.Context, kek KEK, dek []byte, timeout time.Duration) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	wrapped, err := kek.Wrap(callCtx, dek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) == 0 {
		return nil, errs.New(errs.CodeInternal, "KEK 返回了空的包装结果")
	}
	if len(wrapped) > 0xFFFF {
		// uint16 长度字段装不下：与其静默截断，不如在写入时就失败。
		// 正常 KMS 的包装结果远小于 64KB（通常几百字节）。
		return nil, errs.Newf(errs.CodeInternal, "被包装的数据密钥过长（%d 字节），超出格式上限", len(wrapped))
	}
	return wrapped, nil
}

func (k *KeyManager) unwrapWith(ctx context.Context, kek KEK, wrapped []byte) ([]byte, error) {
	return unwrapWith(ctx, kek, wrapped, k.timeout)
}

func unwrapWith(ctx context.Context, kek KEK, wrapped []byte, timeout time.Duration) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dek, err := kek.Unwrap(callCtx, wrapped)
	if err != nil {
		return nil, err
	}
	if len(dek) != DEKSize {
		return nil, errs.Newf(errs.CodeAuthInvalidConfig,
			"数据密钥长度应为 %d 字节，实际 %d", DEKSize, len(dek))
	}
	return dek, nil
}

// cachedUnwrap 走缓存解包。
func (k *KeyManager) cachedUnwrap(wrapped []byte) ([]byte, error) {
	if k.cache == nil {
		return k.unwrapWith(context.Background(), k.kek, wrapped)
	}
	sum := sha256.Sum256(wrapped)
	if dek, ok := k.cache.get(sum); ok {
		return dek, nil
	}
	dek, err := k.unwrapWith(context.Background(), k.kek, wrapped)
	if err != nil {
		return nil, err
	}
	k.cache.put(sum, dek)
	return dek, nil
}

// zero 清掉内存里的密钥副本。
//
// Go 的优化器理论上可能把这次清零优化掉，但它仍然有实际意义：在崩溃转储与
// 内存快照里，已清零的区域不会残留密钥。真正的保证要靠 KMS 侧的密钥不出域。
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// dekCache 是带容量上限与 TTL 的 DEK 缓存。
//
// 为什么缓存 DEK 而不是明文：DEK 是"数据密钥"，泄漏它的后果与泄漏主密钥不同
// （它只能解一条记录）；而缓存明文会把凭据的明文寿命从"一次调用"拉长到"一个 TTL"。
type dekCache struct {
	mu      sync.Mutex
	items   map[[32]byte]dekEntry
	order   [][32]byte
	size    int
	ttl     time.Duration
	lastGC  time.Time
	nowFunc func() time.Time
}

type dekEntry struct {
	dek     []byte
	expires time.Time
}

func newDEKCache(size int, ttl time.Duration) *dekCache {
	return &dekCache{
		items:   make(map[[32]byte]dekEntry, size),
		order:   make([][32]byte, 0, size),
		size:    size,
		ttl:     ttl,
		nowFunc: time.Now,
	}
}

func (c *dekCache) get(key [32]byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return nil, false
	}
	if c.nowFunc().After(e.expires) {
		delete(c.items, key)
		return nil, false
	}
	// 返回副本：调用方会 defer zero(dek)，直接给缓存里的切片会被清零。
	out := make([]byte, len(e.dek))
	copy(out, e.dek)
	return out, true
}

func (c *dekCache) put(key [32]byte, dek []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFunc()
	// 惰性清理：只在过期量明显时扫一遍，避免每次 put 都 O(n)。
	if now.Sub(c.lastGC) > c.ttl {
		for k, e := range c.items {
			if now.After(e.expires) {
				delete(c.items, k)
			}
		}
		c.lastGC = now
	}
	if _, exists := c.items[key]; !exists {
		if len(c.items) >= c.size {
			// 满了就丢最早插入的一条（order 只增不减，容忍少量陈旧条目）。
			for len(c.order) > 0 {
				oldest := c.order[0]
				c.order = c.order[1:]
				if _, ok := c.items[oldest]; ok {
					delete(c.items, oldest)
					break
				}
			}
		}
		c.order = append(c.order, key)
	}
	cp := make([]byte, len(dek))
	copy(cp, dek)
	c.items[key] = dekEntry{dek: cp, expires: now.Add(c.ttl)}
}

// GenerateMasterKey 生成一把随机主密钥，供开发环境引导使用。
// 生产环境的主密钥应由 KMS 或密钥管理系统的引导流程提供，不通过本函数。
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	return key, nil
}

// EncodeMasterKey 把主密钥编码为配置文件中可安全书写的 Base64 字符串。
func EncodeMasterKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// DecodeMasterKey 解析配置文件中的主密钥。
func DecodeMasterKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errs.Wrap(errs.CodeAuthInvalidConfig, "主密钥不是合法的 Base64", err)
	}
	if len(key) != MasterKeySize {
		return nil, errs.Newf(errs.CodeAuthInvalidConfig,
			"主密钥长度必须为 %d 字节，当前 %d 字节", MasterKeySize, len(key))
	}
	return key, nil
}

// rebuildWith 用 to 这把 KEK 重新加密明文（v1 → v2 迁移路径）。
func rebuildWith(plaintext string, to KEK) ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成数据密钥失败", err)
	}
	defer zero(dek)
	wrapped, err := wrapWith(context.Background(), to, dek, DefaultKMSTimeout)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "生成随机数失败", err)
	}
	sealed := aead.Seal(nil, nonce, []byte(plaintext), aadData)
	out := make([]byte, 0, len(blobMagic)+2+len(wrapped)+len(nonce)+len(sealed))
	out = append(out, blobMagic...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wrapped)))
	out = append(out, lenBuf[:]...)
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}
