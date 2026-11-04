package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

func mustLocalKEK(t *testing.T, keyID string) (*LocalKEK, []byte) {
	t.Helper()
	master := make([]byte, MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("生成主密钥失败: %v", err)
	}
	kek, err := NewLocalKEK(keyID, master)
	if err != nil {
		t.Fatalf("构造本地 KEK 失败: %v", err)
	}
	return kek, master
}

func mustKM(t *testing.T, kek KEK, opts Options) *KeyManager {
	t.Helper()
	km, err := NewKeyManager(kek, opts)
	if err != nil {
		t.Fatalf("构造 KeyManager 失败: %v", err)
	}
	return km
}

// v1 密文是"主密钥直接加密数据"，AAD 是 kekID。这里手工构造，用于验证
// 迁移期新旧共存——那正是最容易写错的一段。
func buildLegacyCipher(t *testing.T, master []byte, kekID, plaintext string) []byte {
	t.Helper()
	block, err := aes.NewCipher(master)
	if err != nil {
		t.Fatalf("初始化 AES 失败: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("初始化 GCM 失败: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("生成 nonce 失败: %v", err)
	}
	return aead.Seal(nonce, nonce, []byte(plaintext), []byte(kekID))
}

// --- 基本往返 ---

func TestEnvelopeRoundTrip(t *testing.T) {
	kek, _ := mustLocalKEK(t, "kek-v1")
	km := mustKM(t, kek, Options{})

	for _, plain := range []string{"s3cr3t", "", strings.Repeat("长", 5000)} {
		ct, err := km.Encrypt(plain)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}
		if len(ct) == 0 {
			t.Fatal("密文为空")
		}
		got, err := km.Decrypt(ct)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
		if got != plain {
			t.Fatalf("往返不一致：want %q got %q", plain, got)
		}
	}
}

// 同样的明文两次加密必须不同：DEK 与 nonce 都是随机的。
// 若相同，说明 DEK 被复用了——那是信封加密最严重的一类实现错误。
func TestEncryptUsesFreshDEKEachTime(t *testing.T) {
	kek, _ := mustLocalKEK(t, "kek-v1")
	km := mustKM(t, kek, Options{})

	a, _ := km.Encrypt("same-plaintext")
	b, _ := km.Encrypt("same-plaintext")
	if string(a) == string(b) {
		t.Fatal("两次加密结果相同：数据密钥或 nonce 被复用")
	}
}

// 篡改任意一个字节都必须解不开（GCM 的完整性）。
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	kek, _ := mustLocalKEK(t, "kek-v1")
	km := mustKM(t, kek, Options{})
	ct, _ := km.Encrypt("secret")

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := km.Decrypt(tampered); err == nil {
		t.Fatal("篡改后的密文必须解密失败")
	}
}

// 换一把 KEK 解不开：这正是"密文与密钥分离"的证据。
func TestDecryptFailsWithDifferentKEK(t *testing.T) {
	kek1, _ := mustLocalKEK(t, "kek-v1")
	kek2, _ := mustLocalKEK(t, "kek-v2")
	ct, _ := mustKM(t, kek1, Options{}).Encrypt("secret")

	if _, err := mustKM(t, kek2, Options{}).Decrypt(ct); err == nil {
		t.Fatal("用另一把 KEK 竟然解开了")
	}
}

// --- v1 兼容 ---

func TestDecryptLegacyCiphertext(t *testing.T) {
	kek, master := mustLocalKEK(t, "kek-v1")
	km := mustKM(t, kek, Options{})

	legacy := buildLegacyCipher(t, master, "kek-v1", "legacy-secret")
	got, err := km.Decrypt(legacy)
	if err != nil {
		t.Fatalf("v1 密文应能解开: %v", err)
	}
	if got != "legacy-secret" {
		t.Fatalf("v1 解密结果不符: %q", got)
	}
}

// v1 密文的 AAD 绑定了当时的 kekID，换版本后解不开——必须给出可执行的提示，
// 而不是让 GCM 报"认证失败"让人误以为密文损坏。
func TestDecryptLegacyReportsKEKMismatch(t *testing.T) {
	kek, master := mustLocalKEK(t, "kek-v2")
	km := mustKM(t, kek, Options{})

	legacy := buildLegacyCipher(t, master, "kek-v1", "old")
	// 模拟从 secret_dek_id 列读到的历史版本。
	_, err := km.DecryptWithKEKID(legacy, "kek-v1")
	if err == nil {
		t.Fatal("kekID 不匹配时应报错")
	}
	if !strings.Contains(err.Error(), "v1") || !strings.Contains(err.Error(), "keyrewrap") {
		t.Fatalf("错误文案应指明明原因与出路，实际: %v", err)
	}
}

// --- 远程 KMS ---

// fakeKMS 实现 kek_remote.go 文件头约定的两个动作。
type fakeKMS struct {
	srv        *httptest.Server
	wrapCalls  int64
	unwrapCall int64
	// failStatus 非 0 时所有请求返回该状态码。
	failStatus int
	// badKey 为 true 时 unwrap 返回长度不对的密钥。
	badKey bool
	// master 是"KMS 内部的 KEK"，与服务进程完全分离。
	master []byte
	token  string
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	f := &fakeKMS{master: make([]byte, MasterKeySize), token: "kms-test-token"}
	if _, err := rand.Read(f.master); err != nil {
		t.Fatalf("生成 KMS 主密钥失败: %v", err)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.failStatus != 0 {
			w.WriteHeader(f.failStatus)
			_, _ = w.Write([]byte(`{"error":"kms down"}`))
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		switch r.URL.Path {
		case "/v1/wrap":
			atomic.AddInt64(&f.wrapCalls, 1)
			dek, _ := base64.StdEncoding.DecodeString(body["plaintext"])
			wrapped, err := f.seal(dek)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"wrapped": base64.StdEncoding.EncodeToString(wrapped),
			})
		case "/v1/unwrap":
			atomic.AddInt64(&f.unwrapCall, 1)
			if f.badKey {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"plaintext": base64.StdEncoding.EncodeToString([]byte("short")),
				})
				return
			}
			wrapped, _ := base64.StdEncoding.DecodeString(body["wrapped"])
			dek, err := f.open(wrapped)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString(dek),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeKMS) seal(dek []byte) ([]byte, error) {
	aead, err := newGCM(f.master)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, dek, []byte("kms")), nil
}

func (f *fakeKMS) open(wrapped []byte) ([]byte, error) {
	aead, err := newGCM(f.master)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("short")
	}
	// 与 seal 的写入顺序对应：nonce || ciphertext。
	return aead.Open(nil, wrapped[:ns], wrapped[ns:], []byte("kms"))
}

func (f *fakeKMS) remote(t *testing.T, keyID string) *RemoteKEK {
	t.Helper()
	kek, err := NewRemoteKEK(RemoteKEKConfig{
		BaseURL: f.srv.URL,
		KeyID:   keyID,
		Token:   f.token,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造远程 KEK 失败: %v", err)
	}
	return kek
}

func TestRemoteKEKRoundTrip(t *testing.T) {
	kms := newFakeKMS(t)
	km := mustKM(t, kms.remote(t, "kek-kms-1"), Options{})

	ct, err := km.Encrypt("remote-secret")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	got, err := km.Decrypt(ct)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if got != "remote-secret" {
		t.Fatalf("往返不一致: %q", got)
	}
	if atomic.LoadInt64(&kms.wrapCalls) == 0 || atomic.LoadInt64(&kms.unwrapCall) == 0 {
		t.Fatal("应当真的调用了 KMS")
	}
}

// DEK 缓存：同一行反复解密只应打一次 KMS。
// 没有它，每次登录都要多一次 5–20ms 的外部调用。
func TestDEKCacheAvoidsRepeatedUnwrap(t *testing.T) {
	kms := newFakeKMS(t)
	km := mustKM(t, kms.remote(t, "kek-kms-1"), Options{
		DEKCacheTTL:  time.Minute,
		DEKCacheSize: 8,
	})
	ct, _ := km.Encrypt("cached")

	for i := 0; i < 5; i++ {
		if _, err := km.Decrypt(ct); err != nil {
			t.Fatalf("第 %d 次解密失败: %v", i, err)
		}
	}
	// 第一次解密后进缓存，其余 4 次不应再调用 unwrap。
	if n := atomic.LoadInt64(&kms.unwrapCall); n != 1 {
		t.Fatalf("缓存生效时 unwrap 应只调用 1 次，实际 %d 次", n)
	}
}

// 缓存关闭时必须每次都问 KMS——否则"缓存"这件事就变成了隐式行为。
func TestNoCacheCallsKMSEveryTime(t *testing.T) {
	kms := newFakeKMS(t)
	km := mustKM(t, kms.remote(t, "kek-kms-1"), Options{})
	ct, _ := km.Encrypt("uncached")

	for i := 0; i < 3; i++ {
		if _, err := km.Decrypt(ct); err != nil {
			t.Fatalf("第 %d 次解密失败: %v", i, err)
		}
	}
	if n := atomic.LoadInt64(&kms.unwrapCall); n != 3 {
		t.Fatalf("未启用缓存时应每次调用，实际 %d 次", n)
	}
}

func TestRemoteKEKServerErrorIsRetryable(t *testing.T) {
	kms := newFakeKMS(t)
	kms.failStatus = http.StatusServiceUnavailable
	kek := kms.remote(t, "kek-kms-1")

	_, err := kek.Wrap(context.Background(), make([]byte, DEKSize))
	if err == nil {
		t.Fatal("KMS 5xx 应报错")
	}
	if !errs.Retryable(err) {
		t.Fatalf("KMS 5xx 应标记可重试，实际 %v", err)
	}
	if !strings.Contains(err.Error(), "KMS") {
		t.Fatalf("文案应指向 KMS，实际: %v", err)
	}
}

// KMS 返回长度不对的密钥必须拒绝：拿截断的密钥去解数据会得到"解密失败"，
// 而失败点离真正原因很远。
func TestRemoteKEKRejectsWrongDEKLength(t *testing.T) {
	kms := newFakeKMS(t)
	kms.badKey = true
	kek := kms.remote(t, "kek-kms-1")

	_, err := kek.Unwrap(context.Background(), []byte("wrapped"))
	if err == nil {
		t.Fatal("长度不对的 DEK 必须拒绝")
	}
	if !strings.Contains(err.Error(), "长度") {
		t.Fatalf("文案应说明长度问题，实际: %v", err)
	}
}

// 远程 KEK 下遇到 v1 密文：不能装作解开了，也不能只报"解密失败"。
func TestLegacyCipherUnderRemoteKEKIsActionable(t *testing.T) {
	kms := newFakeKMS(t)
	km := mustKM(t, kms.remote(t, "kek-kms-1"), Options{})

	// 造一段 v1 密文（与 KEK 无关，任何 v1 密文都会走到这个分支）。
	master := make([]byte, MasterKeySize)
	legacy := buildLegacyCipher(t, master, "local-kek-v1", "x")

	_, err := km.Decrypt(legacy)
	if err == nil {
		t.Fatal("远程 KEK 无法解 v1 密文，应报错")
	}
	if !strings.Contains(err.Error(), "keyrewrap") {
		t.Fatalf("应指出迁移路径，实际: %v", err)
	}
}

// --- 轮换（rewrap）---

// 这是信封加密存在的理由：换 KEK 只重写 DEK 那几十字节，数据密文一个字节都不动。
func TestRewrapOnlyRewritesWrappedDEK(t *testing.T) {
	from, _ := mustLocalKEK(t, "kek-old")
	to, _ := mustLocalKEK(t, "kek-new")
	km := mustKM(t, from, Options{})

	ct, _ := km.Encrypt("rotate-me")
	rewrapped, err := km.Rewrap(ct, to)
	if err != nil {
		t.Fatalf("rewrap 失败: %v", err)
	}

	// 数据段（DEK 之后的部分）必须逐字节相同：那才叫"没有重新加密数据"。
	oldData := dataSection(t, ct)
	newData := dataSection(t, rewrapped)
	if string(oldData) != string(newData) {
		t.Fatal("数据密文被改写了：rewrap 不应触碰业务数据")
	}

	// 新 KEK 能解，旧 KEK 解不开。
	newKM := mustKM(t, to, Options{})
	if got, err := newKM.Decrypt(rewrapped); err != nil || got != "rotate-me" {
		t.Fatalf("新 KEK 应能解密，err=%v got=%q", err, got)
	}
	if _, err := km.Decrypt(rewrapped); err == nil {
		t.Fatal("旧 KEK 不应再能解开 rewrapped 密文")
	}
}

// v1 → v2 的迁移必须真的换格式（这条路径无法只换包装，必须解明文重加密）。
func TestRewrapUpgradesLegacyFormat(t *testing.T) {
	kek, master := mustLocalKEK(t, "kek-v1")
	km := mustKM(t, kek, Options{})
	legacy := buildLegacyCipher(t, master, "kek-v1", "legacy-plain")

	if looksLikeV2(legacy) {
		t.Fatal("前置条件错误：构造出来的不是 v1 密文")
	}
	upgraded, err := km.Rewrap(legacy, kek)
	if err != nil {
		t.Fatalf("升级失败: %v", err)
	}
	if !looksLikeV2(upgraded) {
		t.Fatal("迁移后必须是 v2 格式")
	}
	if got, err := km.Decrypt(upgraded); err != nil || got != "legacy-plain" {
		t.Fatalf("迁移后解密失败: err=%v got=%q", err, got)
	}
}

// dataSection 返回密文中 DEK 之后的部分（nonce + 数据密文）。
func dataSection(t *testing.T, blob []byte) []byte {
	t.Helper()
	const headerLen = len(blobMagic) + 2
	if len(blob) < headerLen {
		t.Fatalf("密文过短")
	}
	dekLen := int(blob[len(blobMagic)])<<8 | int(blob[len(blobMagic)+1])
	start := headerLen + dekLen
	if len(blob) < start {
		t.Fatalf("密文头部越界")
	}
	return blob[start:]
}
