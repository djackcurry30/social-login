// Package mockkms 是一个"够真"的假 KMS：实现 crypto/kek_remote.go 文件头约定的
// 两个动作，用一把自己的 AES-256 密钥做包装/解包。
//
// 它存在的理由与 mockusercenter 相同：KMS 是外部依赖，等有了真 KMS 再验
// "切换后登录还能不能跑"，等于把协议映射、缓存、失败降级三件事同时押在那一天。
// 这里有三个用途：
//
//  1. 本地/CI 演练"本地主密钥 → KMS"的切换（含 cmd/keyrewrap 迁移）；
//  2. 演示 DEK 缓存的效果（真实 KMS 不会告诉你被调用了多少次，这里可以统计）；
//  3. 由测试注入失败（5xx / 超时）验证降级路径。
//
// ⚠️ 它【不是】KMS：密钥在进程内存里、无审计、无租户隔离、无 HSM。
// 仅限本地与测试。真实的密钥不出域保证只能来自真 KMS。
package mockkms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

// Server 是假 KMS。
type Server struct {
	master []byte
	// FailStatus 非 0 时所有请求返回该状态（用于验证降级）。
	FailStatus int
	wraps      int64
	unwraps    int64
}

// New 构造假 KMS。master 为 nil 时随机生成一把，并把生成的密钥返回，
// 便于调用方打印出来固定使用。
//
// 为什么要能固定：重启一次就换密钥，等于把"KMS 密钥丢失"这个最严重的故障
// 演示成日常操作——本地演练时用它迁移过的密文会全部解不开。真 KMS 的密钥
// 是持久化的，假实现至少不该在这一点上误导人。
func New(master []byte) (*Server, []byte, error) {
	if len(master) == 0 {
		master = make([]byte, 32)
		if _, err := rand.Read(master); err != nil {
			return nil, nil, err
		}
	} else if len(master) != 32 {
		return nil, nil, fmt.Errorf("master 必须是 32 字节，实际 %d", len(master))
	}
	return &Server{master: master}, master, nil
}

// WrapCount / UnwrapCount 便于测试断言"缓存是否生效"。
func (s *Server) WrapCount() int64   { return atomic.LoadInt64(&s.wraps) }
func (s *Server) UnwrapCount() int64 { return atomic.LoadInt64(&s.unwraps) }

// Handler 返回 http.Handler，便于直接挂到 httptest 或独立进程。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/wrap", s.handleWrap)
	mux.HandleFunc("/v1/unwrap", s.handleUnwrap)
	// /stats 让"DEK 缓存有没有生效"变成可观测的事实，而不是靠猜。
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]int64{
			"wrap":   atomic.LoadInt64(&s.wraps),
			"unwrap": atomic.LoadInt64(&s.unwraps),
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}

func (s *Server) handleWrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	atomic.AddInt64(&s.wraps, 1)
	if s.FailStatus != 0 {
		w.WriteHeader(s.FailStatus)
		return
	}
	body, err := decode(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dek, err := base64.StdEncoding.DecodeString(body["plaintext"])
	if err != nil || len(dek) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"plaintext 非法"}`))
		return
	}
	wrapped, err := s.seal(dek)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"wrapped": base64.StdEncoding.EncodeToString(wrapped)})
}

func (s *Server) handleUnwrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	atomic.AddInt64(&s.unwraps, 1)
	if s.FailStatus != 0 {
		w.WriteHeader(s.FailStatus)
		return
	}
	body, err := decode(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	wrapped, err := base64.StdEncoding.DecodeString(body["wrapped"])
	if err != nil || len(wrapped) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"wrapped 非法"}`))
		return
	}
	dek, err := s.open(wrapped)
	if err != nil {
		// 400 而不是 500：这是"你给的密文不对"，不是 KMS 故障。
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"解包失败"}`))
		return
	}
	writeJSON(w, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)})
}

func (s *Server) seal(plain []byte) ([]byte, error) {
	aead, err := newGCM(s.master)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte("mockkms")), nil
}

func (s *Server) open(wrapped []byte) ([]byte, error) {
	aead, err := newGCM(s.master)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(wrapped) < ns+aead.Overhead() {
		return nil, errors.New("短密文")
	}
	return aead.Open(nil, wrapped[:ns], wrapped[ns:], []byte("mockkms"))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func decode(r *http.Request) (map[string]string, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
