package jwtkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// FileStore 是签名密钥的本地文件持久化。
//
// ⚠️ 这是"没有 KMS 时的可用实现"，不是推荐的长期方案（§8.3 要求私钥由
// KMS / 配置中心托管）。它存在的理由：轮换必须能在重启后保持——
// 如果 rotate 的结果只存在内存里，进程一重启就回到"配置里那把旧密钥"，
// 轮换等于没做，而且 JWKS 会在重启后突然少一把公钥，旧 token 全部验签失败。
//
// 落盘内容分两类：
//
//	signing-keys.json   元数据 + 私钥（PKCS#8 PEM，仅当前签名密钥）
//	                     旧密钥只存公钥（SPKI PEM）——它已经不需要签名，
//	                     继续持有私钥只会扩大泄漏面。
//
// 权限：目录 0700、文件 0600。部署时必须确认该目录不在版本库与备份的
// 公开路径下。
type FileStore struct {
	dir string
}

// NewFileStore 构造文件存储。dir 为空时调用方应改用其它实现。
func NewFileStore(dir string) *FileStore { return &FileStore{dir: dir} }

// Path 返回状态文件路径（供运维核对）。
func (f *FileStore) Path() string { return filepath.Join(f.dir, "signing-keys.json") }

// fileState 是落盘结构。
type fileState struct {
	Version   int       `json:"version"`
	ActiveKID string    `json:"active_kid"`
	Keys      []fileKey `json:"keys"`
}

type fileKey struct {
	KID     string `json:"kid"`
	Private string `json:"private_key_pem,omitempty"`
	Public  string `json:"public_key_pem,omitempty"`
	// CreatedAt 与 DemotedAt 是轮换判定的依据，必须一起落盘。
	CreatedAt time.Time `json:"created_at"`
	DemotedAt time.Time `json:"demoted_at,omitempty"`
}

// Exists 报告状态文件是否已存在。
func (f *FileStore) Exists() bool {
	if f == nil || f.dir == "" {
		return false
	}
	_, err := os.Stat(f.Path())
	return err == nil
}

// Load 读取全部密钥，返回的切片以当前签名密钥开头（NewSigner 的约定）。
func (f *FileStore) Load() ([]Key, error) {
	if f == nil || f.dir == "" {
		return nil, errs.New(errs.CodeConfigInvalid, "未配置签名密钥目录")
	}
	raw, err := os.ReadFile(f.Path())
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "读取签名密钥文件失败", err).
			WithDetail("path", f.Path())
	}
	var st fileState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "解析签名密钥文件失败", err).
			WithDetail("path", f.Path())
	}
	if len(st.Keys) == 0 {
		return nil, errs.New(errs.CodeInternal, "签名密钥文件为空").
			WithDetail("path", f.Path())
	}

	keys := make([]Key, 0, len(st.Keys))
	// 先放 active，保证 NewSigner 把它当作签名密钥。
	for _, want := range []bool{true, false} {
		for _, fk := range st.Keys {
			isActive := fk.KID == st.ActiveKID
			if isActive != want {
				continue
			}
			k := Key{
				KID:       fk.KID,
				CreatedAt: fk.CreatedAt,
				DemotedAt: fk.DemotedAt,
			}
			if fk.Private != "" {
				parsed, perr := ParsePrivatePEMBlock([]byte(fk.Private))
				if perr != nil {
					return nil, perr
				}
				k.Private = parsed
			} else if fk.Public != "" {
				pub, perr := ParsePublicPEM([]byte(fk.Public))
				if perr != nil {
					return nil, perr
				}
				k.Public = pub
			} else {
				return nil, errs.Newf(errs.CodeInternal, "密钥 %s 既无私钥也无公钥", fk.KID)
			}
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Save 持久化当前全部密钥与 active kid。
func (f *FileStore) Save(activeKID string, states []KeyState) error {
	if f == nil || f.dir == "" {
		return errs.New(errs.CodeConfigInvalid, "未配置签名密钥目录")
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return errs.Wrap(errs.CodeInternal, "创建签名密钥目录失败", err).
			WithDetail("dir", f.dir)
	}

	st := fileState{Version: 1, ActiveKID: activeKID}
	for _, s := range states {
		fk := fileKey{KID: s.KID, CreatedAt: s.CreatedAt, DemotedAt: s.DemotedAt}
		switch {
		case s.Private != nil:
			pemBytes, err := MarshalPrivatePEM(s.Private)
			if err != nil {
				return err
			}
			fk.Private = string(pemBytes)
		case s.Public != nil:
			pemBytes, err := MarshalPublicPEM(s.Public)
			if err != nil {
				return err
			}
			fk.Public = string(pemBytes)
		default:
			return errs.Newf(errs.CodeInternal, "密钥 %s 没有任何材料可持久化", s.KID)
		}
		st.Keys = append(st.Keys, fk)
	}

	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "序列化签名密钥失败", err)
	}

	// 先写临时文件再原子替换：直接覆盖时若进程在写一半崩溃，
	// 会留下一个无法解析的文件——那就意味着服务重启后无法签发令牌。
	tmp := f.Path() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return errs.Wrap(errs.CodeInternal, "写入签名密钥临时文件失败", err)
	}
	if err := os.Rename(tmp, f.Path()); err != nil {
		_ = os.Remove(tmp)
		return errs.Wrap(errs.CodeInternal, "替换签名密钥文件失败", err)
	}
	return nil
}
