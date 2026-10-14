package provider

import (
	"sort"
	"sync"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Registry 是渠道注册表。适配器在包 init 时注册，运行期只读查找。
//
// 这样做的收益（决策 D7）：新增渠道 = 新增一个包 + 一行 blank import，
// 【不触碰任何既有文件】，核心编排流程完全不知道 concrete provider 的存在。
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider // key: "platform:scene"
}

// NewRegistry 构造一个空注册表（测试用；生产用 Global()）。
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider, 16)}
}

// Register 注册一个渠道。重复注册同一 (平台, 场景) 返回错误。
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return errs.New(errs.CodeInternal, "注册了空的渠道实现")
	}
	m := p.Metadata()
	if !IsValidPlatform(m.Platform) {
		return errs.Newf(errs.CodeConfigInvalid, "未知平台: %s", m.Platform).
			WithDetail("platform", m.Platform)
	}
	if !IsValidScene(m.Platform, m.Scene) {
		return errs.Newf(errs.CodeConfigInvalid, "平台 %s 下的未知场景: %s", m.Platform, m.Scene).
			WithDetail("platform", m.Platform).
			WithDetail("scene", m.Scene).
			WithDetail("valid_scenes", ScenesOf(m.Platform))
	}
	key := m.Key()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.providers[key]; dup {
		return errs.Newf(errs.CodeInternal, "渠道重复注册: %s", key).WithDetail("key", key)
	}
	r.providers[key] = p
	return nil
}

// MustRegister 注册并 panic on error，供 init() 使用——配置错误应在启动时就暴露。
func (r *Registry) MustRegister(p Provider) {
	if err := r.Register(p); err != nil {
		panic(err)
	}
}

// Lookup 按 (平台, 场景) 查找渠道实现。
func (r *Registry) Lookup(platform, scene string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[Key(platform, scene)]
	if !ok {
		return nil, errs.Newf(errs.CodeProviderNotFound, "渠道未接入: %s:%s", platform, scene).
			WithDetail("platform", platform).
			WithDetail("scene", scene)
	}
	return p, nil
}

// LookupKey 按路由键查找。
func (r *Registry) LookupKey(key string) (Provider, error) {
	platform, scene, ok := SplitKey(key)
	if !ok {
		return nil, errs.Newf(errs.CodeProviderNotFound, "非法的渠道路由键: %s", key).
			WithDetail("key", key)
	}
	return r.Lookup(platform, scene)
}

// List 返回已注册渠道的元信息，按路由键排序。
func (r *Registry) List() []Metadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Metadata, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.Metadata())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Len 返回已注册渠道数量。
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// --- 全局注册表 ---
//
// 各适配器在自己的包内 init() 里调用 provider.MustRegister(...)，
// 由 adapters/adapters.go 统一 blank import 触发。
var global = NewRegistry()

// Register 向全局注册表注册；失败直接 panic（注册错误必须在启动时暴露）。
func Register(p Provider) { global.MustRegister(p) }

// Lookup 在全局注册表中查找。
func Lookup(platform, scene string) (Provider, error) { return global.Lookup(platform, scene) }

// Global 返回全局注册表。
func Global() *Registry { return global }
