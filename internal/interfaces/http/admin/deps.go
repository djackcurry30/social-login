// Package admin 中的 deps.go：暴露 RouterDeps 给外部装配用。
//
// 为什么需要这一层？为了让主 router（internal/interfaces/http/router.go）
// 显式声明字段是 *admin.AdminDeps 而不是 *admin.Deps：
//
//   - *admin.Deps 直接暴露给业务端 router 容易让"业务端 router"误调到 admin 装配细节
//   - 用 *admin.RouterDeps 让两个名字明显不同：router 的装配 contract 与 admin 内部 contract
//
// 因此这里只保留一个 alias：RouterDeps = Deps。
package admin

// RouterDeps 是 admin 路由依赖装配本装配需要的全部输入。
//
// 它就是 admin.Deps 的别名（type alias）——同包内可以直接用 Deps 写，
// 但跨包引用时统一用 RouterDeps 这个名字，更显式说明"装配 contract"。
type RouterDeps = Deps