// Package contract 是【跨服务契约的唯一测试交叉点】。
//
// 为什么这个包存在，以及为什么它必须在这里而不在任一服务内部：
//
//	2026-11-02 确认的边界规则是"同一仓库、共用 internal/pkg 通用工具包，
//	但两个服务的业务代码不得互相 import"。所以：
//	  · internal/usercenter/**  只能引用自己 + internal/pkg/**
//	  · internal/{application,domain,infrastructure,interfaces,bootstrap}/**
//	    只能引用自己 + internal/pkg/**
//	  · 而"两边的错误码必须一致"这件事，天然需要同时看到两边
//
// 于是把它放在 test/ 下：test/ 是唯一允许跨服务引用的位置（契约守卫 +
// 端到端验收），它不属于任何一个服务的生产代码，也不参与它们的构建。
//
// 这条边界由 scripts/check-service-boundary.sh 强制；本包是它明确豁免的
// 那一个目录。新增跨服务断言时请放这里，不要放回服务内部。
package contract
