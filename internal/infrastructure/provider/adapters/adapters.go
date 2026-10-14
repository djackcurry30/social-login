// Package adapters 通过 blank import 触发各渠道适配器的编译期注册。
//
// 这是决策 D7 的接线点：新增渠道时，只需新建一个适配器包（内部 init() 自行
// 调用 provider.Register），然后在本文件加一行 blank import。
// 【不需要触碰任何其他既有文件】——核心编排流程完全不知道 concrete provider 的存在。
//
// 也可以直接 import 各适配器包并用其 New(logger) 构造带日志的实例，
// 但注册表的默认装载走这里，保证"忘记接线"在编译期就能通过 go vet 发现
// （unused import 会报错）。
package adapters

import (
	// 通用 OAuth2（配置驱动）。第一期验收即用它接入自建 OAuth2 测试服务。
	_ "github.com/17track/social-login/internal/infrastructure/provider/adapters/generic_oauth2"
	// 后续渠道在此追加，每个渠道一行：
	//   _ ".../adapters/wechat"   // 第二期：app / mini_program / official_account / pc_qr
	//   _ ".../adapters/alipay"   // 第二期：app / mini_program / web
	//   _ ".../adapters/apple"    // 第二期（约束 C2 必做）
)
