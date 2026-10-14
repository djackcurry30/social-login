// Package provider 定义渠道适配器（Provider SPI）及其路由键。
//
// 命名约定（架构文首 A10）：本文档中 platform 与 provider 指同一概念，
// 概念层统一用「平台 Platform」；Provider 仅作为"渠道适配器接口"的名字保留。
package provider

import (
	"sort"
	"strings"
)

// 平台枚举（权威定义见架构文首「权威枚举表」）。
const (
	PlatformWeChat        = "wechat"
	PlatformAlipay        = "alipay"
	PlatformApple         = "apple"
	PlatformGenericOAuth2 = "generic_oauth2"
)

// 接入场景枚举。scene 只需在所属平台内唯一。
//
// 治理要求（扩展性 E4）：必须在此集中定义，Admin 写入配置时做白名单校验，
// 防止拼写错误流入数据库；新增场景时同步更新架构文首的枚举表。
const (
	// SceneApp 是移动应用登录。注意：iOS 与 Android【共用】同一个场景与同一份
	// 平台侧 appid，因此它们天然共享同一个 openid，不会分裂成两个账号（规则 2）。
	SceneApp = "app"
	// SceneMiniProgram 是小程序登录（独立 appid）。
	SceneMiniProgram = "mini_program"
	// SceneOfficialAccount 是公众号网页授权。
	SceneOfficialAccount = "official_account"
	// ScenePCQR 是 PC 扫码登录。
	ScenePCQR = "pc_qr"
	// SceneWeb 是通用网页登录（支付宝 / Apple / 通用 OAuth2）。
	SceneWeb = "web"
	// SceneNotify 是服务端通知端点，不是登录场景（Apple）。
	SceneNotify = "notify"
)

// 承载形态（Client）。仅用于遥测与风控，【不参与路由与配置查找】（规则 2）。
const (
	ClientIOS         = "ios"
	ClientAndroid     = "android"
	ClientMiniProgram = "mini_program"
	ClientH5          = "h5"
	ClientWeb         = "web"
	ClientAdmin       = "admin"
	ClientServer      = "server"
)

// AuthMode 是授权请求的意图。
const (
	// ModeLogin 是登录：identity 无活跃绑定时走未绑定分支。
	ModeLogin = "login"
	// ModeBind 是绑定：断言登录态，把 identity 绑到目标账号。
	ModeBind = "bind"
)

// scenesByPlatform 是场景白名单的权威表。
var scenesByPlatform = map[string]map[string]string{
	PlatformWeChat: {
		SceneApp:             "移动应用登录",
		SceneMiniProgram:     "小程序登录",
		SceneOfficialAccount: "公众号网页授权",
		ScenePCQR:            "PC 扫码登录",
	},
	PlatformAlipay: {
		SceneApp:         "App 登录",
		SceneMiniProgram: "小程序登录",
		SceneWeb:         "网页登录",
	},
	PlatformApple: {
		SceneApp:    "iOS 原生登录",
		SceneWeb:    "Web 登录",
		SceneNotify: "服务端通知端点（非登录）",
	},
	// 通用 OAuth2 是配置驱动的标准协议，场景由配置决定，因此不设白名单。
}

// IsValidPlatform 判断平台是否在白名单内。
func IsValidPlatform(platform string) bool {
	switch platform {
	case PlatformWeChat, PlatformAlipay, PlatformApple, PlatformGenericOAuth2:
		return true
	default:
		return false
	}
}

// IsValidScene 判断 (平台, 场景) 组合是否合法（扩展性 E4 的白名单校验）。
// 通用 OAuth2 不设场景白名单：其场景由配置驱动。
func IsValidScene(platform, scene string) bool {
	if scene == "" {
		return false
	}
	if platform == PlatformGenericOAuth2 {
		return true
	}
	scenes, ok := scenesByPlatform[platform]
	if !ok {
		return false
	}
	_, ok = scenes[scene]
	return ok
}

// ScenesOf 返回某平台的全部合法场景，按字典序排列（供 Admin 下拉与校验提示）。
func ScenesOf(platform string) []string {
	scenes, ok := scenesByPlatform[platform]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(scenes))
	for s := range scenes {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SceneName 返回场景的中文名，用于错误提示与文档。
func SceneName(platform, scene string) string {
	if scenes, ok := scenesByPlatform[platform]; ok {
		if n, ok := scenes[scene]; ok {
			return n
		}
	}
	return scene
}

// Key 返回渠道路由键 "platform:scene"。
//
// 注意：路由键【不含承载形态】（规则 2）。iOS 与 Android 都路由到
// "wechat:app"，共用同一份配置；新增鸿蒙版不需要任何服务端改动。
func Key(platform, scene string) string {
	return platform + ":" + scene
}

// SplitKey 拆解路由键。
func SplitKey(key string) (platform, scene string, ok bool) {
	i := strings.IndexByte(key, ':')
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

// IsValidClient 判断承载形态取值是否合法。承载形态不影响路由，
// 因此校验失败只降级为 "unknown"，不应导致请求失败。
func IsValidClient(client string) bool {
	switch client {
	case ClientIOS, ClientAndroid, ClientMiniProgram, ClientH5,
		ClientWeb, ClientAdmin, ClientServer:
		return true
	default:
		return false
	}
}

// NormalizeClient 归一化承载形态；非法值降级为 "unknown"。
func NormalizeClient(client string) string {
	if IsValidClient(client) {
		return client
	}
	return "unknown"
}
