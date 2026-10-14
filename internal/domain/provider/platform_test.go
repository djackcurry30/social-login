package provider

import (
	"sort"
	"strings"
	"testing"
)

// TestSceneWhitelist 覆盖扩展性 E4：scene 必须在代码中集中定义，
// 配置写入时做白名单校验，防止拼写错误流入数据库。
//
// 一个拼错的 scene（如 "miniprogram"）在运行时的表现是"渠道未配置"，
// 而排查方向会被误导到配置管理台——实际原因却是代码里少了校验。
func TestSceneWhitelist(t *testing.T) {
	t.Parallel()

	valid := []struct{ platform, scene string }{
		{PlatformWeChat, SceneApp},
		{PlatformWeChat, SceneMiniProgram},
		{PlatformWeChat, SceneOfficialAccount},
		{PlatformWeChat, ScenePCQR},
		{PlatformAlipay, SceneApp},
		{PlatformAlipay, SceneMiniProgram},
		{PlatformAlipay, SceneWeb},
		{PlatformApple, SceneApp},
		{PlatformApple, SceneWeb},
		{PlatformApple, SceneNotify},
		// 通用 OAuth2 是配置驱动的标准协议，场景由配置决定，不设白名单。
		{PlatformGenericOAuth2, "anything"},
	}
	for _, c := range valid {
		if !IsValidScene(c.platform, c.scene) {
			t.Errorf("%s:%s 应为合法场景", c.platform, c.scene)
		}
	}

	invalid := []struct{ platform, scene string }{
		{PlatformWeChat, "miniprogram"}, // 少了下划线
		{PlatformWeChat, "mini_programs"},
		{PlatformWeChat, ""},
		{PlatformAlipay, "pc_qr"},       // 支付宝没有扫码场景
		{PlatformApple, "mini_program"}, // Apple 没有小程序
		{"weixin", SceneApp},            // 平台名拼错
		{"", SceneApp},
	}
	for _, c := range invalid {
		if IsValidScene(c.platform, c.scene) {
			t.Errorf("%s:%s 必须被判为非法场景", c.platform, c.scene)
		}
	}
}

func TestIsValidPlatform(t *testing.T) {
	t.Parallel()

	for _, p := range []string{PlatformWeChat, PlatformAlipay, PlatformApple, PlatformGenericOAuth2} {
		if !IsValidPlatform(p) {
			t.Errorf("%s 应为合法平台", p)
		}
	}
	for _, p := range []string{"", "weixin", "WeChat", "douyin"} {
		if IsValidPlatform(p) {
			t.Errorf("%s 不应为合法平台", p)
		}
	}
}

// TestRoutingKeyNeverContainsClient 是"规则 2"的可执行断言。
//
// 路由键只有 (platform, scene)。iOS 与 Android 必须命中同一个渠道，
// 否则新增一个客户端类型（鸿蒙版）就要在服务端加配置，
// 且同一份平台密钥会被拆成多份，改一次密钥要改多处。
func TestRoutingKeyNeverContainsClient(t *testing.T) {
	t.Parallel()

	key := Key(PlatformWeChat, SceneApp)
	if key != "wechat:app" {
		t.Fatalf("路由键期望 wechat:app，实际 %s", key)
	}
	for _, client := range []string{ClientIOS, ClientAndroid} {
		// 承载形态只做遥测，绝不能出现在路由键里。
		if strings.Contains(key, client) {
			t.Fatalf("路由键不得包含承载形态 %s: %s", client, key)
		}
	}

	platform, scene, ok := SplitKey(key)
	if !ok || platform != PlatformWeChat || scene != SceneApp {
		t.Fatalf("SplitKey 解析失败: %s %s %v", platform, scene, ok)
	}

	bad := []string{"", "wechat", "wechat:", ":app", ":"}
	for _, b := range bad {
		if _, _, ok := SplitKey(b); ok {
			t.Errorf("非法路由键 %q 应解析失败", b)
		}
	}
}

// TestScenesOfIsSortedAndStable 验证下拉数据源稳定，
// 否则管理台的场景列表会随 map 遍历顺序跳动，看起来像"配置在变"。
func TestScenesOfIsSortedAndStable(t *testing.T) {
	t.Parallel()

	first := ScenesOf(PlatformWeChat)
	if len(first) != 4 {
		t.Fatalf("微信应有 4 个场景，实际 %v", first)
	}
	if !sort.StringsAreSorted(first) {
		t.Fatalf("场景列表必须有序，实际 %v", first)
	}
	second := ScenesOf(PlatformWeChat)
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("多次调用必须返回相同顺序: %v vs %v", first, second)
		}
	}
	if ScenesOf("unknown_platform") != nil {
		t.Error("未知平台应返回空列表")
	}
}

func TestNormalizeClient(t *testing.T) {
	t.Parallel()

	if got := NormalizeClient(ClientIOS); got != ClientIOS {
		t.Errorf("合法承载形态应原样返回，实际 %s", got)
	}
	// 承载形态只用于遥测，非法值降级为 unknown 而不是让请求失败——
	// 遥测信息不该有阻断业务的能力。
	for _, bad := range []string{"", "harmony", "IOS", "小程序"} {
		if got := NormalizeClient(bad); got != "unknown" {
			t.Errorf("非法承载形态 %q 应降级为 unknown，实际 %s", bad, got)
		}
	}
}
