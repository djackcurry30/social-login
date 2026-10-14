package identity

import "testing"

func TestNormalizePhone(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"13800138000":    "13800138000",
		"+8613800138000": "13800138000",
		"8613800138000":  "13800138000",
		"138 0013 8000":  "13800138000",
		"(138)0013-8000": "13800138000",
		"":               "",
		"   ":            "",
	}
	for in, want := range cases {
		if got := NormalizePhone(in); got != want {
			t.Errorf("NormalizePhone(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestNormalizePhoneCrossChannelConsistency 说明归一化为什么是归并的前提。
//
// 同一个手机号经不同渠道返回的格式不同：微信小程序带国家码、支付宝不带。
// 如果归一化不一致，"按手机号归并"会静默失效——两个人不会被合并成一个人，
// 而是同一个人的两条凭证被当成两条不同的记录。
func TestNormalizePhoneCrossChannelConsistency(t *testing.T) {
	t.Parallel()

	fromWeChat := "+86 138-0013-8000"
	fromAlipay := "13800138000"

	if NormalizePhone(fromWeChat) != NormalizePhone(fromAlipay) {
		t.Fatalf("不同渠道的同号必须归一化为同一个值: %q vs %q",
			NormalizePhone(fromWeChat), NormalizePhone(fromAlipay))
	}
}

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"  User@Example.COM ": "user@example.com",
		"user@example.com":    "user@example.com",
		"":                    "",
	}
	for in, want := range cases {
		if got := NormalizeEmail(in); got != want {
			t.Errorf("NormalizeEmail(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestTrustedSourceWhitelist 验证 R4 红线 1 的白名单。
//
// 这张名单是安全边界本身，不是配置项：如果允许用户手填的手机号参与归并，
// 攻击者只需在注册时填上受害者的手机号，下次登录就会被自动归并进受害者账号。
func TestTrustedSourceWhitelist(t *testing.T) {
	t.Parallel()

	trusted := []string{SourceWeChatPhone, SourceAlipayPhone, SourceSMSVerified, SourceAppleEmail}
	for _, s := range trusted {
		if !IsTrustedSource(s) {
			t.Errorf("%s 应属于可信来源", s)
		}
		if !IsValidSource(s) {
			t.Errorf("%s 应属于合法枚举", s)
		}
	}

	if IsTrustedSource(SourceManual) {
		t.Error("manual（用户手填）绝不可作为归并依据")
	}
	if !IsValidSource(SourceManual) {
		t.Error("manual 仍是合法枚举（会被记录，只是不参与归并）")
	}
	if IsTrustedSource("sms") {
		t.Error("sms 是 v0.7 的旧枚举，应已统一为 sms_verified；未知来源必须不可信")
	}
	if IsTrustedSource("") {
		t.Error("空来源必须不可信")
	}
}
