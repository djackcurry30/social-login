package domain

import "testing"

// TestNormalizePhone 覆盖 §7 点名的边界。
//
// 这一组用例的价值不在"函数写对了"，而在"两边的归一化规则不会漂移"：
// social-login 的 domain/identity/claim.go 里有一组等价的用例，
// 两边都跑同一批输入。任一侧改了规则，只有一侧的测试会红。
func TestNormalizePhone(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"13800000000", "13800000000"},
		{"+86 138-0000-0000", "13800000000"},
		{"8613800000000", "13800000000"},   // 13 位且 86 开头 → 去前缀
		{"138 0000 0000", "13800000000"},   // 去空格与横线
		{"  13800000000  ", "13800000000"}, // 去首尾空白
		{"008613800000000", "008613800000000"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizePhone(c.in); got != c.want {
			t.Errorf("NormalizePhone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  Foo@Bar.COM ", "foo@bar.com"},
		{"a@b.cn", "a@b.cn"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeEmail(c.in); got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNormalizeIsIdempotent 归一化必须幂等：写入时归一化一次、查询时再归一化一次，
// 若第二次结果不同，就会"建号成功但查不到"。
func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{"+86 138-0000-0000", "8613800000000", " Foo@Bar.COM "} {
		typ := ClaimTypePhone
		if got := Normalize(typ, in); got != Normalize(typ, Normalize(typ, in)) {
			t.Errorf("%q 归一化不幂等: %q → %q", in, got, Normalize(typ, got))
		}
	}
}

func TestValidateClaimValue(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		value   string
		wantErr bool
	}{
		{"正常手机号", ClaimTypePhone, "13800000000", false},
		{"最短 6 位", ClaimTypePhone, "123456", false},
		{"太短", ClaimTypePhone, "12345", true},
		{"空值", ClaimTypePhone, "", true},
		{"超长（16 位）", ClaimTypePhone, "1234567890123456", true},
		{"正常邮箱", ClaimTypeEmail, "a@b.cn", false},
		{"邮箱无 @", ClaimTypeEmail, "abc", true},
		{"邮箱 @ 在结尾", ClaimTypeEmail, "abc@", true},
		{"邮箱 @ 在开头", ClaimTypeEmail, "@abc", true},
		{"不支持的类型", "open_id", "abc", true},
	}
	for _, c := range cases {
		err := ValidateClaimValue(c.typ, c.value)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: ValidateClaimValue(%q, %q) err=%v, wantErr=%v",
				c.name, c.typ, c.value, err, c.wantErr)
		}
	}
}

func TestIsValidClaimType(t *testing.T) {
	for _, ok := range []string{ClaimTypePhone, ClaimTypeEmail} {
		if !IsValidClaimType(ok) {
			t.Errorf("%q 应被支持", ok)
		}
	}
	for _, bad := range []string{"", "union_id", "PHONE", "open_id"} {
		if IsValidClaimType(bad) {
			t.Errorf("%q 不应被支持", bad)
		}
	}
}
