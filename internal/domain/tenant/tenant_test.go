package tenant

import (
	"strings"
	"testing"
)

// TestPolicyValidateEnforcesConfigConsistency 覆盖架构 §7.5.4 的配置一致性校验。
//
// 这些规则的共同原则是：凡"配置生效但行为不符"一律【拒绝】而非静默降级。
// 静默降级会产生最难排查的一类故障——运维以为开了自动合并，实际没有，
// 而日志里没有任何异常。
func TestPolicyValidateEnforcesConfigConsistency(t *testing.T) {
	t.Parallel()

	base := func(mut func(p *Policy)) Policy {
		p := DefaultPolicy()
		if mut != nil {
			mut(&p)
		}
		return p
	}

	cases := []struct {
		name      string
		policy    Policy
		wantErr   bool
		wantWarn  bool
		errSubstr string
	}{
		{
			name:   "默认配置合法",
			policy: base(nil),
		},
		{
			// 登录期归并是显式开关：配了就要真的生效，所以取值必须能通过校验。
			name: "auto + on_login=claim_verified 合法",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeAuto
				p.Merge.OnLogin = OnLoginClaimVerified
			}),
		},
		{
			// 拼错一个字母如果被放行，归并会静默不生效，而配置看起来是开着的。
			name: "auto + on_login 拼错必须拒绝",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeAuto
				p.Merge.OnLogin = "claim_verify"
			}),
			wantErr:   true,
			errSubstr: "未知的 on_login 取值",
		},
		{
			name: "confirm + verification=none 必须拒绝",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeConfirm
				p.Merge.Verification = VerificationNone
			}),
			wantErr:   true,
			errSubstr: "verification 不可为 none",
		},
		{
			name: "confirm + on_login=claim_verified 必须拒绝",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeConfirm
				p.Merge.OnLogin = OnLoginClaimVerified
			}),
			wantErr:   true,
			errSubstr: "不可为 claim_verified",
		},
		{
			name: "auto + verification=none 必须拒绝（R4 红线 1）",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeAuto
				p.Merge.Verification = VerificationNone
			}),
			wantErr:   true,
			errSubstr: "自动归并的依据必须是平台侧已验证凭证",
		},
		{
			name: "关闭被合并账号通知必须拒绝（R4 红线 2）",
			policy: base(func(p *Policy) {
				p.Merge.NotifySourceAccount = false
			}),
			wantErr:   true,
			errSubstr: "红线",
		},
		{
			name: "未知 merge mode 必须拒绝",
			policy: base(func(p *Policy) {
				p.Merge.Mode = "whatever"
			}),
			wantErr:   true,
			errSubstr: "未知的合并模式",
		},
		{
			name: "manual + on_login 非 off 时归一化并告警",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeManual
				p.Merge.OnLogin = OnLoginClaimVerified
			}),
			wantWarn: true,
		},
		{
			name: "auto + claim_verified 合法",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeAuto
				p.Merge.OnLogin = OnLoginClaimVerified
				p.Merge.Verification = VerificationSMS
			}),
		},
		{
			name: "auto + 跨平台自动合并会告警",
			policy: base(func(p *Policy) {
				p.Merge.Mode = MergeModeAuto
				p.Merge.AllowCrossPlatformAuto = true
			}),
			wantWarn: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.policy.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望校验失败，实际通过")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("错误信息应包含 %q，实际: %v", tc.errSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望校验通过，实际失败: %v", err)
			}
			if tc.wantWarn && len(res.Warnings) == 0 {
				t.Fatalf("期望至少一条告警，实际没有")
			}
		})
	}
}

// TestPolicyRedirectURIWhitelist 覆盖开放重定向防护。
//
// 白名单为空时必须【拒绝所有】请求：失败关闭优于默认放行。
// 一旦这里放行，本服务就成了一个开放重定向器，攻击者可把 auth_code 骗到自己的域名。
func TestPolicyRedirectURIWhitelist(t *testing.T) {
	t.Parallel()

	p := DefaultPolicy()
	if p.IsRedirectURIAllowed("https://a.example.com/cb") {
		t.Fatal("白名单为空时必须拒绝所有回跳地址")
	}

	p.AllowedRedirectURIs = []string{
		"https://app.example.com/callback",
		"https://h5.example.com/",
		"http://localhost:3000/callback",
	}

	allowed := []string{
		"https://app.example.com/callback",
		"https://h5.example.com/",
		"https://h5.example.com/any/deep/path",
		"http://localhost:3000/callback",
	}
	for _, u := range allowed {
		if !p.IsRedirectURIAllowed(u) {
			t.Errorf("应允许: %s", u)
		}
	}

	denied := []string{
		"",
		"https://evil.com/callback",
		// 前缀注入：白名单是 https://h5.example.com/，攻击者用相似域名绕过。
		"https://h5.example.com.evil.com/callback",
		// 精确匹配项必须完全相同。
		"https://app.example.com/callback/extra",
		// 必须带 scheme 与 host。
		"/callback",
		"javascript:alert(1)",
	}
	for _, u := range denied {
		if p.IsRedirectURIAllowed(u) {
			t.Errorf("必须拒绝: %s", u)
		}
	}
}

// TestPolicyNormalizeCannotDefaultSecuritySwitch 说明 Normalize 的边界。
//
// Normalize 能把字符串类字段补成默认值，但【不能】补布尔型安全开关：
// Go 的 bool 零值与"显式配置为 false"无法区分，而两者语义相反。
//
// 因此约定是"调用方从 DefaultPolicy() 出发再覆盖"，从零值出发时 Validate
// 会拒绝——这是失败关闭，不会静默放行。
func TestPolicyNormalizeCannotDefaultSecuritySwitch(t *testing.T) {
	t.Parallel()

	var zero Policy
	zero.Normalize()

	// 字符串类字段被补成了默认值。
	def := DefaultPolicy()
	if zero.OnUnboundLogin != def.OnUnboundLogin {
		t.Errorf("on_unbound_login 应落到默认值 %s，实际 %s", def.OnUnboundLogin, zero.OnUnboundLogin)
	}
	if zero.Merge.Mode != def.Merge.Mode {
		t.Errorf("merge.mode 应落到默认值 %s，实际 %s", def.Merge.Mode, zero.Merge.Mode)
	}

	// 布尔安全开关保持零值 false —— 必须被 Validate 拒绝，而不是被当成"允许关闭通知"。
	if _, err := zero.Validate(); err == nil {
		t.Fatal("从零值出发的策略必须被拒绝（失败关闭），实际通过")
	}
}

// TestDefaultPolicyIsValidAndSafe 验证默认策略本身是合法且最保守的。
func TestDefaultPolicyIsValidAndSafe(t *testing.T) {
	t.Parallel()

	def := DefaultPolicy()
	if _, err := def.Validate(); err != nil {
		t.Fatalf("默认策略必须合法，实际: %v", err)
	}

	// 默认必须是最保守的一档：不自动归并、需要用户确认、短信验证、必须通知。
	if def.Merge.Mode != MergeModeConfirm {
		t.Errorf("默认合并模式应为 confirm（最平衡），实际 %s", def.Merge.Mode)
	}
	if def.Merge.OnLogin != OnLoginOff {
		t.Errorf("默认不得在登录阶段归并，实际 %s", def.Merge.OnLogin)
	}
	if !def.Merge.NotifySourceAccount {
		t.Error("默认必须通知被合并账号（R4 红线 2）")
	}
	if def.OnUnboundLogin != OnUnboundNeedRegister {
		t.Errorf("默认首次登录处置应为 need_register（C4 下本服务不能自己建号），实际 %s", def.OnUnboundLogin)
	}
	if len(def.AllowedRedirectURIs) != 0 {
		t.Error("默认回跳白名单必须为空——由接入方显式配置，不做宽松默认")
	}
}
