package identity

// 令牌 scope 取值（架构 §8.1）。
//
// scope 是业务方判断"这个令牌能不能访问业务数据"的唯一依据，因此必须语义明确。
const (
	// ScopeOpenIDProfile 是正常登录成功后授予的完整 scope。
	ScopeOpenIDProfile = "openid profile"
	// ScopeIdentityOnly 是"身份可信但尚未注册"场景下的受限 scope
	// （对应 on_unbound_login = need_register / session_only 两个分支）。
	// 业务方据此只允许走注册引导流程，不允许访问业务数据。
	ScopeIdentityOnly = "identity_only"
)
