// Package authflow 是统一授权流程的用例编排（架构 §5）。
//
// 这是本服务的核心链路：/authorize → （三方授权）→ /callback → 签发一次性 auth_code。
// 它依赖的是 identitysource.Source 抽象而非 provider.Provider（决策 D8），
// 因此将来引入上游 IdP 时本包不需要改动。
//
// 约束 C4 带来的关键分支：remote 模式下本服务无法自己产出账号，因此当身份
// 没有活跃绑定时，默认返回 AUTH.NEED_REGISTER + 一次性 bind_ticket，由业务方
// 引导用户注册/登录后完成绑定（架构 §5.2）。
package authflow

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	appmerge "github.com/djackcurry30/social-login/internal/application/merge"
	"github.com/djackcurry30/social-login/internal/application/tenantconfig"
	"github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/audit"
	"github.com/djackcurry30/social-login/internal/domain/binding"
	"github.com/djackcurry30/social-login/internal/domain/identity"
	"github.com/djackcurry30/social-login/internal/domain/identitysource"
	"github.com/djackcurry30/social-login/internal/domain/provider"
	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/pkg/reqmeta"
)

// Config 是流程配置。
type Config struct {
	// CallbackBaseURL 是本服务对外可访问的基地址，用于拼出三方回调地址。
	// 例：https://auth.example.com
	CallbackBaseURL string
	// ExchangeTimeout 是 Exchange + UserInfo 的独立超时。
	//
	// 这一层超时存在的意义（架构 §5.7 第 3 条）：入站请求可能已被调用方取消
	// （用户断网），但 Exchange 一旦发出就无法撤销——授权码可能已被平台消费。
	// 因此必须让这次调用跑完并落库，否则会出现"code 没了、token 也没拿到"。
	ExchangeTimeout time.Duration
}

// Deps 是依赖集合。
type Deps struct {
	Tenant     *tenantconfig.Service
	Sources    *identitysource.Registry
	Tickets    ticket.Store
	Identities identity.Repository
	Claims     identity.ClaimRepository
	Hasher     identity.ClaimHasher
	Bindings   binding.Repository
	Accounts   account.Provider
	Audit      audit.Writer
	Logger     *zap.Logger
	// Merge 是账号合并能力（第三期，§7.2 / §7.3）。
	//
	// 定义成接口而不是具体类型：授权流程是最核心的链路，不该因为合并包的
	// 内部演进被牵连；而且三条冲突分支（auto / confirm / manual）可以用
	// 假实现覆盖，不必拉起数据库。
	//
	// 为 nil 时冲突一律按"拒绝"处理——不允许因为少装一个依赖就静默放行。
	Merge MergeExecutor
}

// MergeExecutor 是账号合并的端口（实现见 application/merge）。
type MergeExecutor interface {
	Execute(ctx context.Context, req appmerge.Request) (*appmerge.Result, error)
}

// Service 是授权流程服务。
type Service struct {
	cfg  Config
	deps Deps
}

// New 构造服务。
func New(cfg Config, deps Deps) *Service {
	if cfg.ExchangeTimeout <= 0 {
		// 架构 §5.5 的链路预算：整条授权链路 8s，其中 Exchange+UserInfo 占大头。
		cfg.ExchangeTimeout = 5 * time.Second
	}
	return &Service{cfg: cfg, deps: deps}
}

// --- 授权发起 ---

// AuthorizeInput 是 /v1/authorize 的入参。
type AuthorizeInput struct {
	AppCode   string
	Platform  string
	Scene     string
	ConfigKey string
	// Client 是承载形态，仅用于遥测与审计，【不参与路由】（规则 2）。
	Client string
	// Mode 是 login | bind。
	Mode string
	// RedirectURI 是业务方希望回调后跳回的地址。必须命中应用白名单。
	RedirectURI string
	// BusinessState 是业务侧透传的 state，本服务只原样回传、不做解释。
	BusinessState       string
	CodeChallenge       string
	CodeChallengeMethod string
	// AuthenticatedUserID 是 bind 模式下当前登录用户（由接入层从 access_token 解出）。
	// login 模式下必须为空——登录时用户还没证明对任何账号的控制权。
	AuthenticatedUserID string
	// ResponseMode 是 redirect | json。
	ResponseMode string
}

// AuthorizeOutput 是 /v1/authorize 的结果。
type AuthorizeOutput struct {
	// RedirectURL 是三方授权地址。
	RedirectURL string
	// Immediate 为 true 表示该渠道无授权页（如微信小程序），
	// 需由前端调用 SDK 取 code 后直接回调 /v1/oauth/callback/{platform}。
	Immediate bool
	Params    map[string]string
	// State 是本服务的票据 ID，便于排障时把前端日志与后端日志对上。
	State string
}

// Authorize 生成三方授权跳转地址。
func (s *Service) Authorize(ctx context.Context, in AuthorizeInput) (*AuthorizeOutput, error) {
	mode := in.Mode
	if mode == "" {
		mode = provider.ModeLogin
	}
	if mode != provider.ModeLogin && mode != provider.ModeBind {
		return nil, errs.Newf(errs.CodeInvalidRequest, "非法的 mode: %s", mode).
			WithDetail("valid", []string{provider.ModeLogin, provider.ModeBind})
	}
	// login 模式下一律不携带已登录用户。
	//
	// 这条规则不是洁癖：登录时用户尚未证明对任何账号的控制权，若此时允许
	// 指定绑定目标，就等于开了一道"把任意三方身份挂到任意账号"的后门。
	if mode == provider.ModeLogin && in.AuthenticatedUserID != "" {
		return nil, errs.New(errs.CodeInvalidRequest, "登录模式不允许指定绑定目标账号")
	}
	if mode == provider.ModeBind && in.AuthenticatedUserID == "" {
		return nil, errs.New(errs.CodeUnauthorized, "绑定模式需要已登录的访问令牌")
	}
	if !provider.IsValidScene(in.Platform, in.Scene) {
		return nil, errs.Newf(errs.CodeInvalidRequest, "不支持的接入场景: %s:%s", in.Platform, in.Scene).
			WithDetail("valid_scenes", provider.ScenesOf(in.Platform))
	}

	app, err := s.deps.Tenant.Application(ctx, in.AppCode)
	if err != nil {
		return nil, err
	}

	// 开放重定向防护：回跳地址必须命中白名单。
	//
	// 这里刻意区分两种失败，因为它们指向完全不同的责任方与处置动作：
	//
	//	白名单为空        → 是【我们的配置问题】，返回 5xx 并要求运维介入
	//	地址不在白名单内  → 是【调用方的请求问题】，返回 4xx，调用方自己改参数
	//
	// 把后者也报成 5xx 会让每一次调用方拼错参数都变成一次值班告警，
	// 真实故障反而被噪声淹没。反过来，把前者报成 4xx 会让"应用没配白名单"
	// 这个必须我们修的配置缺陷被当成调用方的问题而被忽略。
	if !app.Policy.IsRedirectURIAllowed(in.RedirectURI) {
		if len(app.Policy.AllowedRedirectURIs) == 0 {
			return nil, errs.New(errs.CodeAuthInvalidConfig,
				"该应用未配置 redirect_uri 白名单，出于安全考虑拒绝所有授权请求").
				WithDetail("app_id", app.AppCode).
				WithDetail("hint", "请在 applications.policy.allowed_redirect_uris 中配置允许的回跳地址")
		}
		return nil, errs.New(errs.CodeInvalidRequest, "redirect_uri 不在应用白名单内").
			WithDetail("app_id", app.AppCode)
	}

	ch, err := s.deps.Tenant.Channel(ctx, app.ID, in.Platform, in.Scene, in.ConfigKey)
	if err != nil {
		return nil, err
	}
	src, err := s.deps.Sources.Lookup(in.Platform, in.Scene)
	if err != nil {
		return nil, err
	}

	state := ids.New(ids.PrefixTicket)
	// nonce 只对声明了该能力的平台生成（当前为 Apple）。
	// 不无差别生成，是因为多余的 nonce 会让 state 票据变长、且平台不校验时毫无收益。
	nonce := ""
	if strings.EqualFold(in.Platform, provider.PlatformApple) {
		nonce = ids.New("nonce")
	}

	tc := &ticket.Context{
		State:               state,
		AppID:               app.ID,
		AppCode:             app.AppCode,
		Platform:            in.Platform,
		Scene:               in.Scene,
		ConfigKey:           ch.Config.ConfigKey,
		Client:              provider.NormalizeClient(in.Client),
		Mode:                mode,
		RedirectURI:         in.RedirectURI,
		BusinessState:       in.BusinessState,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Nonce:               nonce,
		BindExternalUserID:  in.AuthenticatedUserID,
		CreatedAt:           time.Now().UTC(),
	}
	if err := s.deps.Tickets.SaveContext(ctx, tc, ticket.TTLContext); err != nil {
		return nil, err
	}

	res, err := src.BeginAuth(ctx, provider.AuthorizeRequest{
		AppID:     app.AppCode,
		Platform:  in.Platform,
		Scene:     in.Scene,
		ConfigKey: ch.Config.ConfigKey,
		Client:    tc.Client,
		Mode:      mode,
		// 传给三方平台的 redirect_uri 是【本服务的回调地址】，不是业务方地址。
		// 两者混淆是接入期最常见的错误：业务方地址是我们回跳的目标，
		// 而三方只认我们自己的回调。
		RedirectURI:         s.callbackURL(in.Platform),
		State:               state,
		BusinessState:       in.BusinessState,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Nonce:               nonce,
		Creds:               ch.Creds,
	})
	if err != nil {
		return nil, err
	}

	return &AuthorizeOutput{
		RedirectURL: res.URL,
		Immediate:   res.Immediate,
		Params:      res.Params,
		State:       state,
	}, nil
}

// callbackURL 拼出本服务的三方回调地址。
//
// 路径固定为 /v1/oauth/callback/{platform}（架构 §5.2：全平台只有一个回调地址，
// 上下文由 state 票据还原），这样平台侧配置量不随渠道数量增长。
func (s *Service) callbackURL(platform string) string {
	base := strings.TrimRight(s.cfg.CallbackBaseURL, "/")
	return base + "/v1/oauth/callback/" + platform
}

// --- 回调 ---

// CallbackInput 是 /v1/oauth/callback/{platform} 的入参。
type CallbackInput struct {
	// Platform 来自路径参数，仅用于与票据交叉校验——权威值以票据为准。
	Platform string
	Query    url.Values
	Body     []byte
	Header   http.Header
}

// CallbackOutput 是回调结果。
//
// 设计要点：回调【一定】回跳业务方，即使是失败也带 error 参数回跳，
// 而不是给用户一个 500 页面——用户看到的是业务方的错误提示，而不是我们的。
type CallbackOutput struct {
	// RedirectURL 是最终回跳地址（含 code 或 error 参数）。
	RedirectURL string
	// ErrorCode 非空表示流程失败。
	ErrorCode        string
	ErrorDescription string
	Retryable        bool

	// 成功时的结果（同时供 JSON 响应模式与测试断言使用）。
	AuthCode       string
	ExternalUserID string
	IdentityID     int64
	Scope          string
	NeedRegister   bool
	BindTicket     string
	Profile        map[string]any
	// Hint 承载"检测到同手机号已有账号"一类的非阻断提示（on_login=detect_only）。
	Hint string

	BusinessState string
	Platform      string
	Scene         string

	// Cause 是内部原因，供接入层记日志，【不外发】。
	Cause error
}

// Callback 处理三方回调。
func (s *Service) Callback(ctx context.Context, in CallbackInput) (*CallbackOutput, error) {
	state := in.Query.Get("state")
	if state == "" {
		return nil, errs.New(errs.CodeAuthInvalidState, "回调缺少 state 参数")
	}
	tc, err := s.deps.Tickets.ConsumeContext(ctx, state)
	if err != nil {
		if errors.Is(err, ticket.ErrContextExpired) {
			return nil, errs.New(errs.CodeAuthInvalidState,
				"授权上下文不存在或已过期，请重新发起授权").
				WithDetail("reason", "ticket_expired")
		}
		return nil, err
	}

	// 票据里的 platform 是权威值。路径参数与它不一致说明有人在拼接 URL，
	// 这属于攻击特征而非用户误操作。
	if in.Platform != "" && !strings.EqualFold(in.Platform, tc.Platform) {
		return nil, errs.New(errs.CodeAuthInvalidState, "回调平台与授权上下文不一致")
	}

	out, err := s.handleCallback(ctx, tc, in)
	if err == nil {
		return out, nil
	}

	// 票据已消费，因此我们知道该往哪儿回跳——把错误带回业务方，
	// 同时把内部原因留在 Cause 里供日志记录。
	e := errs.From(err)
	failed := s.redirectError(tc, e)
	failed.Cause = err
	return failed, nil
}

// exchangeExtraKeys 是允许透传给适配器的平台私有回调参数白名单。
//
// 为什么不把整个 Query 塞进 Extra：
//  1. 回调里还有 state / code 等敏感值，适配器不需要、也不该看到；
//  2. 白名单让"谁能读到什么"是显式的，新增平台时需要主动登记，
//     而不是被动接收一切（那种设计迟早会把某平台的 token 带进另一平台的日志）。
var exchangeExtraKeys = []string{
	// 微信小程序 getPhoneNumber：旧版加密数据 + 新版一次性 code
	"encrypted_data", "iv", "phone_code",
	// Apple / OIDC：id_token 与首次授权才返回的 user（含 name / email）
	"id_token", "user",
	// 公众号网页授权可能回传的 scope
	"scope",
}

func exchangeExtras(q url.Values) map[string]string {
	if len(q) == 0 {
		return nil
	}
	out := make(map[string]string, len(exchangeExtraKeys))
	for _, k := range exchangeExtraKeys {
		if v := q.Get(k); v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Service) handleCallback(ctx context.Context, tc *ticket.Context, in CallbackInput) (*CallbackOutput, error) {
	meta := reqmeta.From(ctx)
	started := time.Now()

	// 三方返回了错误（如用户点了拒绝授权）。
	if pe := in.Query.Get("error"); pe != "" {
		desc := in.Query.Get("error_description")
		return nil, errs.Newf(errs.CodeProviderRejected, "三方授权被拒绝: %s", pe).
			WithDetail("provider_error", pe).
			WithDetail("provider_error_description", desc)
	}
	code := in.Query.Get("code")
	if code == "" {
		return nil, errs.New(errs.CodeProviderRejected, "回调缺少 code 参数")
	}

	app, err := s.deps.Tenant.Application(ctx, tc.AppCode)
	if err != nil {
		return nil, err
	}
	ch, err := s.deps.Tenant.Channel(ctx, app.ID, tc.Platform, tc.Scene, tc.ConfigKey)
	if err != nil {
		return nil, err
	}
	src, err := s.deps.Sources.Lookup(tc.Platform, tc.Scene)
	if err != nil {
		return nil, err
	}

	// 回调验签（Apple / 支付宝需要；通用 OAuth2 返回 nil 即视为无需验签）。
	if verifier, ok := src.(identitysource.CallbackVerifier); ok {
		if err := verifier.VerifyCallback(ctx, &provider.CallbackPayload{
			Platform: tc.Platform,
			Scene:    tc.Scene,
			Query:    in.Query,
			Body:     in.Body,
			Header:   in.Header,
		}); err != nil {
			return nil, err
		}
	}

	// 取消隔离：Exchange 一旦发出就不可撤销，必须让它跑完并落库（架构 §5.7）。
	exchangeCtx, cancel := httpx.Detach(ctx, s.cfg.ExchangeTimeout)
	defer cancel()

	user, _, err := src.Authenticate(exchangeCtx, provider.ExchangeRequest{
		AppID:        app.AppCode,
		Platform:     tc.Platform,
		Scene:        tc.Scene,
		ConfigKey:    tc.ConfigKey,
		Creds:        ch.Creds,
		Code:         code,
		State:        tc.State,
		RedirectURI:  s.callbackURL(tc.Platform),
		CodeVerifier: tc.CodeChallenge, // PKCE 的 verifier 由接入层在回调入参中带上
		Nonce:        tc.Nonce,
		Extra:        exchangeExtras(in.Query),
	})
	if err != nil {
		s.auditLogin(ctx, app.ID, 0, "", tc, audit.ResultFailure, errs.CodeOf(err), meta, started)
		return nil, err
	}
	if user.OpenID == "" {
		return nil, errs.New(errs.CodeProviderRejected, "三方未返回用户标识")
	}

	idn, err := s.deps.Identities.Upsert(ctx, identity.UpsertInput{
		AppID:         app.ID,
		Platform:      tc.Platform,
		ProviderAppID: ch.Config.ProviderAppID,
		OpenID:        user.OpenID,
		UnionID:       user.UnionID,
		// 约束 C3：identity_key = open_id（unionid 不可用）。
		IdentityKey: user.OpenID,
		Profile:     user.ProfileSnapshot(),
		At:          time.Now().UTC(),
	})
	if err != nil {
		s.auditLogin(ctx, app.ID, 0, "", tc, audit.ResultFailure, errs.CodeOf(err), meta, started)
		return nil, err
	}

	// 归并依据落库（第一期为第二/三期的归并能力准备数据）。
	//
	// 注意 persisted 只含"本次写入成功的哈希凭证"，不含明文；而用户中心需要的
	// 是明文（它要落库成账号的手机号），因此单独用 userAccountClaims(user)
	// 从 ExternalUser 构造，并在本函数作用域内用完即弃。
	_, conflicts, err := s.persistClaims(ctx, app.ID, idn.ID, user)
	if err != nil {
		s.auditLogin(ctx, app.ID, idn.ID, "", tc, audit.ResultFailure, errs.CodeOf(err), meta, started)
		return nil, err
	}

	out := &CallbackOutput{
		Platform:      tc.Platform,
		Scene:         tc.Scene,
		BusinessState: tc.BusinessState,
		IdentityID:    idn.ID,
		Profile:       user.ProfileSnapshot(),
	}
	if len(conflicts) > 0 {
		// 冲突不是错误：C5 下"同一手机号被另一个身份验证过"是设计预期内的状态，
		// 只是需要提示业务方可以引导用户合并（需求 R1）。
		out.Hint = "same_claim_exists"
	}

	switch tc.Mode {
	case provider.ModeBind:
		return s.finishBind(ctx, app, tc, idn, out, meta, started)
	default:
		return s.finishLogin(ctx, app, tc, idn, out,
			userAccountClaims(user), len(conflicts), meta, started)
	}
}
