// http.go 是 account.Provider 的生产实现：通过 HTTP 调用用户中心。
//
// 为什么契约由【本服务】定义，而不是去适应用户中心现有的接口：
// 用户中心是外部系统，它当前可能没有、或者有几个形态各异的内部接口。
// 本服务需要的几件事（按 id 查、按凭证反查、创建、合并、换绑）各自都有硬性
// 语义要求——强一致读、幂等键、命中多账号必须报错——这些语义没法从
// "对方恰好有这么一个接口"里推出来。所以这里的路径与报文就是
// 【对用户中心的接口要求】，写进联调文档，而不是写成一个可配置的
// 万能适配器。
//
// 对端契约（v1.1）：
//
//	所有路径带应用前缀 /v1/apps/{app_key}/accounts，app_key 取 applications.app_code。
//	理由与取舍见 docs/user-center-mvp-design.md §2：账号空间边界是业务应用（C1），
//	应用不进路径就只能有一个全局账号空间，App2 会登进 App1 的账号。
//
//	GET  {base}/v1/apps/{app_key}/accounts/{user_id}
//	     → 200 {"user_id","status","claims":[{"type","value","source"}],"extra":{}}
//	     → 404 + {"code":"ACCOUNT.NOT_FOUND"}
//
//	GET  {base}/v1/apps/{app_key}/accounts/by-claim?type=phone&value=13800000000
//	     → 200 同上
//	     → 404 没有账号持有该凭证
//	     → 409 + {"code":"ACCOUNT.MULTIPLE"} 命中多个账号（数据不一致）
//	     ⚠️ 必须【强一致读】：这个接口是归并前的最后一道防线（§8.5 P0-6），
//	        读到延迟从库的旧数据会让防线失效。
//
//	POST {base}/v1/apps/{app_key}/accounts
//	     Idempotency-Key: <首次登录的幂等键>
//	     {"claims":[...],"nickname":"","avatar_url":""}
//	     → 200/201 同上（重放同一幂等键必须返回同一账号）
//	     → 404/405/501 且无错误码 → 不提供创建能力 → ACCOUNT.NOT_SUPPORTED
//	     → 409 + ACCOUNT.CLAIM_TAKEN → BIND.IDENTITY_TAKEN
//	     → 409 + ACCOUNT.IDEMPOTENCY_IN_PROGRESS → 可重试
//
//	POST {base}/v1/apps/{app_key}/accounts/merge
//	     Idempotency-Key: <合并幂等键>
//	     {"target_user_id","source_user_id","reason"}
//	     → 200 {"merged","already_merged","discarded_claims":[...],"remote_ref":{}}
//	     → 404 任一端不存在
//	     → 409 + ACCOUNT.MERGE_REJECTED（如 target == source）
//
//	PUT  {base}/v1/apps/{app_key}/accounts/{user_id}/claims/{claim_type}
//	     {"value":"139...","source":"wechat_phone"}
//	     → 200 账号报文（换绑后的状态）
//	     → 409 + ACCOUNT.CLAIM_TAKEN 新值被别的账号占用
//	     → 409 + ACCOUNT.CONFLICT 并发换绑，后到者失败（可重试）
//
//	POST {base}/internal/v1/apps/{app_key}/accounts/{user_id}/close
//	     → 200 {"user_id","status":"closed"}
//	     → 404 + ACCOUNT.NOT_FOUND  账号本就不存在（视为已注销）
//	     ⚠️ 幂等：已 closed 的账号重复调用必须仍返回 200。
//
// 统一错误信封 {"code","message","retryable"}：
// 适配层【优先按 code 翻译，状态码只作兜底】。原先只看状态码时，Create 上
// 任何 409 都被译成"凭证已被占用"——一旦对端用 409 表达别的冲突（幂等处理中），
// 业务方看到的原因就是错的，而且错得很有误导性。
//
// 三条实现纪律（与 §5.5 / C6 对齐）：
//
//  1. 【不重试】。httpx 本身就不带重试，这里也不加。登录链路的失败单位是
//     "整次授权"，由接入方重新发起；补偿任务对 Merge 的重试走的是
//     merge_operations 的幂等键，不是 HTTP 层重试。
//  2. 【错误码翻译】。httpx 是给三方渠道写的，传输层错误用 PROVIDER.*
//     表达；但本接口的调用对象是用户中心，对外契约里出现 PROVIDER.TIMEOUT
//     会让排障的人去翻渠道日志。所以这里统一翻成 ACCOUNT.*。
//  3. 【响应校验】。对端返回的 user_id 为空、status 不在枚举内时拒绝，
//     而不是把垃圾值传进业务层——那时错误会以"账号状态非 active，跳过归并"
//     这种极具误导性的形式出现。
package account

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/httpx"
)

// 对端路径（见文件头的契约）。
const (
	// pathPrefix 是租户前缀。用 /v1 而不是无版本路径：契约会演进，
	// 没有版本号的那一天只能靠"双方同时上线"来改行为。
	pathPrefix = "/v1/apps/"
	// pathPrefixInternal 是内部接口（应用注册、账号注销）的前缀。
	//
	// 分两段不是洁癖：内部接口在部署上只对网关开放、对外不可见，
	// 把它们和业务契约放在同一前缀下，网关就得按路径正则挑出要拦的那几条，
	// 而路径正则一旦漏一条，内部接口就露在网上。
	pathPrefixInternal = "/internal/v1/apps/"
)

// 对端错误码。语义见文件头的映射表与 docs/user-center-mvp-design.md §2.5。
//
// 导出的原因：假对端（internal/testsupport/mockusercenter）要返回同一套码，
// 而它刻意不 import 本包——独立写一份才有"两边漂移能被测出来"的价值，
// 由测试断言两边字面量相等。
const (
	CodeUpstreamNotFound       = "ACCOUNT.NOT_FOUND"
	CodeUpstreamClaimTaken     = "ACCOUNT.CLAIM_TAKEN"
	CodeUpstreamMultiple       = "ACCOUNT.MULTIPLE"
	CodeUpstreamMergeRejected  = "ACCOUNT.MERGE_REJECTED"
	CodeUpstreamIdemInProgress = "ACCOUNT.IDEMPOTENCY_IN_PROGRESS"
	CodeUpstreamConflict       = "ACCOUNT.CONFLICT"
	CodeUpstreamAppUnknown     = "APP.UNKNOWN"
	CodeUpstreamAppDisabled    = "APP.DISABLED"
)

// IdempotencyHeader 是幂等键请求头。
//
// 用标准名而不是自定义 X- 头：这是跨服务写操作的通用约定，用户中心
// 也可能有别的调用方，统一命名比各自发明前缀更省沟通。
const IdempotencyHeader = "Idempotency-Key"

// HTTPConfig 是 HTTPAccountProvider 的配置。
type HTTPConfig struct {
	// BaseURL 是用户中心的根地址，例如 https://uc.internal。
	// 不带末尾斜杠也可以（构造时会裁掉）。
	BaseURL string
	// Token 是服务间鉴权用的 Bearer token。为空时不带 Authorization 头
	// （仅限内网无鉴权的联调环境）。
	Token string
	// Timeout 是单次调用总超时。默认 3s。
	//
	// 为什么不是 5s（httpx 的默认值）：这是【登录链路的同步依赖】，
	// 整条授权链路的预算是 8s，Exchange+UserInfo 已经占掉 5s。
	// 用户中心慢到 3s 还没回，让本次登录失败比拖死整个请求更好。
	Timeout time.Duration
	Logger  *zap.Logger
}

// HTTPProvider 是 account.Provider 的 HTTP 实现。
type HTTPProvider struct {
	baseURL string
	token   string
	client  *httpx.Client
	logger  *zap.Logger
}

var (
	_ domainaccount.Provider      = (*HTTPProvider)(nil)
	_ domainaccount.ClaimReplacer = (*HTTPProvider)(nil)
)

// NewHTTPProvider 构造用户中心客户端。
//
// 配置不完整时返回 CONFIG.INVALID 而不是带着空 base_url 启动：
// 后者会让每一次登录都变成"拼出一个相对 URL 然后失败"，且日志里看不出
// 是配置问题。
func NewHTTPProvider(cfg HTTPConfig) (*HTTPProvider, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errs.New(errs.CodeConfigInvalid,
			"account.provider=http 但 account.http.base_url 为空")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, errs.Wrap(errs.CodeConfigInvalid, "account.http.base_url 不是合法 URL", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errs.Newf(errs.CodeConfigInvalid,
			"account.http.base_url 必须以 http:// 或 https:// 开头，当前为 %q", base)
	}
	if u.Host == "" {
		return nil, errs.New(errs.CodeConfigInvalid, "account.http.base_url 缺少主机名")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	return &HTTPProvider{
		baseURL: base,
		token:   cfg.Token,
		client: httpx.New(httpx.Config{
			Name:         "account-center",
			TotalTimeout: timeout,
			Logger:       cfg.Logger,
		}),
		logger: cfg.Logger,
	}, nil
}

// accountsPath 拼出某应用下的账号集合地址。
func (p *HTTPProvider) accountsPath(appKey string) string {
	return p.baseURL + pathPrefix + url.PathEscape(appKey) + "/accounts"
}

// internalAccountsPath 是"内部接口"的账号路径。
//
// 与 accountsPath 分开而不是加参数：两者属于不同的契约分区（内部 vs 对外），
// 混在一个函数里，调用方很容易顺手传错——而传错的代价是 404，
// 又恰好与"不存在"同码（见 Close 的判定）。
func (p *HTTPProvider) internalAccountsPath(appKey string) string {
	return p.baseURL + pathPrefixInternal + url.PathEscape(appKey) + "/accounts"
}

// Get 按 user_id 查询账号。
func (p *HTTPProvider) Get(ctx context.Context, appKey, userID string) (*domainaccount.Account, error) {
	if err := requireAppKey(appKey, "Get"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		// 空 id 打到对端通常会被路由成"列出所有账号"或 404，
		// 两种都很危险；在本地就拒绝。
		return nil, errs.New(errs.CodeInternal, "查询账号缺少 user_id")
	}
	resp, err := p.call(ctx, http.MethodGet,
		p.accountsPath(appKey)+"/"+url.PathEscape(userID), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return decodeAccount(resp.Raw, "Get")
	}
	return nil, p.classify("Get", resp)
}

// GetByClaim 按已验证凭证反查账号。
//
// ⚠️ 对端必须强一致读（见文件头）。这里的 409 不是"冲突"，是"命中了多个账号"
// ——用户中心的唯一性已经坏了，必须让调用方走人工排查而不是随手挑一个。
func (p *HTTPProvider) GetByClaim(ctx context.Context, appKey string, claim domainaccount.Claim) (*domainaccount.Account, error) {
	if err := requireAppKey(appKey, "GetByClaim"); err != nil {
		return nil, err
	}
	if claim.Type == "" || claim.Value == "" {
		return nil, errs.New(errs.CodeInternal, "凭证反查缺少类型或取值")
	}
	q := url.Values{}
	q.Set("type", claim.Type)
	q.Set("value", claim.Value)

	resp, err := p.call(ctx, http.MethodGet,
		p.accountsPath(appKey)+"/by-claim?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return decodeAccount(resp.Raw, "GetByClaim")
	}
	return nil, p.classify("GetByClaim", resp)
}

// Create 创建账号。
//
// 幂等键是硬要求：首次登录可能因接入方重试而调用两次，没有幂等键就会
// 建出两个账号，而这两个账号此后无法通过任何流程合并回来（用户会看到
// 两个"自己"）。
func (p *HTTPProvider) Create(ctx context.Context, req domainaccount.CreateRequest) (*domainaccount.Account, error) {
	if err := requireAppKey(req.AppKey, "Create"); err != nil {
		return nil, err
	}
	if req.IdempotencyKey == "" {
		return nil, errs.New(errs.CodeInternal, "Create 缺少幂等键")
	}

	body := map[string]any{
		"claims":     claimsToDTO(req.Claims),
		"nickname":   req.Nickname,
		"avatar_url": req.AvatarURL,
	}
	h := map[string]string{IdempotencyHeader: req.IdempotencyKey}

	resp, err := p.call(ctx, http.MethodPost, p.accountsPath(req.AppKey), body, h)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		return decodeAccount(resp.Raw, "Create")

	case resp.StatusCode == http.StatusNotFound,
		resp.StatusCode == http.StatusMethodNotAllowed,
		resp.StatusCode == http.StatusNotImplemented:
		// 三种都可能表示"对端不提供创建能力"。但 404 有第二层含义：
		// 对端实现了该路径，只是请求里的某个东西不存在。
		//
		// 区分办法看有没有错误信封——对端只要回了 code，就说明它认识这个
		// 请求，不是"没这个能力"。判错方向会很糟：本该提示"应用未注册"，
		// 却让业务方去改 on_unbound_login 配置。
		if ue := parseErrorEnvelope(resp.Raw); ue != nil && ue.Code != "" {
			return nil, p.classify("Create", resp)
		}
		return nil, errs.New(errs.CodeAccountNotSupported,
			"用户中心未提供创建账号能力").WithDetail("status", resp.StatusCode)

	default:
		return nil, p.classify("Create", resp)
	}
}

// Merge 把 source 合并进 target。
func (p *HTTPProvider) Merge(ctx context.Context, req domainaccount.MergeRequest) (*domainaccount.MergeResult, error) {
	if err := requireAppKey(req.AppKey, "Merge"); err != nil {
		return nil, err
	}
	if req.IdempotencyKey == "" {
		// 缺幂等键时宁可失败：补偿任务会重试，不幂等的 Merge 会重复迁移数据。
		return nil, errs.New(errs.CodeInternal, "Merge 缺少幂等键（P0-4 要求）")
	}
	if req.TargetUserID == "" || req.SourceUserID == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "合并缺少 target_user_id 或 source_user_id")
	}

	body := map[string]any{
		"target_user_id": req.TargetUserID,
		"source_user_id": req.SourceUserID,
		"reason":         req.Reason,
	}
	h := map[string]string{IdempotencyHeader: req.IdempotencyKey}

	resp, err := p.call(ctx, http.MethodPost, p.accountsPath(req.AppKey)+"/merge", body, h)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, p.classify("Merge", resp)
	}

	var out mergeResultDTO
	if err := json.Unmarshal(resp.Raw, &out); err != nil {
		return nil, errs.Wrap(errs.CodeAccountUnavailable,
			"解析用户中心合并结果失败", err).WithDetail("op", "Merge")
	}
	return &domainaccount.MergeResult{
		Merged:          out.Merged,
		AlreadyMerged:   out.AlreadyMerged,
		DiscardedClaims: claimsFromDTO(out.DiscardedClaims),
		RemoteRef:       out.RemoteRef,
	}, nil
}

// ReplaceClaim 换绑某类型凭证。
//
// 目前没有调用方（P1 才接登录链路的"平台侧手机号变了"识别），但在 P0 就把
// 适配层实现出来：契约已经定了，先让假对端与真实实现对得上，比等到 P1
// 再同时改两边更省事。
func (p *HTTPProvider) ReplaceClaim(ctx context.Context, req domainaccount.ReplaceClaimRequest) (*domainaccount.Account, error) {
	if err := requireAppKey(req.AppKey, "ReplaceClaim"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.UserID) == "" || req.Claim.Type == "" || req.Claim.Value == "" {
		return nil, errs.New(errs.CodeInvalidRequest, "换绑缺少 user_id / claim_type / value")
	}

	body := map[string]any{
		"value":  req.Claim.Value,
		"source": req.Claim.Source,
	}
	resp, err := p.call(ctx, http.MethodPut,
		p.accountsPath(req.AppKey)+"/"+url.PathEscape(req.UserID)+"/claims/"+url.PathEscape(req.Claim.Type),
		body, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return decodeAccount(resp.Raw, "ReplaceClaim")
	}
	return nil, p.classify("ReplaceClaim", resp)
}

// Close 注销账号（把状态置为 closed）。
//
// ⚠️ 路径在 /internal/v1 下，不是 /v1：注销是"内部接口"（对端只在网关上
// 开放给本服务），而按 id 查、建号、换绑是对外契约。这两组混用会得到
// 一个 404，而 404 恰好与"账号本来就不存在"同码——见下面的判定。
func (p *HTTPProvider) Close(ctx context.Context, appKey, userID string) error {
	if err := requireAppKey(appKey, "Close"); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return errs.New(errs.CodeInvalidRequest, "注销缺少 user_id")
	}

	resp, err := p.call(ctx, http.MethodPost,
		p.internalAccountsPath(appKey)+"/"+url.PathEscape(userID)+"/close", nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	err = p.classify("Close", resp)
	if !errors.Is(err, domainaccount.ErrNotFound) {
		return err
	}

	// 只有【带信封的 ACCOUNT.NOT_FOUND】才算"账号本就不存在"。
	//
	// 裸 404 绝不能当成功。它可能来自：路径写错、base_url 少了前缀、
	// 网关没转发、对端版本落后没有这个接口。把这些都当成"已注销"的后果
	// 是——本地数据清干净了、对端账号还活着，接口返回 200，用户以为自己
	// 注销了。这类"静默成功"比直接报错危险得多，因为它不会有人来查。
	//
	// （这不是假设：首版把路径写成 /v1/... 时，实测就是这个表现——对端
	// 404、本地清理照做、响应 200，而 accounts.status 仍是 active。）
	if ue := parseErrorEnvelope(resp.Raw); ue == nil || ue.Code != CodeUpstreamNotFound {
		return p.fail("Close", resp, errs.CodeAccountUnavailable,
			"用户中心未提供注销接口（检查 base_url 与契约版本）", false, nil)
	}
	return nil
}

// --- 内部 ---

// requireAppKey 在本地拦掉空 appKey。
//
// 不拦的后果：拼出 /v1/apps//accounts，对端返回 404，我们译成 ErrNotFound，
// 业务方看到的是"账号不存在"——而真相是调用方少传了一个参数。
// 空租户是那种"不报错、只查错人"的错误，必须在这里挡住。
func requireAppKey(appKey, op string) error {
	if strings.TrimSpace(appKey) == "" {
		return errs.New(errs.CodeInternal, "调用用户中心缺少 app_key").WithDetail("op", op)
	}
	return nil
}

// call 构造并执行一次请求，统一注入鉴权与 JSON 头。
//
// 返回的 Response 可能带任意状态码：状态码的语义由各方法按对端契约判定，
// 这里只负责"传输成功"与"传输失败"的区分。
func (p *HTTPProvider) call(ctx context.Context, method, fullURL string, body any, headers map[string]string) (*httpx.Response, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "序列化用户中心请求失败", err)
		}
		reader = strings.NewReader(string(buf))
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "构造用户中心请求失败", err)
	}
	req.Header.Set("Accept", "application/json")
	// 声明调用方身份，供用户中心的审计记录 actor。
	// 和 trace_id 分工：trace_id 说"这次调用串到哪"，actor 说"记在谁头上"。
	// 用户中心读不到我们的服务名（token 是共用的一把），只能靠这个头。
	req.Header.Set("X-Actor", "social-login")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(ctx, req)
	if err != nil {
		// 传输层错误：httpx 用 PROVIDER.* 表达，这里翻成 ACCOUNT.*。
		return nil, translateTransportError(err)
	}
	return resp, nil
}

// classify 把对端的失败响应翻译成业务语义的错误。
//
// 顺序是刻意的：
//
//  1. 429 / 5xx 先判。它们回答的是"要不要重试"，这个判断不能被对端一个
//     写错的 code 改掉——把 500 译成不可重试，等于把一次上游抖动变成用户的
//     一次登录失败。
//  2. 再看错误信封的 code。这是契约新增的一层：状态码只有 20 来个，而
//     "冲突"有四种完全不同的原因（凭证被占、幂等处理中、合并被拒、数据脏）。
//  3. 最后按状态码兜底，兼容还没实现信封的早期对端。
func (p *HTTPProvider) classify(op string, resp *httpx.Response) error {
	ue := parseErrorEnvelope(resp.Raw)

	if resp.StatusCode == http.StatusTooManyRequests {
		return p.fail(op, resp, errs.CodeRateLimited, "用户中心限流", true, ue)
	}
	if resp.StatusCode >= 500 {
		return p.fail(op, resp, errs.CodeAccountUnavailable, "用户中心不可用", true, ue)
	}

	if ue != nil {
		switch ue.Code {
		case CodeUpstreamNotFound:
			return domainaccount.ErrNotFound
		case CodeUpstreamMultiple:
			return domainaccount.ErrMultipleAccounts
		case CodeUpstreamClaimTaken:
			return p.fail(op, resp, errs.CodeBindIdentityTaken,
				"该凭证已被用户中心的其他账号占用", false, ue)
		case CodeUpstreamMergeRejected:
			return p.fail(op, resp, errs.CodeInvalidRequest,
				"用户中心拒绝了本次合并", false, ue)
		case CodeUpstreamIdemInProgress:
			// 同一幂等键的另一个请求还在处理。这是并发重试的正常现象，
			// 不是故障：等一会儿再来就会拿到同一结果。
			return p.fail(op, resp, errs.CodeAccountUnavailable,
				"同一幂等键的请求正在用户中心处理中，请稍后重试", true, ue)
		case CodeUpstreamConflict:
			return p.fail(op, resp, errs.CodeAccountUnavailable,
				"用户中心并发冲突，请稍后重试", true, ue)
		case CodeUpstreamAppUnknown:
			// 不可重试：应用没注册，重试一百次还是没注册。
			// 文案要指向真正的原因——"该应用未在用户中心注册"，
			// 而不是笼统的"用户中心不可用"，否则运维会去查网络。
			return p.fail(op, resp, errs.CodeAccountUnavailable,
				"该应用未在用户中心注册（检查 app_code 与注册同步任务）", false, ue)
		case CodeUpstreamAppDisabled:
			return p.fail(op, resp, errs.CodeAccountUnavailable,
				"该应用已在用户中心停用", false, ue)
		}
	}

	switch resp.StatusCode {
	case http.StatusNotFound:
		return domainaccount.ErrNotFound
	case http.StatusConflict:
		// 没带 code 的 409：分不清是凭证占用还是数据脏，只能按不可重试
		// 的通用失败处理，并把原始报文带出去让人判断。
		return p.fail(op, resp, errs.CodeAccountUnavailable,
			"用户中心返回 409 但未给出错误码，无法判定原因", false, ue)
	}
	// 其余（含裸 400）：说明请求不符合对端契约，属于我方或联调期问题。
	//
	// 不译成 REQUEST.INVALID——那是对外说"调用方参数错了"，但出错的是
	// 我方对内部的这次调用，业务方无从修改。
	return p.fail(op, resp, errs.CodeAccountUnavailable,
		"用户中心返回了未预期的状态码", false, ue)
}

// fail 组装一个带排障信息的错误。
func (p *HTTPProvider) fail(op string, resp *httpx.Response, code errs.Code, msg string, retryable bool, ue *errorEnvelope) error {
	e := errs.New(code, msg).
		WithDetail("op", op).
		WithDetail("status", resp.StatusCode).
		WithRetryable(retryable)
	if ue != nil && ue.Code != "" {
		e = e.WithDetail("upstream_code", ue.Code)
		if ue.Message != "" {
			e = e.WithDetail("upstream_message", ue.Message)
		}
	}
	if snippet := errorSnippet(resp.Raw); snippet != "" {
		e = e.WithDetail("upstream_error", snippet)
	}
	if p.logger != nil {
		fields := []zap.Field{
			zap.String("op", op),
			zap.Int("status", resp.StatusCode),
			zap.String("mapped_code", string(code)),
		}
		if ue != nil {
			fields = append(fields, zap.String("upstream_code", ue.Code))
		}
		p.logger.Warn("用户中心调用失败", fields...)
	}
	return e
}

// translateTransportError 把渠道语义的传输错误翻成账号语义。
//
// 不翻的后果是排障方向错误：业务方看到 PROVIDER.TIMEOUT 会去查微信/支付宝
// 的健康状况，而真正超时的是用户中心。
//
// ⚠️ 这里刻意【不复用 err 的文案】，而是新建一个干净的错误，把原始错误放进
// detail。原因：httpx 的文案是"无法连接三方平台"，而这条错误的文案会被
// accountsync 写进 applications.uc_sync_error、显示在管理端应用列表里——
// 让运维在"用户中心同步失败"的提示下读到"三方平台"，等于把排障方向带偏。
func translateTransportError(err error) error {
	e, ok := errs.As(err)
	if !ok {
		return errs.New(errs.CodeAccountUnavailable, "调用用户中心失败").
			WithDetail("cause", err.Error())
	}
	// cause 只进 details（管理端与日志可见），不进对外文案。
	withCause := func(msg string, retryable bool) error {
		ne := errs.New(errs.CodeAccountUnavailable, msg).
			WithDetail("cause", e.Message)
		if retryable {
			ne = ne.WithRetryable(true)
		}
		return ne
	}
	switch e.Code {
	case errs.CodeProviderTimeout:
		return withCause("用户中心响应超时", true)
	case errs.CodeProviderUnavailable:
		return withCause("用户中心不可用（连接失败）", e.Retryable)
	case errs.CodeProviderRejected:
		// 传输层不会产生这个码（它来自 4xx 解析），保留兜底。
		return withCause("用户中心拒绝了请求", false)
	default:
		return withCause("调用用户中心失败", false)
	}
}

// decodeAccount 解析并校验账号报文。
//
// 校验 user_id / status 不是多余的：缺字段的响应如果直接放进业务层，
// 会以"账号状态非 active → 跳过归并"的形式出现，看起来像数据问题，
// 实际是对端契约不符。
func decodeAccount(raw []byte, op string) (*domainaccount.Account, error) {
	var dto accountDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return nil, errs.Wrap(errs.CodeAccountUnavailable,
			"解析用户中心账号报文失败", err).WithDetail("op", op)
	}
	if strings.TrimSpace(dto.UserID) == "" {
		return nil, errs.New(errs.CodeAccountUnavailable,
			"用户中心返回的账号缺少 user_id").WithDetail("op", op)
	}
	status := domainaccount.Status(dto.Status)
	if !validStatus(status) {
		return nil, errs.Newf(errs.CodeAccountUnavailable,
			"用户中心返回了未知的账号状态: %q", dto.Status).WithDetail("op", op)
	}
	return &domainaccount.Account{
		UserID: dto.UserID,
		Status: status,
		Extra:  dto.Extra,
		Claims: claimsFromDTO(dto.Claims),
	}, nil
}

// claimsFromDTO 转换凭证列表，顺带丢掉单条脏数据。
//
// 单条脏数据不该让整个账号不可用：跳过并继续。这会影响回源核对的判定
// （少一条就没得比），所以调用侧看到 claims 变少时，问题在对端数据质量。
func claimsFromDTO(in []claimDTO) []domainaccount.Claim {
	out := make([]domainaccount.Claim, 0, len(in))
	for _, c := range in {
		if c.Type == "" || c.Value == "" {
			continue
		}
		out = append(out, domainaccount.Claim{Type: c.Type, Value: c.Value, Source: c.Source})
	}
	return out
}

func validStatus(s domainaccount.Status) bool {
	switch s {
	case domainaccount.StatusActive, domainaccount.StatusFrozen, domainaccount.StatusClosed:
		return true
	}
	return false
}

// errorSnippet 截取对端错误报文用于排障。
//
// 上限 200 字节并折叠换行：错误 details 会进响应体，不能让它变成一个
// 可能含内部信息的大块 HTML（对端 502 时经常返回网关页面）。
func errorSnippet(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	const max = 200
	s := string(raw)
	if len(s) > max {
		s = s[:max] + "…"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}

// --- DTO ---

type accountDTO struct {
	UserID string         `json:"user_id"`
	Status string         `json:"status"`
	Claims []claimDTO     `json:"claims"`
	Extra  map[string]any `json:"extra"`
}

type claimDTO struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type mergeResultDTO struct {
	Merged          bool           `json:"merged"`
	AlreadyMerged   bool           `json:"already_merged"`
	DiscardedClaims []claimDTO     `json:"discarded_claims"`
	RemoteRef       map[string]any `json:"remote_ref"`
}

// errorEnvelope 是对端的统一错误信封。
//
// 容忍 message 缺失、code 缺失：早期对端可能只返回状态码。
// 但 code 缺失时调用方要能察觉（返回 nil 就表示"没有可用信封"）。
type errorEnvelope struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// parseErrorEnvelope 尝试从响应体解析错误信封。
//
// 返回 nil 的条件：不是 JSON 对象、或者对象里没有 code。
// 只看"有没有 code"而不是"能不能解析"：对端的 404 页面（HTML）也能被
// 某些解码器勉强吞掉一部分，按 code 判断才可靠。
func parseErrorEnvelope(raw []byte) *errorEnvelope {
	if len(raw) == 0 {
		return nil
	}
	var e errorEnvelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil
	}
	if strings.TrimSpace(e.Code) == "" {
		return nil
	}
	e.Code = strings.TrimSpace(e.Code)
	return &e
}

func claimsToDTO(claims []domainaccount.Claim) []claimDTO {
	out := make([]claimDTO, 0, len(claims))
	for _, c := range claims {
		out = append(out, claimDTO{Type: c.Type, Value: c.Value, Source: c.Source})
	}
	return out
}
