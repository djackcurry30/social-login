// Package mockusercenter 是一个按契约实现的假用户中心。
//
// 2026-11-02 起真实对端已存在（cmd/usercenter，见 docs/user-center-mvp-design.md §14），
// 这个假对端仍然保留，理由变了但价值没变：
//
//   - 它能被故意弄坏（fault injection）。契约里最难验的不是顺利路径，而是
//     "对端超时 / 5xx / 命中多账号"时我们怎么退化——这些用真实对端很难复现，
//     而在真实对端上造这些故障需要改它的代码或拔网线。
//   - 它记录每一次调用（含 app_key 与幂等键），让测试能断言"我们确实带了
//     租户前缀和幂等键"，而不是只断言"登录成功了"。真实对端也能记，但那是
//     跨服务断言，脆且慢。
//   - 它跑在进程内（httptest），让 `go test ./...` 不依赖外部服务。
//
// 真实对端的价值在另一头：强一致读、幂等的真实实现、跨服务事务、容量与延迟。
// 两者分工见 docs/user-center-integration.md：
//
//	本包   验"我方适配层 + 编排"（快、可注入故障）
//	真实对端 验"最后一段"（test/acceptance/account_http_real_test.go，
//	         设 TEST_USER_CENTER_URL 才跑）
//
// 定位仍是【契约的可执行版本】：路径、报文、状态码、幂等键语义、错误信封，
// 全部对齐 infrastructure/account/http.go 文件头写的契约（v1.1）与
// docs/user-center-mvp-design.md §2。改契约时两边一起改，否则它就成了
// "测试通过但线上不对"的源头。
//
// ⚠️ 没有任何安全设计（明文比较 token、内存态、无审计）。仅限测试与本地联调。
package mockusercenter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 账号状态，取值与 domain/account 的枚举一致。
// 故意用字符串常量而不是 import 领域包：mock 要能独立发现"我方枚举改了但
// mock 没跟上"这种问题，直接复用常量会把这个信号吞掉。
const (
	StatusActive = "active"
	StatusFrozen = "frozen"
	StatusClosed = "closed"
	// StatusDisabled 是【应用】的状态（不是账号的），用于应用注册。
	StatusDisabled = "disabled"
)

// 错误码。
//
// 与 infrastructure/account 的 CodeUpstream* 【刻意各写一份】：复用常量会让
// "两边漂移"永远测不出来，而跨服务契约最怕的就是"我方改了码，对端没改"。
// 由 account_errorcodes_test.go 断言两份字面量相等。
const (
	CodeNotFound       = "ACCOUNT.NOT_FOUND"
	CodeClaimTaken     = "ACCOUNT.CLAIM_TAKEN"
	CodeMultiple       = "ACCOUNT.MULTIPLE"
	CodeMergeRejected  = "ACCOUNT.MERGE_REJECTED"
	CodeIdemInProgress = "ACCOUNT.IDEMPOTENCY_IN_PROGRESS"
	CodeConflict       = "ACCOUNT.CONFLICT"
	CodeAppUnknown     = "APP.UNKNOWN"
	CodeAppDisabled    = "APP.DISABLED"
	CodeInvalid        = "INVALID.REQUEST"
)

// 故障模式。
const (
	// FaultNone 表示无故障。
	FaultNone = ""
	// FaultServerError 返回 500：验证我方是否按"可重试的上游故障"处理。
	FaultServerError = "500"
	// FaultRateLimited 返回 429：验证是否映射成 RATE_LIMITED 而不是可用性故障。
	FaultRateLimited = "429"
	// FaultTimeout 睡过客户端超时再返回：验证超时被翻译成 ACCOUNT.UNAVAILABLE。
	FaultTimeout = "timeout"
	// FaultSlow 延迟后正常返回：验证慢但对端仍然成功时我方不误判。
	FaultSlow = "slow"
	// FaultMultiAccount 让 by-claim 返回 409：验证"命中多账号"走人工排查而不是择一。
	FaultMultiAccount = "multi"
	// FaultIdemInProgress 让写操作返回 409 + IDEMPOTENCY_IN_PROGRESS：
	// 验证我方把它当成可重试，而不是"凭证被占用"。
	FaultIdemInProgress = "idem_in_progress"
)

// 操作名，用于按操作注入故障与记录调用。
const (
	OpGet     = "get"
	OpByClaim = "by_claim"
	OpCreate  = "create"
	OpMerge   = "merge"
	OpReplace = "replace"
	// OpRegister 是应用注册（POST /internal/v1/apps）。
	OpRegister = "register"
	// OpAll 表示对所有操作生效。
	OpAll = "*"
)

// IdempotencyHeader 必须与 account.IdempotencyHeader 一致。
const IdempotencyHeader = "Idempotency-Key"

// Claim 是一条已验证凭证。
type Claim struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// Account 是账号视图，字段与契约报文一致。
type Account struct {
	UserID string         `json:"user_id"`
	Status string         `json:"status"`
	Claims []Claim        `json:"claims"`
	Extra  map[string]any `json:"extra,omitempty"`
}

// Fault 是一条故障注入规则。
type Fault struct {
	// Mode 取 Fault* 常量。
	Mode string
	// Delay 供 FaultTimeout / FaultSlow 使用。
	Delay time.Duration
}

// Call 是一次被记录的调用。
//
// 记录幂等键是刻意的：P0-4 要求 Merge 必须带幂等键，而"带没带"这件事
// 在登录成功的表象里看不出来——只能看对端收到了什么。
//
// 记录 app_key 同理：应用维度漏带时，请求仍然会成功（如果对端宽容），
// 只有从对端视角才能发现"它被当成了全局账号空间"。
type Call struct {
	AppKey         string
	Op             string
	UserID         string
	ClaimType      string
	ClaimValue     string
	IdempotencyKey string
	Status         int
	At             time.Time
}

// Config 是假用户中心的配置。
type Config struct {
	// Token 非空时要求 Authorization: Bearer <token>。
	Token string
	// CreateUnsupported 为 true 时 POST /accounts 返回 404，
	// 模拟"用户中心不提供创建能力"（契约允许 404/405/501）。
	CreateUnsupported bool
	// RequireRegisteredApp 为 true 时只接受已通过 RegisterApp 注册的 app_key，
	// 其余返回 400 APP.UNKNOWN（对应 §2.6 的"不做懒注册"）。
	RequireRegisteredApp bool
	// Prefix 是自动生成的 user_id 前缀，默认 "uc-"。
	Prefix string
}

// MergeResult 是合并结果报文。
type MergeResult struct {
	Merged          bool           `json:"merged"`
	AlreadyMerged   bool           `json:"already_merged"`
	DiscardedClaims []Claim        `json:"discarded_claims,omitempty"`
	RemoteRef       map[string]any `json:"remote_ref,omitempty"`
}

// RegisteredApp 是一个注册到假用户中心的应用。
//
// 与真实对端一样，注册是 upsert：同一个 app_key 重复注册只更新名称与状态，
// 不会产生第二条租户记录。测试据此断言"对账重放不会造出重复租户"。
type RegisteredApp struct {
	AppKey string `json:"app_key"`
	Name   string `json:"name"`
	// Status 取 StatusActive / StatusDisabled。
	//
	// ⚠️ 假对端只【记录】状态，不据此拒绝请求：§12.3 还没定"停用应用后
	// 用户中心是否也拒绝"，在契约确定前按"了解但不拦"行为模拟。
	Status string `json:"status"`
}

// Server 是内存态假用户中心。
type Server struct {
	cfg Config

	mu sync.Mutex
	// accounts 按 user_id 索引（user_id 全局唯一，便于跨应用排查）。
	accounts map[string]*Account
	// appOf 记录每个账号属于哪个应用——合并必须校验两端同应用（R3）。
	appOf map[string]string
	// claimOwner 的 key 带 app 前缀：同一个手机号在两个应用里是两条独立记录。
	claimOwner   map[string]string
	createKeys   map[string]string
	mergeResults map[string]*MergeResult
	apps         map[string]*RegisteredApp
	faults       map[string]Fault
	calls        []Call
	seq          int
}

// New 构造假用户中心。
func New(cfg Config) *Server {
	if cfg.Prefix == "" {
		cfg.Prefix = "uc-"
	}
	return &Server{
		cfg:          cfg,
		accounts:     make(map[string]*Account),
		appOf:        make(map[string]string),
		claimOwner:   make(map[string]string),
		createKeys:   make(map[string]string),
		mergeResults: make(map[string]*MergeResult),
		apps:         make(map[string]*RegisteredApp),
		faults:       make(map[string]Fault),
	}
}

// --- 测试可直接调用的控制面（不必绕 HTTP）---

// RegisterApp 注册一个应用。RequireRegisteredApp 为 true 时必需。
//
// 控制面入口（不走 HTTP），供需要预置应用的测试使用。
func (s *Server) RegisterApp(appKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps[appKey] = &RegisteredApp{AppKey: appKey, Status: StatusActive}
}

// AppRegistration 返回某个应用的注册信息快照，不存在时第二个返回值为 false。
func (s *Server) AppRegistration(appKey string) (*RegisteredApp, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[appKey]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// RegisteredApps 返回全部已注册应用的数量。
func (s *Server) RegisteredAppCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.apps)
}

// Seed 直接写入一个账号。userID 为空时自动生成。
func (s *Server) Seed(appKey, userID string, claims []Claim) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if userID == "" {
		userID = s.nextUserIDLocked()
	}
	s.accounts[userID] = &Account{
		UserID: userID,
		Status: StatusActive,
		Claims: append([]Claim(nil), claims...),
	}
	s.appOf[userID] = appKey
	for _, c := range claims {
		s.claimOwner[claimKey(appKey, c.Type, c.Value)] = userID
	}
	return userID
}

// SetStatus 修改账号状态（frozen / closed）。
func (s *Server) SetStatus(userID, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.accounts[userID]; ok {
		a.Status = status
	}
}

// InjectFault 注入故障。op 取 Op* 常量，传 OpAll 表示全部操作。
func (s *Server) InjectFault(op, mode string, delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[op] = Fault{Mode: mode, Delay: delay}
}

// ClearFaults 清除全部故障注入。
func (s *Server) ClearFaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = make(map[string]Fault)
}

// Account 返回账号快照，不存在时第二个返回值为 false。
func (s *Server) Account(userID string) (*Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[userID]
	if !ok {
		return nil, false
	}
	cp := *a
	cp.Claims = append([]Claim(nil), a.Claims...)
	return &cp, true
}

// Accounts 返回全部账号的快照（按 user_id 排序由调用方自行处理）。
func (s *Server) Accounts() []*Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		cp := *a
		cp.Claims = append([]Claim(nil), a.Claims...)
		out = append(out, &cp)
	}
	return out
}

// Count 返回账号数量。
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.accounts)
}

// Calls 返回调用记录快照。
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// CallsOf 返回某个操作的调用记录。
func (s *Server) CallsOf(op string) []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Call
	for _, c := range s.calls {
		if c.Op == op {
			out = append(out, c)
		}
	}
	return out
}

// Reset 清空全部状态（账号、幂等记录、调用记录、故障）。
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = make(map[string]*Account)
	s.appOf = make(map[string]string)
	s.claimOwner = make(map[string]string)
	s.createKeys = make(map[string]string)
	s.mergeResults = make(map[string]*MergeResult)
	s.faults = make(map[string]Fault)
	s.apps = make(map[string]*RegisteredApp)
	s.calls = nil
	s.seq = 0
}

// --- HTTP ---

// Handler 返回可挂到 httptest / http.Server 的路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	// 应用注册：服务间接口，不在 /v1/apps/{app_key} 前缀下——它本身就是
	// "声明一个应用存在"。
	mux.HandleFunc("/internal/v1/apps", s.registerApp)
	// 所有业务路径都在 /v1/apps/{app_key}/accounts 下（v1.1 契约）。
	mux.HandleFunc("/v1/apps/", s.appScoped)
	return s.withAuth(mux)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "accounts": s.Count()})
}

// registerApp 处理 POST /internal/v1/apps。
//
// 这是"服务间"接口：由登录中心的同步任务调用，不是业务方的入口。
// 语义必须是幂等 upsert —— 对账任务每 5 分钟会把全部应用重放一遍，
// 不幂等的实现会不断造出重复租户，而重复租户在账号侧的表现是
// "用户被随机分到其中一份，另一半数据永远查不到"。
func (s *Server) registerApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// 405 不带 code：与"资源不存在"区分开，也让适配层知道不是能力缺失。
		writeErrNoCode(w, http.StatusMethodNotAllowed, "only POST")
		return
	}
	var req struct {
		AppKey string `json:"app_key"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.record(OpRegister, "", "", "", "", "", http.StatusBadRequest)
		writeErr(w, http.StatusBadRequest, CodeInvalid, "bad json")
		return
	}
	req.AppKey = strings.TrimSpace(req.AppKey)
	switch {
	case req.AppKey == "":
		s.record(OpRegister, "", "", "", "", "", http.StatusBadRequest)
		writeErr(w, http.StatusBadRequest, CodeInvalid, "app_key is required")
		return
	case req.Status != StatusActive && req.Status != StatusDisabled:
		// 状态缺失时拒绝而不是默认成 active：默认启用会让一个已停用的应用
		// 在对端被重新启用，而"停用"通常是安全或合规原因。
		s.record(OpRegister, req.AppKey, "", "", "", "", http.StatusBadRequest)
		writeErr(w, http.StatusBadRequest, CodeInvalid, "status must be active|disabled")
		return
	}

	// 故障注入放在参数校验之后：要验的是"对端收到合法请求但出错了"，
	// 而不是"连参数校验都过不去"。注册失败会让该应用的登录全部不可用，
	// 所以这条路径必须能被主动弄坏来测降级。
	s.handle(w, r, req.AppKey, OpRegister, func() {
		s.mu.Lock()
		s.apps[req.AppKey] = &RegisteredApp{AppKey: req.AppKey, Name: req.Name, Status: req.Status}
		s.mu.Unlock()

		s.record(OpRegister, req.AppKey, "", "", "", "", http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{"app_key": req.AppKey, "status": req.Status})
	})
}

// appScoped 解析 /v1/apps/{app_key}/accounts/... 并分派。
//
// 自己解析而不是用路由库：路径形状是契约的一部分，测试里要能一眼看出
// "少带应用前缀会得到什么"，比藏在路由注册里更直接。
func (s *Server) appScoped(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/apps/")
	appKey, tail, ok := strings.Cut(rest, "/")
	if !ok || appKey == "" {
		writeErr(w, http.StatusBadRequest, CodeInvalid, "missing app_key in path")
		return
	}
	if s.cfg.RequireRegisteredApp {
		s.mu.Lock()
		registered := s.apps[appKey] != nil
		s.mu.Unlock()
		if !registered {
			// 不做懒注册：配置里写错一个字母就会造出空租户，而那种错误
			// 不报错、只表现成"用户数据全丢了"（§2.6）。
			writeErr(w, http.StatusBadRequest, CodeAppUnknown, "app not registered: "+appKey)
			return
		}
	}
	parts := strings.Split(strings.Trim(tail, "/"), "/")
	if len(parts) == 0 || parts[0] != "accounts" {
		writeErr(w, http.StatusNotFound, CodeNotFound, "unknown path: "+r.URL.Path)
		return
	}
	switch {
	case len(parts) == 1:
		s.createAccount(w, r, appKey)
	case len(parts) == 2 && parts[1] == "by-claim":
		s.byClaim(w, r, appKey)
	case len(parts) == 2 && parts[1] == "merge":
		s.merge(w, r, appKey)
	case len(parts) == 2:
		s.getAccount(w, r, appKey, parts[1])
	case len(parts) == 4 && parts[2] == "claims":
		s.replaceClaim(w, r, appKey, parts[1], parts[3])
	default:
		writeErr(w, http.StatusNotFound, CodeNotFound, "unknown path: "+r.URL.Path)
	}
}

// createAccount 处理 POST /v1/apps/{app}/accounts。
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request, appKey string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, CodeInvalid, "only POST")
		return
	}
	s.handle(w, r, appKey, OpCreate, func() {
		if s.cfg.CreateUnsupported {
			s.record(OpCreate, appKey, "", "", "", "", http.StatusNotFound)
			// 契约允许 404/405/501 且【不带错误码】表示"不提供该能力"。
			writeErrNoCode(w, http.StatusNotFound, "create not supported")
			return
		}
		key := strings.TrimSpace(r.Header.Get(IdempotencyHeader))
		if key == "" {
			// 契约要求写操作必须带幂等键；对端缺键时返回 400 是合理反应，
			// 我们这边的适配层已经在本地拦截，这里只是兜底。
			s.record(OpCreate, appKey, "", "", "", "", http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "missing Idempotency-Key")
			return
		}
		var req struct {
			Claims    []Claim `json:"claims"`
			Nickname  string  `json:"nickname"`
			AvatarURL string  `json:"avatar_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.record(OpCreate, appKey, "", "", "", key, http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "bad json")
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		// 幂等命中：同一键必须返回同一账号，且不新增。键必须带应用前缀——
		// 否则两个应用用了同一个键（首登键里含 appCode，理论上不会，但不能依赖）。
		spaceKey := appKey + "\x00" + key
		if uid, ok := s.createKeys[spaceKey]; ok {
			s.recordLocked(OpCreate, appKey, uid, "", "", key, http.StatusOK)
			writeJSON(w, http.StatusOK, s.accounts[uid])
			return
		}
		// 凭证唯一性：任一凭证在本应用内被别的账号持有时返回 409。
		// 只在本应用内检查：同一个手机号在别的应用里属于别人是【正常】的。
		for _, c := range req.Claims {
			if uid, ok := s.claimOwner[claimKey(appKey, c.Type, c.Value)]; ok {
				s.recordLocked(OpCreate, appKey, uid, c.Type, c.Value, key, http.StatusConflict)
				writeErr(w, http.StatusConflict, CodeClaimTaken, "claim already taken by "+uid)
				return
			}
		}
		uid := s.nextUserIDLocked()
		acc := &Account{UserID: uid, Status: StatusActive, Claims: req.Claims}
		s.accounts[uid] = acc
		s.appOf[uid] = appKey
		for _, c := range req.Claims {
			s.claimOwner[claimKey(appKey, c.Type, c.Value)] = uid
		}
		s.createKeys[spaceKey] = uid
		s.recordLocked(OpCreate, appKey, uid, "", "", key, http.StatusOK)
		writeJSON(w, http.StatusCreated, acc)
	})
}

// getAccount 处理 GET /v1/apps/{app}/accounts/{user_id}。
func (s *Server) getAccount(w http.ResponseWriter, r *http.Request, appKey, userID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, CodeInvalid, "only GET")
		return
	}
	s.handle(w, r, appKey, OpGet, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		acc, ok := s.accounts[userID]
		// 跨应用查同一个 id 视为不存在：id 只在应用内唯一，拿到别的应用的账号
		// 等于越权读到别人的数据。
		if !ok || s.appOf[userID] != appKey {
			s.recordLocked(OpGet, appKey, userID, "", "", "", http.StatusNotFound)
			writeErr(w, http.StatusNotFound, CodeNotFound, "account not found")
			return
		}
		s.recordLocked(OpGet, appKey, userID, "", "", "", http.StatusOK)
		writeJSON(w, http.StatusOK, acc)
	})
}

// byClaim 处理 GET /v1/apps/{app}/accounts/by-claim?type=&value=。
func (s *Server) byClaim(w http.ResponseWriter, r *http.Request, appKey string) {
	s.handle(w, r, appKey, OpByClaim, func() {
		q := r.URL.Query()
		ct, cv := q.Get("type"), q.Get("value")
		if ct == "" || cv == "" {
			s.record(OpByClaim, appKey, "", ct, cv, "", http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "missing type/value")
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if f, ok := s.faults[OpByClaim]; ok && f.Mode == FaultMultiAccount {
			// 模拟"用户中心唯一性已坏"：即使本地只有一条，也返回 409。
			s.recordLocked(OpByClaim, appKey, "", ct, cv, "", http.StatusConflict)
			writeErr(w, http.StatusConflict, CodeMultiple, "multiple accounts matched")
			return
		}
		// 只在本应用内反查。跨应用反查不是"多一条结果"，是查错了人。
		uid, ok := s.claimOwner[claimKey(appKey, ct, cv)]
		if !ok {
			s.recordLocked(OpByClaim, appKey, "", ct, cv, "", http.StatusNotFound)
			writeErr(w, http.StatusNotFound, CodeNotFound, "no account holds this claim")
			return
		}
		acc, ok := s.accounts[uid]
		if !ok {
			s.recordLocked(OpByClaim, appKey, "", ct, cv, "", http.StatusNotFound)
			writeErr(w, http.StatusNotFound, CodeNotFound, "no account holds this claim")
			return
		}
		s.recordLocked(OpByClaim, appKey, uid, ct, cv, "", http.StatusOK)
		writeJSON(w, http.StatusOK, acc)
	})
}

// merge 处理 POST /v1/apps/{app}/accounts/merge。
func (s *Server) merge(w http.ResponseWriter, r *http.Request, appKey string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, CodeInvalid, "only POST")
		return
	}
	s.handle(w, r, appKey, OpMerge, func() {
		key := strings.TrimSpace(r.Header.Get(IdempotencyHeader))
		if key == "" {
			s.record(OpMerge, appKey, "", "", "", "", http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "missing Idempotency-Key")
			return
		}
		var req struct {
			TargetUserID string `json:"target_user_id"`
			SourceUserID string `json:"source_user_id"`
			Reason       string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.record(OpMerge, appKey, "", "", "", key, http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "bad json")
			return
		}
		if req.TargetUserID == "" || req.SourceUserID == "" {
			s.record(OpMerge, appKey, "", "", "", key, http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "missing target/source")
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		// 幂等命中：同一键重放必须返回同一结果，且不再迁移任何数据。
		// 这是 P0-4 的核心——补偿任务重试时不能重复迁移。
		//
		// ⚠️ 返回 merged=false + already_merged=true，不能把首次的结果原样返回。
		// 语义上"这次调用没有执行合并"，补偿任务据此判断是否还要推进本地收敛；
		// 原样返回会让它以为又合并了一次。
		spaceKey := appKey + "\x00" + key
		if prev, ok := s.mergeResults[spaceKey]; ok {
			s.recordLocked(OpMerge, appKey, req.TargetUserID, "", "", key, http.StatusOK)
			writeJSON(w, http.StatusOK, &MergeResult{
				Merged:        false,
				AlreadyMerged: true,
				RemoteRef:     prev.RemoteRef,
			})
			return
		}
		if req.TargetUserID == req.SourceUserID {
			s.recordLocked(OpMerge, appKey, req.TargetUserID, "", "", key, http.StatusConflict)
			writeErr(w, http.StatusConflict, CodeMergeRejected, "target == source")
			return
		}
		target, ok := s.accounts[req.TargetUserID]
		if !ok || s.appOf[req.TargetUserID] != appKey {
			s.recordLocked(OpMerge, appKey, req.TargetUserID, "", "", key, http.StatusNotFound)
			writeErr(w, http.StatusNotFound, CodeNotFound, "target not found in this app")
			return
		}
		source, ok := s.accounts[req.SourceUserID]
		if !ok || s.appOf[req.SourceUserID] != appKey {
			// 跨应用合并必须拒绝（R3）：两端不同应用说明调用方传错了 id，
			// 真合并会把两个业务的账号搅在一起。
			s.recordLocked(OpMerge, appKey, req.SourceUserID, "", "", key, http.StatusNotFound)
			writeErr(w, http.StatusNotFound, CodeNotFound, "source not found in this app")
			return
		}

		// source 已经是 closed：说明此前用【另一个】幂等键合并过。
		// 按"已完成"返回，而不是再迁移一次。
		if source.Status == StatusClosed {
			res := &MergeResult{Merged: false, AlreadyMerged: true,
				RemoteRef: map[string]any{"note": "source already closed"}}
			s.mergeResults[spaceKey] = res
			s.recordLocked(OpMerge, appKey, req.TargetUserID, "", "", key, http.StatusOK)
			writeJSON(w, http.StatusOK, res)
			return
		}

		// 凭证按【类型】目标优先：target 已有该类型（哪怕号不同）时，
		// source 的那条只能撤销——一个账号每类凭证只允许一条活跃。
		occupied := make(map[string]bool, len(target.Claims))
		for _, c := range target.Claims {
			occupied[c.Type] = true
		}
		var discarded []Claim
		for _, c := range source.Claims {
			if occupied[c.Type] {
				discarded = append(discarded, c)
				delete(s.claimOwner, claimKey(appKey, c.Type, c.Value))
				continue
			}
			occupied[c.Type] = true
			target.Claims = append(target.Claims, c)
			s.claimOwner[claimKey(appKey, c.Type, c.Value)] = target.UserID
		}
		source.Claims = nil
		source.Status = StatusClosed

		res := &MergeResult{
			Merged:          true,
			AlreadyMerged:   false,
			DiscardedClaims: discarded,
			RemoteRef:       map[string]any{"reason": req.Reason, "discarded": len(discarded)},
		}
		s.mergeResults[spaceKey] = res
		s.recordLocked(OpMerge, appKey, req.TargetUserID, "", "", key, http.StatusOK)
		writeJSON(w, http.StatusOK, res)
	})
}

// replaceClaim 处理 PUT /v1/apps/{app}/accounts/{user_id}/claims/{type}。
func (s *Server) replaceClaim(w http.ResponseWriter, r *http.Request, appKey, userID, claimType string) {
	if r.Method != http.MethodPut {
		writeErr(w, http.StatusMethodNotAllowed, CodeInvalid, "only PUT")
		return
	}
	s.handle(w, r, appKey, OpReplace, func() {
		var req struct {
			Value  string `json:"value"`
			Source string `json:"source"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.record(OpReplace, appKey, userID, claimType, "", "", http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "bad json")
			return
		}
		if strings.TrimSpace(req.Value) == "" {
			s.record(OpReplace, appKey, userID, claimType, "", "", http.StatusBadRequest)
			writeErr(w, http.StatusBadRequest, CodeInvalid, "missing value")
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		acc, ok := s.accounts[userID]
		if !ok || s.appOf[userID] != appKey {
			s.recordLocked(OpReplace, appKey, userID, claimType, req.Value, "", http.StatusNotFound)
			writeErr(w, http.StatusNotFound, CodeNotFound, "account not found")
			return
		}
		newKey := claimKey(appKey, claimType, req.Value)
		if owner, ok := s.claimOwner[newKey]; ok && owner != userID {
			s.recordLocked(OpReplace, appKey, userID, claimType, req.Value, "", http.StatusConflict)
			writeErr(w, http.StatusConflict, CodeClaimTaken, "claim already taken by "+owner)
			return
		}
		// 已经是本账号当前值：幂等 no-op。
		for _, c := range acc.Claims {
			if c.Type == claimType && c.Value == req.Value {
				s.recordLocked(OpReplace, appKey, userID, claimType, req.Value, "", http.StatusOK)
				writeJSON(w, http.StatusOK, acc)
				return
			}
		}
		next := make([]Claim, 0, len(acc.Claims)+1)
		for _, c := range acc.Claims {
			if c.Type == claimType {
				delete(s.claimOwner, claimKey(appKey, c.Type, c.Value))
				continue
			}
			next = append(next, c)
		}
		next = append(next, Claim{Type: claimType, Value: req.Value, Source: req.Source})
		acc.Claims = next
		s.claimOwner[newKey] = userID
		s.recordLocked(OpReplace, appKey, userID, claimType, req.Value, "", http.StatusOK)
		writeJSON(w, http.StatusOK, acc)
	})
}

// --- 内部 ---

// handle 统一处理鉴权之外的故障注入与响应包装。
//
// 故障注入放在业务逻辑之前：目的就是让请求根本到不了业务逻辑，
// 从而验证调用方在"对端没有正常响应"时的行为。
func (s *Server) handle(w http.ResponseWriter, r *http.Request, appKey, op string, fn func()) {
	if f, ok := s.faultFor(op); ok {
		switch f.Mode {
		case FaultServerError:
			s.record(op, appKey, "", "", "", r.Header.Get(IdempotencyHeader), http.StatusInternalServerError)
			writeErr(w, http.StatusInternalServerError, "UPSTREAM.INTERNAL", "injected 500")
			return
		case FaultRateLimited:
			s.record(op, appKey, "", "", "", r.Header.Get(IdempotencyHeader), http.StatusTooManyRequests)
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, "RATE.LIMITED", "injected 429")
			return
		case FaultIdemInProgress:
			// 同一幂等键的另一请求还在处理：409 + 明确的 code。
			// 这个场景用状态码根本区分不出来（和"凭证被占用"都是 409），
			// 正是错误信封存在的理由。
			s.record(op, appKey, "", "", "", r.Header.Get(IdempotencyHeader), http.StatusConflict)
			writeErr(w, http.StatusConflict, CodeIdemInProgress, "injected idempotency in progress")
			return
		case FaultTimeout:
			d := f.Delay
			if d <= 0 {
				d = 5 * time.Second
			}
			// 睡过客户端超时；客户端断开后这里仍会写完，但没人读。
			time.Sleep(d)
			s.record(op, appKey, "", "", "", r.Header.Get(IdempotencyHeader), http.StatusGatewayTimeout)
			writeErr(w, http.StatusGatewayTimeout, "UPSTREAM.TIMEOUT", "injected timeout")
			return
		case FaultSlow:
			if f.Delay > 0 {
				time.Sleep(f.Delay)
			}
		}
	}
	fn()
}

func (s *Server) faultFor(op string) (Fault, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.faults[op]; ok {
		return f, true
	}
	f, ok := s.faults[OpAll]
	return f, ok
}

func (s *Server) record(op, appKey, userID, claimType, claimValue, key string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordLocked(op, appKey, userID, claimType, claimValue, key, status)
}

func (s *Server) recordLocked(op, appKey, userID, claimType, claimValue, key string, status int) {
	s.calls = append(s.calls, Call{
		AppKey: appKey, Op: op, UserID: userID, ClaimType: claimType, ClaimValue: claimValue,
		IdempotencyKey: key, Status: status, At: time.Now(),
	})
}

func (s *Server) nextUserIDLocked() string {
	s.seq++
	return fmt.Sprintf("%s%04d", s.cfg.Prefix, s.seq)
}

// claimKey 用 NUL 分隔：手机号/邮箱里都可能出现字母与符号，NUL 不会出现，
// 拼接不会产生歧义（"a|b" 与 "a"+"|b" 这类碰撞）。
func claimKey(appKey, claimType, value string) string {
	return appKey + "\x00" + claimType + "\x00" + strings.ToLower(strings.TrimSpace(value))
}

// withAuth 校验 Bearer token（配置了才校验）。
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != s.cfg.Token {
				writeErr(w, http.StatusUnauthorized, "AUTH.UNAUTHORIZED", "invalid token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// writeJSON 写出 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorBody 是对外的统一错误信封（契约 v1.1）。
type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// writeErr 按契约的错误信封返回。
//
// 不返回裸 {"error":"..."}：适配层只能靠状态码猜原因，而"409"至少有四种
// 完全不同的含义。
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{
		Code: code, Message: msg,
		// 5xx / 429 是可重试的；其余由调用方按 code 判断，这里给保守值。
		Retryable: status >= 500 || status == http.StatusTooManyRequests,
	})
}

// writeErrNoCode 返回不带 code 的 404，用于表达"本端点不提供该能力"。
//
// 契约里 404 有双重含义：路由不存在 vs 资源不存在。适配层用"有没有 code"
// 区分——带 code 说明对端认识这个请求，只是业务上不满足。
func writeErrNoCode(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}
