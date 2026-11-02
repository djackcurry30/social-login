// Package service 是用户中心的应用层：把领域规则、加密与存储编排成用例。
//
// 分层意图：
//
//	domain   —— 不依赖任何东西的规则（归一化、错误码、状态枚举）
//	cryptox  —— 只做哈希与加解密，不知道账号是什么
//	store    —— 只做 SQL，不知道"合并为什么要按 id 排序"
//	service  —— 本包：决定顺序、校验输入、组装响应、记指标
//
// service 是唯一同时知道"业务规则"和"存储形态"的地方，因此事务边界在这里
// 划定（具体事务由 store 的用例方法实现，见其注释）。
package service

import (
	"context"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/usercenter/cryptox"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/observe"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// Service 承载全部用例。
type Service struct {
	store  *postgres.Store
	hasher *cryptox.ClaimHasher
	env    *cryptox.Envelope
	log    *zap.Logger
	m      *observe.Metrics

	// newID 可替换，供测试断言"重放返回同一个 id"时使用固定序列。
	newID func() string
}

// New 构造服务。
//
// log 为 nil 时用 Nop logger：集成测试与服务装配都直接构造它，
// 让调用方必须先塞一个日志器只会逼出"为了过编译传个 nil"这种代码，
// 然后在第一次写日志时 panic。指标同理（见 observe.Metrics 的 nil 安全方法）。
func New(store *postgres.Store, hasher *cryptox.ClaimHasher, env *cryptox.Envelope,
	log *zap.Logger, m *observe.Metrics) *Service {
	if log == nil {
		log = zap.NewNop()
	}
	return &Service{
		store:  store,
		hasher: hasher,
		env:    env,
		log:    log,
		m:      m,
		newID:  ids.ULID,
	}
}

// appKeyPattern 是 app_key 的合法形态。
//
// 限制字符集的理由不是防注入（查询全部参数化），而是防"看起来像值的东西"
// 混进租户键：app_key 会出现在 URL 路径、日志字段、指标标签里，
// 允许空格/中文/换行会让这三处都出问题。
var appKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// ResolveApp 解析 app_key 为应用，并校验其状态。
//
// 未注册 → APP.UNKNOWN（400，不可重试）；已停用 → APP.DISABLED（403）。
// 两者都不做隐式创建：配置里写错一个字母就会造出一个空租户，
// 而那种错误不报错、只表现成"用户数据全丢了"（§2.6）。
func (s *Service) ResolveApp(ctx context.Context, appKey string) (domain.App, error) {
	if appKey == "" {
		return domain.App{}, domain.New(domain.CodeAppUnknown, "缺少 app_key")
	}
	app, err := s.store.FindApp(ctx, appKey)
	if err != nil {
		return domain.App{}, err
	}
	if !app.Enabled() {
		// 纵深防御：social-login 已经会拒停用应用，但本服务也可能被别的
		// 内部系统直接调用。停用通常意味着安全或合规原因，多拒一层不是浪费。
		return domain.App{}, domain.Newf(domain.CodeAppDisabled, "应用 %s 已停用", appKey)
	}
	return app, nil
}

// RegisterApp 注册或更新应用（幂等 upsert）。
//
// 这是"声明一个应用存在"，不是给业务方用的开通接口——唯一入口是
// social-login 的管理端 POST /admin/v1/apps（§2.6）。
func (s *Service) RegisterApp(ctx context.Context, appKey, name, status string) (domain.App, error) {
	appKey = strings.TrimSpace(appKey)
	if !appKeyPattern.MatchString(appKey) {
		return domain.App{}, domain.New(domain.CodeInvalid,
			"app_key 不合法：只允许字母数字开头，可含 _ 与 -，长度 1~64")
	}
	statusCode, ok := domain.ParseAppStatus(status)
	if !ok {
		// 状态缺失时拒绝而不是默认成 active：默认启用会把一个已停用的应用
		// 在对端重新启用，而"停用"通常是安全或合规原因。
		return domain.App{}, domain.New(domain.CodeInvalid, "status 必须是 active 或 disabled")
	}
	app, err := s.store.RegisterApp(ctx, appKey, name, statusCode)
	if err != nil {
		return domain.App{}, err
	}
	s.log.Info("应用注册",
		zap.String("app_key", app.Key),
		zap.String("status", domain.AppStatusName(app.Status)))
	return app, nil
}
