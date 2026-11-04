package bootstrap

import (
	"encoding/base64"
	"strings"

	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/application/adminobs"
	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/domain/merge"
	infraaccount "github.com/djackcurry30/social-login/internal/infrastructure/account"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
	"github.com/djackcurry30/social-login/internal/infrastructure/sms"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/ids"
	"github.com/djackcurry30/social-login/internal/pkg/jwtkit"
	"github.com/djackcurry30/social-login/migrations"
)

// 开发环境自动生成密钥时的提示语。
//
// 刻意写得刺眼：这些自动生成的密钥只存在于内存，进程重启就变。
// 用它们加密过的渠道凭据在重启后会解不开（解密失败而不是静默错值，这是刻意的），
// 因此开发环境要么接受"重启后需重新录入凭据"，要么把密钥写进配置文件。
const devKeyWarning = "开发模式自动生成临时密钥：进程重启后会变化。" +
	"用旧密钥加密的渠道凭据将无法解密（会明确报错，不会静默返回错误值）。" +
	"如需持久化，请配置 security.master_key / jwt.signing_keys。"

// BuildKEK 按配置挑一把 KEK。
//
// 导出给 cmd/seed 与 cmd/keyrewrap 用：写入密文的三个位置（服务、种子脚本、
// 迁移工具）必须用同一套判断，否则会出现"seed 用本地密钥写、服务用 KMS 读"
// 这种当场就能把人卡住的错配。
//
// 两条路径，选哪条由 security.kms.enabled 决定：
//   - 启用 KMS：主密钥不出现在本服务的配置里，只有 key_id 与地址；
//   - 未启用：本地主密钥（开发/过渡形态，生产用它等于把 KEK 和数据放在同一套凭证体系里）。
func BuildKEK(cfg *Config, logger *zap.Logger) (crypto.KEK, crypto.Options, error) {
	if cfg.Security.KMS.Enabled {
		kek, err := crypto.NewRemoteKEK(crypto.RemoteKEKConfig{
			BaseURL: cfg.Security.KMS.BaseURL,
			KeyID:   firstNonEmpty(cfg.Security.KMS.KeyID, cfg.Security.KEKID),
			Token:   cfg.Security.KMS.Token,
			Timeout: cfg.Security.KMS.Timeout,
		})
		if err != nil {
			return nil, crypto.Options{}, err
		}
		logger.Info("渠道凭据使用 KMS 托管密钥",
			zap.String("kms", kek.String()),
			zap.Duration("dek_cache_ttl", cfg.Security.KMS.DEKCacheTTL))
		return kek, crypto.Options{
			Timeout: cfg.Security.KMS.Timeout,
			// DEK 缓存：渠道凭据在每次登录时都要解密，而 KMS 一次往返 5–20ms。
			// 不缓存等于把 KMS 变成登录链路上的同步依赖。
			DEKCacheTTL:  cfg.Security.KMS.DEKCacheTTL,
			DEKCacheSize: cfg.Security.KMS.DEKCacheSize,
		}, nil
	}

	if cfg.Security.MasterKey == "" {
		if cfg.Server.IsProduction() {
			return nil, crypto.Options{}, errs.New(errs.CodeConfigInvalid,
				"生产模式必须配置 security.master_key，或启用 security.kms（推荐后者：主密钥不该和数据同处一套凭证体系）")
		}
		key, err := crypto.GenerateMasterKey()
		if err != nil {
			return nil, crypto.Options{}, errs.Wrap(errs.CodeInternal, "生成临时主密钥失败", err)
		}
		logger.Warn(devKeyWarning,
			zap.String("generated_master_key", crypto.EncodeMasterKey(key)),
			zap.String("hint", "把上面这行写入配置的 security.master_key 即可固定"))
		kek, err := crypto.NewLocalKEK(cfg.Security.KEKID, key)
		return kek, crypto.Options{}, err
	}
	key, err := crypto.DecodeMasterKey(cfg.Security.MasterKey)
	if err != nil {
		return nil, crypto.Options{}, err
	}
	kek, err := crypto.NewLocalKEK(cfg.Security.KEKID, key)
	return kek, crypto.Options{}, err
}

// buildKeyManager 构造渠道凭据的信封加密器。
//
// 密文格式在两条路径下完全相同（v2 信封），所以可以随时切换——旧数据用
// `cmd/keyrewrap` 把 DEK 换成新 KEK 的包装即可，不需要重新加密业务数据。
func buildKeyManager(cfg *Config, logger *zap.Logger) (*crypto.KeyManager, error) {
	kek, opts, err := BuildKEK(cfg, logger)
	if err != nil {
		return nil, err
	}
	return crypto.NewKeyManager(kek, opts)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// buildClaimHasher 构造身份凭证哈希器。
func buildClaimHasher(cfg *Config, logger *zap.Logger) (*crypto.ClaimHasher, error) {
	salt := cfg.Security.ClaimSalt
	if salt == "" {
		if cfg.Server.IsProduction() {
			return nil, errs.New(errs.CodeConfigInvalid, "生产模式必须配置 security.claim_salt")
		}
		salt = "dev-claim-salt-" + ids.ULID()
		logger.Warn("开发模式使用随机凭证盐：进程重启后按手机号/邮箱的历史归并依据将无法匹配。"+
			"请配置 security.claim_salt 并保持稳定",
			zap.String("generated_claim_salt", salt))
	}
	return crypto.NewClaimHasher([]byte(salt)), nil
}

// buildAppSecretHasher 构造应用密钥校验器。
func buildAppSecretHasher(cfg *Config, logger *zap.Logger) *crypto.AppSecretHasher {
	salt := cfg.Security.AppSecretSalt
	if salt == "" {
		salt = "dev-app-secret-salt"
		if !cfg.Server.IsProduction() {
			logger.Warn("开发模式使用固定默认应用密钥盐，生产环境必须配置 security.app_secret_salt")
		}
	}
	return crypto.NewAppSecretHasher([]byte(salt))
}

// buildSigner 构造 JWT 签名器。
// buildSigner 构造签名器，并返回密钥存储（供管理端轮换后持久化）。
//
// 加载优先级（从高到低）：
//  1. security.key_dir 下由管理端 rotate 生成的状态文件
//  2. jwt.signing_keys 配置的私钥文件
//  3. 开发模式的临时密钥
//
// 第 1 条必须优先：否则管理端轮换过的密钥在重启后会被配置里的旧密钥顶掉，
// 轮换等于没做，而且 JWKS 会突然少一把公钥，旧 token 全部验签失败。
func buildSigner(cfg *Config, logger *zap.Logger) (*jwtkit.Signer, *jwtkit.FileStore, error) {
	var store *jwtkit.FileStore
	if cfg.Security.KeyDir != "" {
		store = jwtkit.NewFileStore(cfg.Security.KeyDir)
		if store.Exists() {
			keys, err := store.Load()
			if err != nil {
				// 状态文件存在但读不出来时【不能静默回退】到配置：
				// 那会让正在生效的密钥被无声替换。
				return nil, nil, err
			}
			signer, err := jwtkit.NewSigner(jwtkit.Options{
				Issuer: cfg.Server.Issuer,
				TTL:    cfg.JWT.AccessTokenTTL,
				Keys:   keys,
			})
			if err != nil {
				return nil, nil, err
			}
			logger.Info("签名密钥从状态文件加载（管理端轮换过）",
				zap.String("active_kid", signer.ActiveKID()),
				zap.Int("published_kids", len(signer.Kids())),
				zap.String("path", store.Path()))
			return signer, store, nil
		}
	}

	keys := make([]jwtkit.Key, 0, len(cfg.JWT.SigningKeys))
	for i, k := range cfg.JWT.SigningKeys {
		if k.PrivateKeyFile == "" {
			return nil, nil, errs.Newf(errs.CodeConfigInvalid,
				"jwt.signing_keys[%d] 缺少 private_key_file", i)
		}
		key, err := jwtkit.LoadPrivateKeyPEM(k.PrivateKeyFile, k.KID)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		// 生产模式在配置校验阶段已被拦截，这里只会发生在开发/测试环境。
		kid := "dev-" + ids.ULID()[:8]
		logger.Warn("开发模式自动生成临时签名密钥：进程重启会更换 kid，"+
			"业务方缓存的 JWKS 将失效一次。生产必须配置 jwt.signing_keys",
			zap.String("kid", kid))
	}
	signer, err := jwtkit.NewSigner(jwtkit.Options{
		Issuer: cfg.Server.Issuer,
		TTL:    cfg.JWT.AccessTokenTTL,
		Keys:   keys,
	})
	if err != nil {
		return nil, nil, err
	}
	logger.Info("签名密钥就绪",
		zap.String("active_kid", signer.ActiveKID()),
		zap.Int("published_kids", len(signer.Kids())))
	return signer, store, nil
}

// buildSMSSender 构造验证码发送通道。
//
// release 模式下的 "log" 已在 normalizeAndValidate 里被拒绝，
// 因此这里可以安全地把 log 当作开发专用实现。
func buildSMSSender(cfg *Config, logger *zap.Logger) merge.CodeSender {
	switch cfg.SMS.Provider {
	case "log":
		logger.Warn("短信通道使用日志实现：验证码只写日志，不会真实发送（仅限开发）")
		return sms.NewLogSender(logger)
	case "none", "":
		logger.Warn("未配置短信通道：confirm 模式的发码接口会返回 CONFIG.INVALID")
		return sms.NewUnconfiguredSender()
	default:
		// 走到这里说明 normalizeAndValidate 与 build 不一致，按未配置处理。
		return sms.NewUnconfiguredSender()
	}
}

func buildAccountProvider(cfg *Config, logger *zap.Logger) (domainaccount.Provider, error) {
	switch cfg.Account.Provider {
	case "", "stub":
		logger.Warn("使用内存桩账号实现（account.provider=stub）：账号存于进程内存，" +
			"重启即丢失，且无法与真实用户中心对齐。仅限开发与集成测试")
		return infraaccount.NewStubProvider(), nil
	case "http":
		// 真实用户中心。契约见 infrastructure/account/http.go 的文件头。
		//
		// 配置不完整时 NewHTTPProvider 返回 CONFIG.INVALID，这里直接透出——
		// 绝不回退到 stub：回退会让生产环境"看起来在跑"，实际账号存在进程内存里，
		// 重启即全部丢失。
		p, err := infraaccount.NewHTTPProvider(infraaccount.HTTPConfig{
			BaseURL: cfg.Account.HTTP.BaseURL,
			Token:   cfg.Account.HTTP.Token,
			Timeout: cfg.Account.HTTP.Timeout,
			Logger:  logger,
		})
		if err != nil {
			return nil, err
		}
		if cfg.Account.HTTP.Token == "" {
			// 不是错误：内网联调环境可能确实没有鉴权。
			// 但必须喊出来——生产缺 token 会被用户中心直接拒绝，
			// 而现象是"所有登录都 ACCOUNT.UNAVAILABLE"，很难联想到鉴权。
			logger.Warn("用户中心客户端未配置 Bearer token（account.http.token 为空）：" +
				"仅适用于无鉴权的内网联调环境")
		}
		logger.Info("使用用户中心 HTTP 客户端",
			zap.String("base_url", cfg.Account.HTTP.BaseURL),
			zap.Duration("timeout", cfg.Account.HTTP.Timeout))
		return p, nil
	default:
		return nil, errs.Newf(errs.CodeConfigInvalid, "未知的 account.provider: %s", cfg.Account.Provider)
	}
}

// describeAccountCenter 生成管理端看板用的"账号体系现状"标记。
//
// 存在的意义：用户中心未就绪时服务跑在 stub 上，而 stub 与 http 在外部表现上
// 几乎一样——都能登录成功、都能返回令牌。差别只在数据落到哪里：
// stub 存在进程内存，重启即丢，且和真实账号没有任何关系。
// 这种"看起来正常"的状态必须在运维每天都会看的地方显式标出来。
func describeAccountCenter(cfg *Config) adminobs.AccountCenterInfo {
	mode := strings.ToLower(strings.TrimSpace(cfg.Account.Provider))
	if mode == "" {
		mode = "stub"
	}
	info := adminobs.AccountCenterInfo{Provider: mode}
	if mode == "http" {
		info.BaseURL = cfg.Account.HTTP.BaseURL
		info.ProductionReady = true
		switch {
		case cfg.Account.HTTP.Token == "":
			// 不是错误（内网联调确实可能没鉴权），但要说出来：
			// 生产缺 token 的现象是"所有登录都 ACCOUNT.UNAVAILABLE"，极难联想。
			info.Note = "已接用户中心，但未配置服务间鉴权 token"
		default:
			info.Note = "已接用户中心"
		}
		return info
	}
	info.Note = "账号为进程内存桩：重启即丢失，且无法与真实用户中心对齐；仅限开发与演示"
	return info
}

// applyMigrations 执行数据库迁移。
//
// 用 goose 作为库嵌入（而非依赖外部 CLI），好处是"代码与 schema 同版本发布"，
// 不会出现"部署了新代码但忘了跑迁移"。
func applyMigrations(db *gorm.DB, logger *zap.Logger) error {
	sqlDB, err := db.DB()
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "获取数据库连接失败", err)
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(gooseLogger{logger: logger})
	if err := goose.SetDialect("postgres"); err != nil {
		return errs.Wrap(errs.CodeInternal, "设置迁移方言失败", err)
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		return errs.Wrap(errs.CodeInternal, "执行数据库迁移失败", err)
	}
	logger.Info("数据库迁移已应用")
	return nil
}

// gooseLogger 把 goose 的日志接到 zap。
type gooseLogger struct{ logger *zap.Logger }

func (g gooseLogger) Printf(format string, v ...any) {
	if g.logger != nil {
		g.logger.Sugar().Infof(format, v...)
	}
}

func (g gooseLogger) Fatalf(format string, v ...any) {
	if g.logger != nil {
		g.logger.Sugar().Errorf(format, v...)
	}
}

// EncodeKeyForConfig 是一个小工具：把随机生成的 32 字节密钥编码成可写入配置的字符串。
// 供命令行工具生成主密钥与签名密钥时使用。
func EncodeKeyForConfig(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}
