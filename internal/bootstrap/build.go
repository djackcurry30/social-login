package bootstrap

import (
	"encoding/base64"

	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"

	domainaccount "github.com/17track/social-login/internal/domain/account"
	infraaccount "github.com/17track/social-login/internal/infrastructure/account"
	"github.com/17track/social-login/internal/infrastructure/crypto"
	"github.com/17track/social-login/internal/pkg/errs"
	"github.com/17track/social-login/internal/pkg/ids"
	"github.com/17track/social-login/internal/pkg/jwtkit"
	"github.com/17track/social-login/migrations"
)

// 开发环境自动生成密钥时的提示语。
//
// 刻意写得刺眼：这些自动生成的密钥只存在于内存，进程重启就变。
// 用它们加密过的渠道凭据在重启后会解不开（解密失败而不是静默错值，这是刻意的），
// 因此开发环境要么接受"重启后需重新录入凭据"，要么把密钥写进配置文件。
const devKeyWarning = "开发模式自动生成临时密钥：进程重启后会变化。" +
	"用旧密钥加密的渠道凭据将无法解密（会明确报错，不会静默返回错误值）。" +
	"如需持久化，请配置 security.master_key / jwt.signing_keys。"

// buildKeyManager 构造渠道凭据的信封加密器。
func buildKeyManager(cfg *Config, logger *zap.Logger) (*crypto.KeyManager, error) {
	if cfg.Security.MasterKey == "" {
		if cfg.Server.IsProduction() {
			return nil, errs.New(errs.CodeConfigInvalid, "生产模式必须配置 security.master_key")
		}
		key, err := crypto.GenerateMasterKey()
		if err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "生成临时主密钥失败", err)
		}
		logger.Warn(devKeyWarning,
			zap.String("generated_master_key", crypto.EncodeMasterKey(key)),
			zap.String("hint", "把上面这行写入配置的 security.master_key 即可固定"))
		return crypto.NewKeyManager(cfg.Security.KEKID, key)
	}
	key, err := crypto.DecodeMasterKey(cfg.Security.MasterKey)
	if err != nil {
		return nil, err
	}
	return crypto.NewKeyManager(cfg.Security.KEKID, key)
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
func buildSigner(cfg *Config, logger *zap.Logger) (*jwtkit.Signer, error) {
	keys := make([]jwtkit.Key, 0, len(cfg.JWT.SigningKeys))
	for i, k := range cfg.JWT.SigningKeys {
		if k.PrivateKeyFile == "" {
			return nil, errs.Newf(errs.CodeConfigInvalid,
				"jwt.signing_keys[%d] 缺少 private_key_file", i)
		}
		key, err := jwtkit.LoadPrivateKeyPEM(k.PrivateKeyFile, k.KID)
		if err != nil {
			return nil, err
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
		return nil, err
	}
	logger.Info("签名密钥就绪",
		zap.String("active_kid", signer.ActiveKID()),
		zap.Int("published_kids", len(signer.Kids())))
	return signer, nil
}

// buildAccountProvider 构造账号体系实现（约束 C4）。
func buildAccountProvider(cfg *Config, logger *zap.Logger) (domainaccount.Provider, error) {
	switch cfg.Account.Provider {
	case "", "stub":
		logger.Warn("使用内存桩账号实现（account.provider=stub）：账号存于进程内存，" +
			"重启即丢失，且无法与真实用户中心对齐。仅限开发与集成测试")
		return infraaccount.NewStubProvider(), nil
	case "http":
		// HTTPAccountProvider 属第三期交付（替换第一期的 Stub）。
		// 这里显式报错而不是回退到 stub——回退会让生产环境以为是真实用户中心。
		return nil, errs.New(errs.CodeConfigInvalid,
			"account.provider=http 尚未实现（第三期交付 HTTPAccountProvider）")
	default:
		return nil, errs.Newf(errs.CodeConfigInvalid, "未知的 account.provider: %s", cfg.Account.Provider)
	}
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
