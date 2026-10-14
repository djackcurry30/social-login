// Command seed 写入本地联调所需的最小数据：一个业务应用 + 一份通用 OAuth2 渠道配置。
//
// 用法（先启动 cmd/mockoauth2）：
//
//	go run ./cmd/seed \
//	  -config configs/config.yaml \
//	  -app-code app_demo \
//	  -app-secret demo-secret-please-change \
//	  -redirect-uri "http://localhost:3000/callback" \
//	  -oauth2-base-url "http://127.0.0.1:9090"
//
// 执行后即可用 /v1/authorize 走通完整链路。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/alex/social-login/internal/bootstrap"
	"github.com/alex/social-login/internal/domain/provider"
	"github.com/alex/social-login/internal/domain/tenant"
	"github.com/alex/social-login/internal/infrastructure/crypto"
	"github.com/alex/social-login/internal/infrastructure/persistence/postgres"
)

func main() {
	var (
		configPath   = flag.String("config", "configs/config.yaml", "配置文件路径")
		appCode      = flag.String("app-code", "app_demo", "业务应用对外 app_id")
		appName      = flag.String("app-name", "演示应用", "业务应用名称")
		appSecret    = flag.String("app-secret", "demo-secret-please-change", "应用密钥（明文，仅本次录入）")
		redirectURIs = flag.String("redirect-uri", "http://localhost:3000/callback", "允许的回跳地址，逗号分隔；以 / 结尾表示前缀匹配")
		oauthBase    = flag.String("oauth2-base-url", "http://127.0.0.1:9090", "通用 OAuth2 提供方地址")
		clientID     = flag.String("provider-client-id", "mock-client", "平台侧 client_id")
		clientSecret = flag.String("provider-client-secret", "mock-secret", "平台侧 client_secret")
		unboundLogin = flag.String("on-unbound-login", tenant.OnUnboundNeedRegister,
			"首次登录无绑定时的处置：need_register | auto_create | session_only")
		mergeMode = flag.String("merge-mode", tenant.MergeModeConfirm,
			"合并模式：auto | confirm | manual")
		mergeVerify = flag.String("merge-verification", tenant.VerificationSMS,
			"合并验证强度：none | existing_binding | sms | strict")
	)
	flag.Parse()

	ctx := context.Background()

	cfg, err := bootstrap.Load(*configPath)
	if err != nil {
		fail("加载配置失败", err)
	}
	logger, err := bootstrap.NewLogger(cfg.Log)
	if err != nil {
		fail("初始化日志失败", err)
	}

	db, err := postgres.Open(ctx, postgres.Config{
		DSN:             cfg.Database.DSN,
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		SlowThreshold:   cfg.Database.SlowThreshold,
	}, logger)
	if err != nil {
		fail("连接数据库失败", err)
	}
	defer func() { _ = postgres.Close(db) }()

	// 构造加密器。注意：若配置里没有固定 master_key，这里生成的密钥与
	// 服务进程启动时生成的不会是同一把，写入的凭据将无法被服务解密。
	if cfg.Security.MasterKey == "" {
		fmt.Fprintln(os.Stderr,
			"⚠️ 配置中未设置 security.master_key：本次将使用临时主密钥加密渠道凭据。")
		fmt.Fprintln(os.Stderr,
			"   服务进程启动时会生成【另一把】临时密钥，导致凭据无法解密。")
		fmt.Fprintln(os.Stderr,
			"   请先执行 go run ./cmd/keygen 并把 security.master_key 写入配置。")
		os.Exit(1)
	}
	masterKey, err := crypto.DecodeMasterKey(cfg.Security.MasterKey)
	if err != nil {
		fail("解析主密钥失败", err)
	}
	keyManager, err := crypto.NewKeyManager(cfg.Security.KEKID, masterKey)
	if err != nil {
		fail("初始化加密器失败", err)
	}
	secretHasher := crypto.NewAppSecretHasher([]byte(cfg.Security.AppSecretSalt))

	// --- 业务应用 ---
	appRepo := postgres.NewAppRepository(db)
	policy := tenant.DefaultPolicy()
	policy.OnUnboundLogin = *unboundLogin
	policy.Merge.Mode = *mergeMode
	policy.Merge.Verification = *mergeVerify
	policy.AllowedRedirectURIs = splitAndTrim(*redirectURIs)

	// 在写入前先跑一遍配置校验：非法组合（如 confirm + verification=none）
	// 应该在这里就被拒绝，而不是等到线上登录时才暴露。
	check, err := policy.Validate()
	if err != nil {
		fail("应用策略配置非法", err)
	}
	for _, w := range check.Warnings {
		fmt.Fprintf(os.Stderr, "⚠️ %s\n", w)
	}

	app, err := appRepo.Upsert(ctx, &tenant.Application{
		AppCode:       *appCode,
		Name:          *appName,
		AppSecretHash: secretHasher.Hash(*appSecret),
		Status:        1,
		AccountMode:   tenant.AccountModeRemote,
		Policy:        check.Normalized,
	})
	if err != nil {
		fail("写入应用失败", err)
	}

	// --- 渠道配置 ---
	encSecret, err := keyManager.Encrypt(*clientSecret)
	if err != nil {
		fail("加密渠道凭据失败", err)
	}
	base := strings.TrimRight(*oauthBase, "/")
	extra := map[string]any{
		"authorize_url": base + "/oauth/authorize",
		"token_url":     base + "/oauth/token",
		"userinfo_url":  base + "/oauth/userinfo",
		"scopes":        []any{"openid", "profile", "email"},
		// 字段映射：mock 服务用标准字段名，真实平台按需改这里即可，无需改代码。
		"field_open_id":  "sub",
		"field_nickname": "name",
		"field_avatar":   "picture",
		"field_email":    "email",
		"field_phone":    "phone_number",
		// 声明"平台返回的 email 已验证"。留空则邮箱会被记录但永不参与自动归并
		// （R4 红线 1）。这里填 apple_email 只是为了演示取值必须是权威枚举之一。
		"email_verified_by": "apple_email",
	}

	configRepo := postgres.NewProviderConfigRepository(db)
	chCfg, err := configRepo.Upsert(ctx, &tenant.ProviderConfig{
		AppID:         app.ID,
		Platform:      provider.PlatformGenericOAuth2,
		Scene:         provider.SceneWeb,
		ConfigKey:     postgres.DefaultConfigKey,
		ProviderAppID: *clientID,
		SecretCipher:  encSecret,
		SecretDEKID:   keyManager.KEKID(),
		Env:           cfg.Auth.Env,
		Extra:         extra,
		Status:        1,
	})
	if err != nil {
		fail("写入渠道配置失败", err)
	}

	logger.Info("本地数据已写入",
		zap.Int64("app_id", app.ID),
		zap.String("app_code", app.AppCode),
		zap.Int64("provider_config_id", chCfg.ID),
		zap.Time("at", time.Now()))

	fmt.Println()
	fmt.Println("==== 完成 ====")
	fmt.Printf("业务应用:      %s（内部 id=%d）\n", app.AppCode, app.ID)
	fmt.Printf("应用密钥:      %s\n", *appSecret)
	fmt.Printf("渠道:          %s:%s (config_key=%s, env=%s)\n",
		chCfg.Platform, chCfg.Scene, chCfg.ConfigKey, chCfg.Env)
	fmt.Println()
	fmt.Println("下一步：启动服务后访问")
	fmt.Printf("  http://localhost:8080/v1/authorize?app_id=%s&platform=%s&scene=%s"+
		"&redirect_uri=%s&state=xyz\n",
		app.AppCode, chCfg.Platform, chCfg.Scene, urlEncode(firstOf(policy.AllowedRedirectURIs)))
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstOf(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// urlEncode 做最小转义，避免文档示例里的 redirect_uri 被 shell 拆分。
func urlEncode(s string) string {
	replacer := strings.NewReplacer(":", "%3A", "/", "%2F")
	return replacer.Replace(s)
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}
