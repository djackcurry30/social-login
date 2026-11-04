// Command keyrewrap 把已有密文从一把 KEK 迁到另一把，或把 v1 格式升级为 v2。
//
// 存在的理由：信封加密的核心收益是"换 KEK 只重写 DEK 那几十字节"，但这句
// 话只有在有一个工具真的去干的时候才成立。没有它，"换密钥"就退化成
// "把所有渠道凭据重新录一遍"——那正是 migratio 成本随数据量线性增长的来源。
//
// 用法：
//
//	# 看一眼现状（不改数据）：有多少行仍是 v1、多少行已经是 v2
//	go run ./cmd/keyrewrap -config configs/config.yaml -dry-run
//
//	# 本地 KEK 换版本：旧密钥解开 → 新配置的 KEK 重新包装
//	go run ./cmd/keyrewrap -config configs/config.yaml \
//	  -from-master-key "旧主密钥Base64" -from-kek-id "local-kek-v1"
//
//	# 从本地主密钥迁到 KMS：目标 KEK 取配置里的 security.kms
//	go run ./cmd/keyrewrap -config configs/config.yaml \
//	  -from-master-key "旧主密钥Base64" -from-kek-id "local-kek-v1"
//
// 安全性：
//   - 只读取密文列，不把明文写到任何地方；解出的明文仅用于 v1 → v2 升级，
//     在内存中用完即弃。
//   - 默认逐行提交，失败只影响该行，可重复执行（幂等：已是目标 KEK 的行会被跳过）。
//   - 不做 DROP/TRUNCATE 之类动作，唯一写操作是 UPDATE 密文两列 + dek_id。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"gorm.io/gorm"

	"github.com/djackcurry30/social-login/internal/bootstrap"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
)

func main() {
	var (
		configPath = flag.String("config", "configs/config.yaml", "配置文件路径")
		fromKeyB64 = flag.String("from-master-key", "",
			"旧主密钥（Base64，32 字节）。留空表示旧 KEK 与当前配置相同，只做 v1→v2 格式升级")
		fromKEKID = flag.String("from-kek-id", "",
			"旧 KEK 的标识（对应 secret_dek_id）。留空取当前配置的 security.kek_id")
		dryRun = flag.Bool("dry-run", false, "只统计，不写库")
		limit  = flag.Int("limit", 0, "最多处理多少行（0 = 全部）")
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

	// 目标 KEK：与主服务同一条装配逻辑，避免"工具写进去的格式服务读不出来"。
	targetKEK, targetOpts, err := bootstrap.BuildKEK(cfg, logger)
	if err != nil {
		fail("构造目标 KEK 失败", err)
	}
	newKM, err := crypto.NewKeyManager(targetKEK, targetOpts)
	if err != nil {
		fail("初始化目标加密器失败", err)
	}

	// 源 KEK：默认就当前这把（即只做格式升级）。给了旧主密钥则换一把。
	srcKEK := targetKEK
	if *fromKeyB64 != "" {
		key, derr := crypto.DecodeMasterKey(*fromKeyB64)
		if derr != nil {
			fail("解析旧主密钥失败", derr)
		}
		srcKEK, derr = crypto.NewLocalKEK(*fromKEKID, key)
		if derr != nil {
			fail("构造旧 KEK 失败", derr)
		}
	}
	srcKM, err := crypto.NewKeyManager(srcKEK, crypto.Options{})
	if err != nil {
		fail("初始化源加密器失败", err)
	}

	fmt.Printf("源 KEK: %s\n目标 KEK: %s\n模式: %s\n\n",
		srcKEK.KeyID(), targetKEK.KeyID(), modeName(*dryRun))

	stats := &rewrapStats{}
	// 渠道凭据与 webhook 签名密钥是当前仅有的两处"长期保存的敏感密文"。
	// 它们必须在同一轮迁移里处理完：只迁一半会让服务出现"登录正常、投递签名失败"
	// 这种极难定位的状态。
	if err := rewrapProviderConfigs(ctx, db, srcKM, newKM, targetKEK.KeyID(), *dryRun, *limit, stats); err != nil {
		fail("迁移渠道凭据失败", err)
	}
	if err := rewrapWebhookSecrets(ctx, db, srcKM, newKM, targetKEK.KeyID(), *dryRun, *limit, stats); err != nil {
		fail("迁移 webhook 密钥失败", err)
	}

	fmt.Printf("\n==> 渠道凭据: 扫描 %d，已是 v2 %d，v1 %d，迁移 %d，失败 %d\n",
		stats.providerTotal, stats.providerV2, stats.providerV1, stats.providerMigrated, stats.providerFailed)
	fmt.Printf("==> webhook : 扫描 %d，已是 v2 %d，v1 %d，迁移 %d，失败 %d\n",
		stats.webhookTotal, stats.webhookV2, stats.webhookV1, stats.webhookMigrated, stats.webhookFailed)
	if *dryRun {
		fmt.Println("（dry-run：未写入任何数据）")
	}
	if stats.providerFailed+stats.webhookFailed > 0 {
		os.Exit(1)
	}
}

type rewrapStats struct {
	providerTotal, providerV2, providerV1, providerMigrated, providerFailed int
	webhookTotal, webhookV2, webhookV1, webhookMigrated, webhookFailed      int
}

type providerRow struct {
	ID           int64  `gorm:"column:id"`
	AppID        int64  `gorm:"column:app_id"`
	SecretCipher []byte `gorm:"column:secret_cipher"`
	SecretPrev   []byte `gorm:"column:secret_cipher_prev"`
	SecretDEKID  string `gorm:"column:secret_dek_id"`
}

// rewrapProviderConfigs 迁移渠道凭据。
func rewrapProviderConfigs(ctx context.Context, db *gorm.DB, src, dst *crypto.KeyManager,
	targetKEKID string, dryRun bool, limit int, st *rewrapStats) error {

	rows, err := loadProviderRows(ctx, db, limit)
	if err != nil {
		return err
	}
	for _, row := range rows {
		st.providerTotal++
		if len(row.SecretCipher) == 0 {
			continue
		}
		newCipher, migrated, isV1, rerr := rewrapOne(src, dst, row.SecretCipher, row.SecretDEKID)
		if rerr != nil {
			st.providerFailed++
			fmt.Printf("  ✗ provider_config id=%d app=%d: %v\n", row.ID, row.AppID, rerr)
			continue
		}
		if isV1 {
			st.providerV1++
		} else {
			st.providerV2++
		}
		if !migrated {
			continue
		}
		st.providerMigrated++
		if dryRun {
			continue
		}
		var newPrev []byte
		if len(row.SecretPrev) > 0 {
			prev, _, _, perr := rewrapOne(src, dst, row.SecretPrev, row.SecretDEKID)
			if perr != nil {
				// 上一版凭据解不开不影响主流程（它本来就可能已失效），
				// 但必须把原因打出来——静默丢弃会让轮换过渡期失效且无人知道。
				fmt.Printf("  ! provider_config id=%d 的上一版凭据无法迁移，已保留原值: %v\n", row.ID, perr)
				newPrev = row.SecretPrev
			} else {
				newPrev = prev
			}
		}
		if uerr := updateProviderRow(ctx, db, row.ID, newCipher, newPrev, targetKEKID); uerr != nil {
			st.providerFailed++
			fmt.Printf("  ✗ provider_config id=%d 写库失败: %v\n", row.ID, uerr)
		}
	}
	return nil
}

// rewrapOne 迁移一段密文，返回新密文、是否真的改动了、以及原格式是否为 v1。
func rewrapOne(src, dst *crypto.KeyManager, ciphertext []byte, storedKEKID string) ([]byte, bool, bool, error) {
	isV1 := !crypto.IsV2(ciphertext)
	// 已经是 v2 且源/目标 KEK 相同：无需改动。
	//
	// 这个短路让工具可以反复执行（运维最常做的就是"再跑一遍确认干净"），
	// 也避免把每行的 DEK 无谓地重包一次——那会让 dry-run 的统计失去意义。
	if !isV1 && src.KEKID() == dst.KEKID() {
		return ciphertext, false, false, nil
	}
	// 用源密钥先确认这行现在解得开：解不开就说明 from 参数给错了，
	// 此时继续写回只会把一条还能用的密文覆盖成不可恢复的垃圾。
	if _, err := src.DecryptWithKEKID(ciphertext, storedKEKID); err != nil {
		return nil, false, isV1, fmt.Errorf("源 KEK 解不开（检查 -from-master-key / -from-kek-id）: %w", err)
	}
	out, err := src.Rewrap(ciphertext, dst.KEK())
	if err != nil {
		return nil, false, isV1, err
	}
	return out, true, isV1, nil
}

func updateProviderRow(ctx context.Context, db *gorm.DB, id int64, cipher, prev []byte, kekID string) error {
	return db.WithContext(ctx).Exec(
		`UPDATE app_provider_configs
		    SET secret_cipher = ?, secret_cipher_prev = ?, secret_dek_id = ?
		  WHERE id = ?`, cipher, nullBytes(prev), kekID, id).Error
}

type webhookRow struct {
	ID        int64  `gorm:"column:id"`
	AppCode   string `gorm:"column:app_code"`
	SecretEnc []byte `gorm:"column:webhook_secret_enc"`
	SecretKid string `gorm:"column:webhook_secret_kid"`
}

func rewrapWebhookSecrets(ctx context.Context, db *gorm.DB, src, dst *crypto.KeyManager,
	targetKEKID string, dryRun bool, limit int, st *rewrapStats) error {

	rows, err := loadWebhookRows(ctx, db, limit)
	if err != nil {
		return err
	}
	for _, row := range rows {
		st.webhookTotal++
		if len(row.SecretEnc) == 0 {
			continue
		}
		newCipher, migrated, isV1, rerr := rewrapOne(src, dst, row.SecretEnc, row.SecretKid)
		if rerr != nil {
			st.webhookFailed++
			fmt.Printf("  ✗ application %s: %v\n", row.AppCode, rerr)
			continue
		}
		if isV1 {
			st.webhookV1++
		} else {
			st.webhookV2++
		}
		if !migrated || dryRun {
			continue
		}
		st.webhookMigrated++
		if uerr := db.WithContext(ctx).Exec(
			`UPDATE applications SET webhook_secret_enc = ?, webhook_secret_kid = ? WHERE id = ?`,
			newCipher, targetKEKID, row.ID).Error; uerr != nil {
			st.webhookFailed++
			fmt.Printf("  ✗ application %s 写库失败: %v\n", row.AppCode, uerr)
		}
	}
	return nil
}

// loadProviderRows 只读密文列。
//
// 用 LIMIT 而不是全表扫：迁移可能涉及几十万行，工具必须能分批跑、
// 可中断、可重入（已迁移的行会被 rewrapOne 判为"无需改动"而跳过）。
func loadProviderRows(ctx context.Context, db *gorm.DB, limit int) ([]providerRow, error) {
	q := db.WithContext(ctx).
		Table("app_provider_configs").
		Select("id, app_id, secret_cipher, secret_cipher_prev, secret_dek_id").
		Where("secret_cipher IS NOT NULL").
		Order("id")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []providerRow
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func loadWebhookRows(ctx context.Context, db *gorm.DB, limit int) ([]webhookRow, error) {
	q := db.WithContext(ctx).
		Table("applications").
		Select("id, app_code, webhook_secret_enc, webhook_secret_kid").
		Where("webhook_secret_enc IS NOT NULL").
		Order("id")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []webhookRow
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func modeName(dryRun bool) string {
	if dryRun {
		return "dry-run（只统计）"
	}
	return "写入"
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "✗ %s: %v\n", msg, err)
	os.Exit(1)
}
