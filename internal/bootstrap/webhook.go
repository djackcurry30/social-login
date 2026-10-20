package bootstrap

import (
	"context"

	"github.com/djackcurry30/social-login/internal/domain/event"
	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
	"github.com/djackcurry30/social-login/internal/infrastructure/persistence/postgres"
	"github.com/djackcurry30/social-login/internal/infrastructure/webhook"
)

// appWebhookTargets 把"应用的投递配置"适配成投递器需要的目标。
//
// 为什么这层适配不放进仓储或投递器：
//   - 仓储不该持有密钥材料（能读库的组件不该顺手能拿到明文签名密钥）
//   - 投递器不该知道"配置存在 applications 表的哪几列"
//
// 装配层做拼接，两边都保持单一职责。
type appWebhookTargets struct {
	apps *postgres.AppRepository
	keys *crypto.KeyManager
}

var _ webhook.TargetReader = (*appWebhookTargets)(nil)

// WebhookTarget 读取并解密投递目标。
func (t *appWebhookTargets) WebhookTarget(ctx context.Context, appID int64) (*webhook.Target, error) {
	appCode, url, secretEnc, _, err := t.apps.WebhookConfig(ctx, appID)
	if err != nil {
		return nil, err
	}
	if url == "" {
		// 未配置投递地址是【配置状态】而非故障：dispatcher 会把它标成 skipped。
		return nil, event.ErrNoWebhook
	}

	secret := ""
	if len(secretEnc) > 0 && t.keys != nil {
		plain, derr := t.keys.Decrypt(secretEnc)
		if derr != nil {
			// 密钥解不开（KEK 轮换后未重加密）时不能静默用空密钥签名——
			// 那样业务方验签必然失败，但我们会以为投递成功。
			return nil, derr
		}
		secret = plain
	}
	return &webhook.Target{URL: url, Secret: secret, AppCode: appCode}, nil
}
