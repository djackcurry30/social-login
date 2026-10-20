-- 00003: Webhook 投递目标（事件外发）
--
-- 事件外发（架构 §5.4）需要每个业务应用自己的接收地址与签名密钥：
--   - webhook_url         业务方接收事件的 HTTPS 端点
--   - app webhook secret  用于 X-Signature: t=<unix>,v1=<HMAC-SHA256(t + "." + body, secret)>
--
-- 为什么密钥单独一列而不是复用 app_secret：
-- app_secret 只存哈希（不可逆），而 HMAC 签名需要【明文】密钥参与运算。
-- 因此这里按渠道凭据同样的方式处理——用主密钥信封加密后落库（BYTEA），
-- 并记下 KEK 版本，便于 §8.3 的密钥轮换。
--
-- 允许为 NULL：老应用可以先不配置 webhook。此时 outbox 里的事件会被标记为
-- skipped（而不是 pending 堆积或假装 sent），运维能一眼看出"这个应用没配投递"。

-- +goose Up

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS webhook_url        TEXT,
    ADD COLUMN IF NOT EXISTS webhook_secret_enc BYTEA,
    ADD COLUMN IF NOT EXISTS webhook_secret_kid VARCHAR(64);

-- 死信重投与死信告警都按 (status, created_at) 扫描；部分索引避免全表扫。
CREATE INDEX IF NOT EXISTS idx_outbox_dead ON event_outbox (created_at)
    WHERE status = 'dead';

-- +goose Down

DROP INDEX IF EXISTS idx_outbox_dead;
ALTER TABLE applications
    DROP COLUMN IF EXISTS webhook_secret_kid,
    DROP COLUMN IF EXISTS webhook_secret_enc,
    DROP COLUMN IF EXISTS webhook_url;
