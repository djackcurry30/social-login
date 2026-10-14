-- 三方登录统一接入服务 · 初始 schema
--
-- ⚠️ 本文件是 DDL 的【唯一真相源】（tech-stack 的两条 GORM 不变量之一）。
-- 禁止用 GORM AutoMigrate 管理生产 schema：它表达不了下面两条部分唯一索引，
-- 而这两条正是整个数据模型的安全底线：
--   uk_claims_verified   —— "同一个已验证凭证只能属于一个身份"
--   uk_bindings_active   —— "一个三方身份同期只能绑一个账号"
--
-- 另注意 SQL 中一律【不使用】双引号标识符（例如 "user"），全部使用小写
-- 不带引号的标识符：这样同一份 DDL 在 PostgreSQL 与 MySQL 下语义一致，
-- 也不会因为大小写折叠规则差异在迁移时踩坑。

-- +goose Up

-- 接入方业务应用（术语定义：Application = 完全独立的业务单元，如 App1/App2）
CREATE TABLE applications (
    id              BIGSERIAL PRIMARY KEY,
    app_code        VARCHAR(64)  NOT NULL UNIQUE,
    name            VARCHAR(128) NOT NULL,
    app_secret_hash VARCHAR(128) NOT NULL,
    status          SMALLINT     NOT NULL DEFAULT 1,
    account_mode    VARCHAR(16)  NOT NULL DEFAULT 'remote',
    policy          JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 渠道配置：唯一键 = (app_id, platform, scene, config_key, env)
-- 不含承载形态（规则 2）：iOS 与 Android 共用 wechat:app 的同一份配置
CREATE TABLE app_provider_configs (
    id                   BIGSERIAL PRIMARY KEY,
    app_id               BIGINT       NOT NULL REFERENCES applications(id),
    platform             VARCHAR(32)  NOT NULL,
    scene                VARCHAR(32)  NOT NULL,
    config_key           VARCHAR(64)  NOT NULL DEFAULT 'default',
    provider_app_id      VARCHAR(128) NOT NULL,
    secret_cipher        BYTEA,
    secret_cipher_prev   BYTEA,
    secret_rotated_at    TIMESTAMPTZ,
    secret_dek_id        VARCHAR(64),
    env                  VARCHAR(16)  NOT NULL DEFAULT 'prod',
    extra                JSONB        NOT NULL DEFAULT '{}',
    version              BIGINT       NOT NULL DEFAULT 1,
    status               SMALLINT     NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (app_id, platform, scene, config_key, env)
);

-- 说明：按约束 C4，本服务不维护 accounts 表。账号主数据在用户中心，
-- 本服务仅以 external_user_id 的形式持有外部引用，且不加外键约束。

-- 三方身份：唯一索引是身份去重的安全底线
CREATE TABLE oauth_identities (
    id                BIGSERIAL PRIMARY KEY,
    app_id            BIGINT       NOT NULL REFERENCES applications(id),
    platform          VARCHAR(32)  NOT NULL,
    provider_app_id   VARCHAR(128) NOT NULL,
    open_id           VARCHAR(191) NOT NULL,
    union_id          VARCHAR(191),
    identity_key      VARCHAR(191) NOT NULL,
    profile_snapshot  JSONB        NOT NULL DEFAULT '{}',
    profile_synced_at TIMESTAMPTZ,
    first_seen_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_login_at     TIMESTAMPTZ,
    UNIQUE (app_id, platform, provider_app_id, open_id)
);

-- 归并查询必须带 app_id，否则跨业务应用串号（约束 C1）
CREATE INDEX idx_identities_key ON oauth_identities (app_id, platform, identity_key);

-- 归并依据：手机号 / 邮箱 / union_id 等可信凭证
CREATE TABLE identity_claims (
    id                 BIGSERIAL PRIMARY KEY,
    app_id             BIGINT       NOT NULL REFERENCES applications(id),
    identity_id        BIGINT       NOT NULL REFERENCES oauth_identities(id),
    claim_type         VARCHAR(32)  NOT NULL,
    claim_value_hash   VARCHAR(128) NOT NULL,
    claim_value_cipher BYTEA,
    verified           BOOLEAN      NOT NULL DEFAULT false,
    verified_at        TIMESTAMPTZ,
    source             VARCHAR(32)  NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ
);

CREATE INDEX idx_claims_identity ON identity_claims (app_id, identity_id);

-- ★ 唯一性只约束「已验证 + 未撤销」的 claim（修正 P0-1）。
-- 用普通 UNIQUE 会有三个后果：
--   1. 用户手填的未验证手机号会占住唯一键，导致真正通过平台验证的人插不进来
--   2. 无法表达"改绑手机号"——旧号码撤销后应可被他人使用
--   3. 一旦冲突就变成系统错误，而它其实是正常业务信号
CREATE UNIQUE INDEX uk_claims_verified
    ON identity_claims (app_id, claim_type, claim_value_hash)
    WHERE verified = true AND revoked_at IS NULL;

CREATE INDEX idx_claims_unverified
    ON identity_claims (app_id, identity_id)
    WHERE verified = false;

-- MySQL 无部分唯一索引，等价实现（生成列 + 唯一索引）：
--   ALTER TABLE identity_claims
--     ADD COLUMN verified_key VARCHAR(128)
--       GENERATED ALWAYS AS (CASE WHEN verified = 1 AND revoked_at IS NULL
--                                 THEN claim_value_hash END) STORED,
--     ADD UNIQUE KEY uk_claims_verified (app_id, claim_type, verified_key);
--   NULL 不参与唯一性判定，语义与部分唯一索引一致

-- 绑定关系：部分唯一索引保证「一个三方身份同期只绑一个账号」
CREATE TABLE oauth_bindings (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT       NOT NULL REFERENCES applications(id),
    external_user_id VARCHAR(128) NOT NULL,
    identity_id      BIGINT       NOT NULL REFERENCES oauth_identities(id),
    status           VARCHAR(16)  NOT NULL DEFAULT 'active',
    is_primary       BOOLEAN      NOT NULL DEFAULT false,
    bind_source      VARCHAR(32)  NOT NULL,
    bound_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    unbound_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX uk_bindings_active
    ON oauth_bindings (identity_id) WHERE status = 'active';
CREATE INDEX idx_bindings_user ON oauth_bindings (app_id, external_user_id, status);

-- 刷新令牌：只存哈希，支持轮转与重放检测
CREATE TABLE refresh_tokens (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT       NOT NULL,
    external_user_id VARCHAR(128) NOT NULL,
    token_hash       VARCHAR(128) NOT NULL UNIQUE,
    device_id        VARCHAR(128),
    scope            VARCHAR(512),
    expires_at       TIMESTAMPTZ  NOT NULL,
    rotated_from     BIGINT,
    revoked          BOOLEAN      NOT NULL DEFAULT false,
    revoked_reason   VARCHAR(64),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_rt_user ON refresh_tokens (app_id, external_user_id);

-- 账号合并操作记录：幂等与补偿的依据（约束 C4 三次独立事务合并必需）
CREATE TABLE merge_operations (
    id              BIGSERIAL PRIMARY KEY,
    app_id          BIGINT       NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    target_user_id  VARCHAR(128) NOT NULL,
    source_user_id  VARCHAR(128) NOT NULL,
    status          VARCHAR(16)  NOT NULL,
    remote_result   JSONB,
    attempts        INT          NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (app_id, idempotency_key)
);

CREATE INDEX idx_merge_pending ON merge_operations (status) WHERE status = 'pending';

-- 事件外发表（Transactional Outbox，修正 P0-3）
-- 事件与业务变更在同一事务写入，由独立 worker 投递，
-- 避免"事务回滚了但事件已经发出去"这种不可撤销的错配。
CREATE TABLE event_outbox (
    id             BIGSERIAL PRIMARY KEY,
    app_id         BIGINT       NOT NULL,
    event_id       VARCHAR(64)  NOT NULL UNIQUE,
    event_type     VARCHAR(64)  NOT NULL,
    schema_version INT          NOT NULL DEFAULT 1,
    payload        JSONB        NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'pending',
    attempts       INT          NOT NULL DEFAULT 0,
    next_retry_at  TIMESTAMPTZ,
    last_error     TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    sent_at        TIMESTAMPTZ
);

CREATE INDEX idx_outbox_pending ON event_outbox (next_retry_at) WHERE status = 'pending';

-- 业务端审计日志
CREATE TABLE auth_audit_logs (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT,
    external_user_id VARCHAR(128),
    platform         VARCHAR(32),
    scene            VARCHAR(32),
    client           VARCHAR(32),
    action           VARCHAR(32)  NOT NULL,
    result           VARCHAR(16)  NOT NULL,
    error_code       VARCHAR(64),
    client_ip        INET,
    user_agent       TEXT,
    trace_id         VARCHAR(64),
    detail           JSONB        NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user_time ON auth_audit_logs (app_id, external_user_id, created_at DESC);
CREATE INDEX idx_audit_client    ON auth_audit_logs (app_id, platform, client, created_at DESC);

-- 管理员授权关系（管理端）。管理员身份本身复用用户中心账号（约束 C4）。
CREATE TABLE admin_grants (
    id           BIGSERIAL PRIMARY KEY,
    subject_id   VARCHAR(128) NOT NULL,
    role         VARCHAR(64)  NOT NULL,
    scope_app_id BIGINT,
    granted_by   VARCHAR(128) NOT NULL,
    granted_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    UNIQUE (subject_id, role, scope_app_id)
);

-- 管理端审计（与业务端审计分离：保留期更长、查询权限更严格）
CREATE TABLE admin_audit_logs (
    id           BIGSERIAL PRIMARY KEY,
    subject_id   VARCHAR(128) NOT NULL,
    action       VARCHAR(64)  NOT NULL,
    target_type  VARCHAR(32)  NOT NULL,
    target_id    VARCHAR(128) NOT NULL,
    app_id       BIGINT,
    reason       TEXT         NOT NULL,
    before_state JSONB,
    after_state  JSONB,
    client_ip    INET,
    trace_id     VARCHAR(64),
    result       VARCHAR(16)  NOT NULL,
    error_code   VARCHAR(64),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_admin_audit_subject ON admin_audit_logs (subject_id, created_at DESC);
CREATE INDEX idx_admin_audit_target  ON admin_audit_logs (target_type, target_id, created_at DESC);

-- +goose Down

DROP TABLE IF EXISTS admin_audit_logs;
DROP TABLE IF EXISTS admin_grants;
DROP TABLE IF EXISTS auth_audit_logs;
DROP TABLE IF EXISTS event_outbox;
DROP TABLE IF EXISTS merge_operations;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS oauth_bindings;
DROP TABLE IF EXISTS identity_claims;
DROP TABLE IF EXISTS oauth_identities;
DROP TABLE IF EXISTS app_provider_configs;
DROP TABLE IF EXISTS applications;
