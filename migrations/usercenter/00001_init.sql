-- 00001: 用户中心 MVP 初始 schema
--
-- 设计依据：docs/user-center-mvp-design.md §3。
--
-- 与统一登录服务（social-login）的关系：
--   本服务持有【账号主数据】，登录/授权/令牌/绑定全在 social-login。
--   两边各自一个数据库，不跨库 join、不跨库读表——耦合只通过 HTTP 契约。
--   因此这里没有任何 oauth_* 表，也没有 accounts 之外的身份概念。
--
-- 五个设计决定，都有代价，写在这里避免以后被"顺手优化"掉：
--
--   1. 所有表的应用维度列叫 app_id，值是 apps.id（本地自增）；跨服务一律用
--      app_key（= social-login 的 app_code）。绝不要把 app_id 传出去：
--      它是本库的自增主键，换环境就会重号（§2.3）。
--
--   2. account_claims 冗余 app_id，并在 (app_id, account_id) 上做复合外键。
--      逻辑上 app_id 能从 accounts join 出来，但唯一索引必须建在
--      (app_id, claim_type, value_hash) 上；复合外键则让"凭证的 app_id 与
--      账号的 app_id 不一致"这种写错 SQL 的情况在数据库层面就无法提交。
--      多一个 (app_id, id) 唯一索引的代价，换掉一次跨租户串号的可能性。
--
--   3. 两个部分唯一索引是产品规则的直接落地，不是性能优化：
--        uk_claim_value        一个凭证值只能属于一个账号（跨账号唯一）
--        uk_claim_one_per_type 一个账号每类凭证只能有一条活跃（换号必须换绑）
--      两者都只作用于 revoked_at IS NULL 的行：撤销即释放号码，
--      但历史行保留——否则无法回答"这个号以前是谁的"（§12.2）。
--
--   4. 合并只记录【成功】的合并（status 列因此不存在）。被拒绝的合并
--      （target==source、跨应用、source 已关闭）没有副作用，重放时重新判定
--      即可；把拒绝也写进审计表会让"重放"返回 already_merged=true，
--      而那是在撒谎（这次调用并没有合并任何东西）。
--
--   5. 不建索引的列只有 created_at 这类"只给人看"的时间戳。所有按应用
--      查询的路径都以 app_id 打头，分片时天然是分片键（E5）。

-- +goose Up

-- ① 租户：一个业务应用一行。
--
-- status 用 smallint（1 启用 / 0 停用）而不是 text：这张表的读放大很低，
-- 但停用判断在每次请求的中间件里都会做，整数比较省掉一次字符串解析。
-- 对外仍然只暴露 "active" / "disabled"（契约里的词），转换在 HTTP 层。
CREATE TABLE apps (
    id         bigserial   PRIMARY KEY,
    app_key    text        NOT NULL,
    name       text        NOT NULL DEFAULT '',
    status     smallint    NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_apps_status   CHECK (status IN (0, 1)),
    CONSTRAINT uk_apps_app_key  UNIQUE (app_key)
);

COMMENT ON TABLE  apps          IS '租户：一个业务应用一行。app_key 取自 social-login 的 applications.app_code';
COMMENT ON COLUMN apps.app_key  IS '业务唯一键，建应用时生成且不可变；所有对外路径都用它做租户标识';
COMMENT ON COLUMN apps.status   IS '1 启用 / 0 停用。停用后本应用的全部账号接口返回 APP.DISABLED';

-- ② 账号。
--
-- public_id 是对外唯一标识（ULID），不用 id 对外：自增主键可枚举，
-- 而账号 id 会出现在业务方的用户表、令牌的 sub、webhook 事件里。
-- merged_into 指向合并目标：合并后 source 不删除，只置 closed + 指向 target，
-- 因为 public_id 已经发给业务方了，删掉会让对方的历史数据指向空气。
CREATE TABLE accounts (
    id          bigserial   PRIMARY KEY,
    app_id      bigint      NOT NULL REFERENCES apps (id),
    public_id   text        NOT NULL,
    status      text        NOT NULL DEFAULT 'active',
    nickname    text        NOT NULL DEFAULT '',
    avatar_url  text        NOT NULL DEFAULT '',
    merged_into bigint      NULL REFERENCES accounts (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_accounts_status CHECK (status IN ('active', 'frozen', 'closed')),
    CONSTRAINT uk_accounts_public_id UNIQUE (app_id, public_id),
    -- 供 account_claims 的复合外键引用（见下方 fk_claims_account）。
    CONSTRAINT uk_accounts_app_id_id UNIQUE (app_id, id)
);

COMMENT ON COLUMN accounts.public_id   IS '对外唯一标识（ULID），即契约里的 user_id';
COMMENT ON COLUMN accounts.merged_into IS '被合并时指向目标账号；非空且 status=closed 表示"这个 id 去哪了"';

-- ③ 凭证：查询走 value_hash，展示/审计走 value_cipher。
--
-- 只存密文无法按值查询（AES-GCM 每次随机 IV，同值不同密文）；
-- 只存哈希无法展示与审计。所以两列都要，这不是冗余而是两个用途。
CREATE TABLE account_claims (
    id            bigserial   PRIMARY KEY,
    app_id        bigint      NOT NULL,
    account_id    bigint      NOT NULL,
    claim_type    text        NOT NULL,
    value_hash    bytea       NOT NULL,
    hash_version  smallint    NOT NULL DEFAULT 1,
    value_cipher  bytea       NOT NULL,
    dek_id        text        NOT NULL,
    source        text        NOT NULL,
    verified_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz NULL,
    revoke_reason text        NULL,
    CONSTRAINT ck_claims_type CHECK (claim_type IN ('phone', 'email')),
    -- 撤销必须带原因，未撤销必须没有原因。少了这条，会出现"revoked_at 为空
    -- 但 revoke_reason=replaced"的行，谁也不知道它到底还算不算活跃。
    CONSTRAINT ck_claims_revoke CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
    CONSTRAINT ck_claims_revoke_reason
        CHECK (revoke_reason IS NULL OR revoke_reason IN ('replaced', 'merged_source', 'closed', 'admin')),
    CONSTRAINT fk_claims_account FOREIGN KEY (app_id, account_id)
        REFERENCES accounts (app_id, id)
);

COMMENT ON COLUMN account_claims.value_hash   IS 'HMAC-SHA256(按 app 派生的盐, 归一化值)；只用于等值查询';
COMMENT ON COLUMN account_claims.value_cipher IS 'AES-256-GCM 密文（nonce||ct||tag）；仅用于展示与审计，不参与查询';
COMMENT ON COLUMN account_claims.hash_version IS '哈希算法/盐版本，换盐时用于灰度迁移';

-- 一个凭证值只能被一个账号持有（跨账号唯一）。
CREATE UNIQUE INDEX uk_claim_value
    ON account_claims (app_id, claim_type, value_hash)
    WHERE revoked_at IS NULL;

-- 一个账号每类凭证最多一条活跃：换手机号必须换绑，不能并存。
--
-- 这条索引是"一个账号一个手机号"的强制实现。没有它，一个账号可以挂两个
-- 手机号，而 by-claim 无论返回哪个都是"看起来对、实际错"的数据。
CREATE UNIQUE INDEX uk_claim_one_per_type
    ON account_claims (app_id, account_id, claim_type)
    WHERE revoked_at IS NULL;

-- 读账号详情（含 Get/GetByClaim 的返回组装）。部分索引即可：
-- 线上路径永远只读活跃凭证，历史行只在运维视图里按 account_id 全表扫。
CREATE INDEX idx_claims_account_active
    ON account_claims (app_id, account_id)
    WHERE revoked_at IS NULL;

-- ④ 幂等键：写操作的结果快照。
--
-- 只服务 Create。Merge 的幂等键在 merges 表上——那张表本来就是流水，
-- 再往这里写一份会出现"两个地方都记了、有一处没写成功"的不一致。
CREATE TABLE idempotency_keys (
    app_id       bigint      NOT NULL REFERENCES apps (id),
    scope        text        NOT NULL,
    key          text        NOT NULL,
    request_hash bytea       NOT NULL,
    status_code  int         NOT NULL,
    response     jsonb       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_idem_scope CHECK (scope IN ('create_account')),
    PRIMARY KEY (app_id, scope, key)
);

COMMENT ON COLUMN idempotency_keys.request_hash IS '同键不同体的判据：不一致说明调用方复用了幂等键，必须拒绝而不是返回旧结果';
COMMENT ON COLUMN idempotency_keys.response     IS '成功响应快照，重放时原样返回（同一 user_id）';

-- ⑤ 合并流水：审计 + 幂等 + 可重放。
--
-- idem_key 上的唯一约束同时承担两件事：审计唯一性与"同一笔合并只执行一次"。
-- 没有它，补偿任务重试会把同一个 source 迁移两遍——第二遍看起来"成功"，
-- 实际什么都没做（source 已 closed），却会让调用方以为又合并了一次。
CREATE TABLE merges (
    id        bigserial   PRIMARY KEY,
    app_id    bigint      NOT NULL REFERENCES apps (id),
    idem_key  text        NOT NULL,
    target_id bigint      NOT NULL,
    source_id bigint      NOT NULL,
    reason    text        NOT NULL DEFAULT '',
    merged_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_merges_idem UNIQUE (app_id, idem_key),
    CONSTRAINT ck_merges_distinct CHECK (target_id <> source_id)
);

COMMENT ON TABLE merges IS '成功的合并流水。被拒绝的合并不入表（无副作用，重放时重新判定）';

-- +goose Down
DROP TABLE IF EXISTS merges;
DROP TABLE IF EXISTS idempotency_keys;
DROP TABLE IF EXISTS account_claims;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS apps;
