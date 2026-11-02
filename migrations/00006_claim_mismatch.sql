-- 00006: 凭证漂移记录表（J 组 · 凭证一致性运维）
--
-- 为什么需要一张表，而不是只打日志 / 只发事件：
--
--   §8.5 规定"凡是用手机号做归并判定，必须先调 AccountProvider.GetByClaim
--   回源核对，不一致则拒绝归并并记录 identity.claim_mismatch 事件"。
--   事件（outbox）是【外发队列】——投递成功后就出队了，没人能按它查
--   "现在还有多少条没处理"。而 J 组的运维动作恰恰是"看还有几条未闭环、
--   逐条判断该不该撤销那条 claim"，这要求记录有【可变更的状态】。
--   所以这里是"事实表 + 状态机"，事件只是从这张表派生出去的同一件事。
--
-- 记录时机（只在这些分支，不是每次登录都写）：
--
--   account_not_found   用户中心说"没有人持有这个凭证"（换号 / 解绑）
--   account_mismatch    用户中心说归账号 A，本地绑定却挂在账号 B
--   multiple_accounts   该凭证在用户中心命中多个账号（数据侧已脏）
--   identity_missing    claim 指向的 identity 已被删除
--
-- 去重策略（关键）：
--
--   同一条 claim 的漂移是【持续性状态】，不是离散事件——用户换了手机号后，
--   每次登录都会命中同一处不一致。如果每次都插一行，一周就能把表写爆，
--   而且运维看到的"待处理条数"会随登录量变化，失去意义。
--   因此 (app_id, claim_id, kind) 在 status='open' 时唯一，
--   重复命中只累加 occurrences 并刷新 last_seen_at。
--
--   反过来，闭环之后（status='resolved'）再出现同一条，
--   应当作为【新的】一次漂移重新开一条记录——否则"上次已处理"会永久
--   吞掉同一处复发的漂移。

-- +goose Up

CREATE TABLE claim_mismatches (
    id                BIGSERIAL PRIMARY KEY,
    app_id            BIGINT       NOT NULL REFERENCES applications(id),
    claim_id          BIGINT       NOT NULL REFERENCES identity_claims(id),
    identity_id       BIGINT       NOT NULL,
    claim_type        VARCHAR(32)  NOT NULL,
    -- 完整哈希保留：与 identity_claims 比对靠它，运维拿它反查也是靠它。
    -- 对外展示由用例层截取前缀（与 C 组 ClaimItem 同口径）。
    claim_value_hash  VARCHAR(128) NOT NULL,
    -- 冗余 platform / claim_source，避免每次列表都 JOIN oauth_identities。
    platform          VARCHAR(32)  NOT NULL DEFAULT '',
    claim_source      VARCHAR(32)  NOT NULL DEFAULT '',
    kind              VARCHAR(32)  NOT NULL,
    -- expected = 本地绑定认为该凭证属于谁；actual = 用户中心说属于谁。
    -- 两者都可能为空（身份已删 / 用户中心查无此人），空值本身也是线索。
    expected_user_id  VARCHAR(128),
    actual_user_id    VARCHAR(128),
    detail            TEXT,
    status            VARCHAR(16)  NOT NULL DEFAULT 'open',
    -- 重复命中次数。为 1 说明只出现过一次，数值大说明这处漂移长期存在。
    occurrences       INTEGER      NOT NULL DEFAULT 1,
    first_seen_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    resolved_by       VARCHAR(64),
    resolution        TEXT,
    CONSTRAINT ck_claim_mismatch_kind CHECK (kind IN (
        'account_not_found', 'account_mismatch', 'multiple_accounts', 'identity_missing')),
    CONSTRAINT ck_claim_mismatch_status CHECK (status IN ('open', 'resolved'))
);

-- 去重的落点：同一 claim 的同一类漂移在未闭环时只有一行。
-- 用部分唯一索引而不是先 SELECT 再 INSERT：并发登录下后者会写重。
CREATE UNIQUE INDEX uk_claim_mismatch_open
    ON claim_mismatches (app_id, claim_id, kind)
    WHERE status = 'open';

-- J 组列表的默认视图：按应用筛未闭环，最近的在前。
CREATE INDEX idx_claim_mismatch_open
    ON claim_mismatches (app_id, last_seen_at DESC)
    WHERE status = 'open';

-- 按身份排查（用户申诉："我换了手机号，为什么还提示已绑定"）。
CREATE INDEX idx_claim_mismatch_identity
    ON claim_mismatches (app_id, identity_id);

-- 历史视图（含已闭环），分页按时间倒序。
CREATE INDEX idx_claim_mismatch_time ON claim_mismatches (app_id, first_seen_at DESC);

-- +goose Down

DROP INDEX IF EXISTS idx_claim_mismatch_time;
DROP INDEX IF EXISTS idx_claim_mismatch_identity;
DROP INDEX IF EXISTS idx_claim_mismatch_open;
DROP INDEX IF EXISTS uk_claim_mismatch_open;
DROP TABLE IF EXISTS claim_mismatches;
