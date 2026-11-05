-- 00002: 账号审计日志（P0.5「谁在什么时候对哪个账号做了什么」）
--
-- 为什么本服务要自己记一份，而不是靠 social-login 的审计表：
--   social-login 只知道"我调用了一次 UC 的 close"，不知道 UC 这边到底改了什么；
--   而合规要回答的是"这个账号的数据什么时候被谁关掉的"。责任边界在哪一侧，
--   记录就该在哪一侧。
--
-- 三个设计决定：
--
--   1. 【与业务同一事务写入】。审计写在 store 的事务里，失败则整个操作回滚。
--      另一种做法是"操作成功后再写审计、失败只记 error 日志"，那会在数据库
--      抖动时产生"改了数据但查不到是谁改的"——恰恰是审计最该有用的时刻。
--      代价是一次额外的 INSERT，对本服务的写入量（万级/天）可以忽略。
--
--   2. 【只记已成为事实的状态变更】。被拒绝的合并、重复注销、幂等重放都不写：
--      它们没有改变任何数据，写进来只会让"这个账号被改过几次"变得不可读。
--      拒绝类事件由 social-login 的审计表负责（那边记 result=failure）。
--
--   3. 【不存凭证明文，只存类型与摘要】。detail 里只出现 claim_type 这类
--      元信息；手机号/邮箱的明文和解密后的值一律不进审计表——审计的保留期
--      比业务数据更长、可查的人更多，它是泄漏面最大的一张表。

-- +goose Up

CREATE TABLE account_audit_logs (
    id         bigserial   PRIMARY KEY,
    app_id     bigint      NOT NULL REFERENCES apps (id),
    -- 内部账号 id。建号时由 store 回填；合并记 target（"并到谁身上"）。
    -- 允许 NULL 是为了给"还没有账号 id 就发生的事"留位置，
    -- 但当前四个动作都能拿到 id，NULL 只是防御。
    account_id bigint      NULL,
    -- public_id 的快照。不 join accounts 取：账号将来若被物理清理（合规删除），
    -- 审计仍要能回答"当年动的是哪个用户"。
    user_id    text        NOT NULL,
    action     text        NOT NULL,
    -- 触发者。跨服务调用默认 "service"；调用方可用 X-Actor 声明自己是谁
    -- （例如 "social-login"）。真实的人在 social-login 那一侧，
    -- 通过 trace_id 关联——这是两服务分工的必然结果，不是遗漏。
    actor      text        NOT NULL DEFAULT 'service',
    trace_id   text        NOT NULL DEFAULT '',
    client_ip  text        NOT NULL DEFAULT '',
    user_agent text        NOT NULL DEFAULT '',
    detail     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_audit_action CHECK (action IN (
        'account.created',
        'account.merged',
        'claim.bound',
        'claim.replaced',
        'account.closed'
    ))
);

COMMENT ON TABLE  account_audit_logs        IS '账号状态变更审计。与业务写操作同事务，不留"改了但查不到"的窗口';
COMMENT ON COLUMN account_audit_logs.user_id IS 'public_id 快照，不依赖 accounts 表仍可读';
COMMENT ON COLUMN account_audit_logs.detail  IS '不含凭证明文；只放类型、来源、数量等元信息';

-- 按账号查"这个用户被谁动过"（客服与合规最常用的入口）。
CREATE INDEX idx_audit_app_user_time ON account_audit_logs (app_id, user_id, created_at DESC);
-- 按应用按时间翻页（运维视图）。
CREATE INDEX idx_audit_app_time ON account_audit_logs (app_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS account_audit_logs;
