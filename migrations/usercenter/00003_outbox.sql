-- 00003: 出站事件表（用户中心 → 登录中心）
--
-- 为什么需要 outbox 而不是"改完直接发一个 HTTP 请求"：
--
--   换绑与注销是【已经发生的事实】。如果推送失败就丢了，登录侧会一直用
--   过期 claim 做归并判定，直到某次对账才发现——而"漏了一次通知"在生产上
--   没有任何告警可依。所以：先在同一事务里写下"要通知什么"，再由后台投递器
--   重试，直到成功或进死信。
--
-- 只做一件事：claim.invalidated。
--
--   账号创建不需要通知（登录侧本来就是它触发的），合并的本地收敛由调用方
--   自己完成；真正"登录侧不知道"的只有用户中心侧的凭证变更与账号注销。
--
-- 不存凭证明文：payload 里只有类型与原因。接收方按 user_id 反查自己的绑定，
-- 不需要、也不应该知道新号码是多少——少一份明文就少一处泄漏面。

-- +goose Up

CREATE TABLE uc_outbox (
    id              bigserial   PRIMARY KEY,
    app_id          bigint      NOT NULL REFERENCES apps (id),
    event_type      text        NOT NULL,
    payload         jsonb       NOT NULL,
    status          text        NOT NULL DEFAULT 'pending',
    attempts        int         NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,

    CONSTRAINT ck_outbox_status CHECK (status IN ('pending', 'sent', 'dead')),
    CONSTRAINT ck_outbox_type   CHECK (event_type IN ('claim.invalidated'))
);

COMMENT ON TABLE  uc_outbox              IS '待投递给登录中心的出站事件；与业务同事务写入';
COMMENT ON COLUMN uc_outbox.next_attempt_at IS '下次可投递时间：失败后按指数退避推进，避免对端故障时打满重试';
COMMENT ON COLUMN uc_outbox.payload      IS '事件体，不含凭证明文';

-- 投递器只扫"待投递且到期"的行。部分索引让这张表长大后扫描量仍然恒定。
CREATE INDEX idx_outbox_due ON uc_outbox (next_attempt_at)
    WHERE status = 'pending';
-- 排查与运维视图：最近的事件。
CREATE INDEX idx_outbox_app_time ON uc_outbox (app_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS uc_outbox;
