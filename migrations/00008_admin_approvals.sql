-- 双人复核（§15.5 高危操作要求）。
--
-- 背景：密钥轮换、渠道凭证轮换这类操作"一次误点 = 全站登录故障"，
-- 单个账号被窃取时不该有能力单独完成。所以引入"申请 → 另一名超管批准 →
-- 一次性消费"的审批单。
--
-- 设计取舍：
--   * 审批单【绑定动作与目标】，不是一个"万能通行证"：
--     action + app_id 必须与真正执行的接口一致，否则批准 A 就能执行 B。
--   * 【一次性】：consumed_at 非空即作废。重放攻击面比"忘记删"小得多。
--   * 【有有效期】：默认 30 分钟。批准的上下文（谁要做什么）过一阵可能已变。
--   * 【不留 payload 明文】：只存 payload_hash。审批单里如果带密钥/凭证明文，
--     它自己就变成了新的泄漏点。

-- +goose Up

CREATE TABLE admin_approvals (
    id             BIGSERIAL PRIMARY KEY,
    -- 动作标识，与审计 action 同口径：app.rotate_secret / config.rotate / key.rotate
    action         VARCHAR(64)  NOT NULL,
    -- 目标应用。NULL 表示不属于某个应用（例如签名密钥轮换是全局的）。
    app_id         BIGINT,
    -- 请求摘要（sha256 hex）。用于核对"批准的是不是同一件事"，
    -- 不存原文：原文可能含凭证。
    payload_hash   VARCHAR(64)  NOT NULL DEFAULT '',
    -- 申请人 / 批准人（admin_users.id）。两者必须不同——这是"双人"的唯一含义。
    requested_by   BIGINT       NOT NULL REFERENCES admin_users(id),
    requested_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    reason         VARCHAR(512) NOT NULL DEFAULT '',
    status         VARCHAR(16)  NOT NULL DEFAULT 'pending',
    -- pending | approved | rejected | consumed
    approved_by    BIGINT       REFERENCES admin_users(id),
    approved_at    TIMESTAMPTZ,
    -- 执行时间。非空即已消费，不能再用于第二次操作。
    consumed_at    TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ  NOT NULL,

    CONSTRAINT admin_approvals_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'consumed')),
    -- 自批在数据库层就挡掉：应用层判漏了也不会产生"一个人批自己"的记录。
    CONSTRAINT admin_approvals_four_eyes
        CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

-- 列表按状态 + 时间倒序；过期清理按 expires_at。
CREATE INDEX idx_admin_approvals_status_time ON admin_approvals (status, requested_at DESC);
CREATE INDEX idx_admin_approvals_expires ON admin_approvals (expires_at) WHERE status = 'pending';

COMMENT ON TABLE admin_approvals IS '高危操作的双人复核审批单（一次性、有有效期、绑定动作与应用）';

-- +goose Down
DROP TABLE IF EXISTS admin_approvals;
