-- 三方登录统一接入服务 · 管理端数据补充
--
-- 00001 已经预建了 §15.3 的 admin_grants / admin_audit_logs（保留期 3 年、JSONB 快照），
-- 但【没有】管理员身份表：§15.3 说"复用用户中心账号"，但用户中心尚未落地，
-- 本期按用户指令走"本地账号密码起步"（参 docs/admin-quickstart.md）。
--
-- 演进路径：将来切 OIDC SSO / 接用户中心时，admin_users 的 password_hash 列废弃
-- 不写，subject_id 列填 IdP 的用户标识，下游 admin_grants / admin_audit_logs 零改动。
-- 这是把 §15.3 的 subject_id 设计成 VARCHAR 而不是 BIGINT 的原因。

-- +goose Up

-- 管理员账号（本地账号密码起步）。
--
-- ⚠️ password_hash 是本表唯一敏感列：bcrypt(cost=12)。任何 dump 都要过滤它。
CREATE TABLE admin_users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(64)  NOT NULL UNIQUE,
    password_hash   VARCHAR(128) NOT NULL,                -- bcrypt(cost=12)
    display_name    VARCHAR(128) NOT NULL DEFAULT '',
    role            VARCHAR(32)  NOT NULL DEFAULT 'viewer', -- 内置 4 角色（K 组未上线前 hardcode）
    status          SMALLINT     NOT NULL DEFAULT 1,        -- 1=enabled, 0=disabled
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT admin_users_role_check CHECK (role IN ('super_admin','config_admin','operator','viewer'))
);

-- 管理员会话。
--
-- 32 字节随机 token，base64url 编码后下发；库内只存 SHA-256（与 refresh_tokens 一致）。
-- expires_at 默认 8 小时；客户端登出时把 revoked_at 置位即可立即失效。
CREATE TABLE admin_sessions (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64)  NOT NULL UNIQUE,         -- SHA-256 hex
    client_ip   INET,
    user_agent  VARCHAR(255) NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ  NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_admin_sessions_user ON admin_sessions (user_id, created_at DESC);
CREATE INDEX idx_admin_sessions_expires ON admin_sessions (expires_at) WHERE revoked_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS admin_users;
