-- 00004: 审计异步导出任务（§15.4 H 组）
--
-- 为什么需要一张任务表，而不是"同步把 CSV 吐给浏览器"（架构 §5.5 ①）：
--   auth_audit_logs 是单表可能上千万行的表，一次导出动辄几十万行。
--   同步等待会长时间占住连接与 goroutine，前端一旦断开还白跑一遍。
--   所以接口只提交任务返回 task_id，由后台 worker 落盘，再给出下载地址。
--
-- 为什么 id 用 VARCHAR 而不是 BIGSERIAL：
--   task_id 会出现在 URL 里给前端，自增数字可枚举——换个数字就能猜别人的
--   导出任务状态。这里用 16 字节随机 hex，不可枚举，也不需要额外的归属校验做兜底
--   （归属校验仍然做，因为不可枚举不是访问控制的替代品）。
--
-- 为什么 filter 存 JSONB 快照：
--   导出是"提交时刻的查询条件"，而不是"执行时刻的"。任务排队的这几秒里
--   若有人改了查询参数，导出的内容应当与提交时看到的一致。

-- +goose Up

CREATE TABLE audit_export_tasks (
    id            VARCHAR(32)  PRIMARY KEY,
    subject_id    VARCHAR(128) NOT NULL,
    filter        JSONB        NOT NULL DEFAULT '{}',
    status        VARCHAR(16)  NOT NULL,   -- pending | running | succeeded | failed
    row_count     BIGINT       NOT NULL DEFAULT 0,
    file_path     TEXT,
    file_size     BIGINT       NOT NULL DEFAULT 0,
    error_code    VARCHAR(64),
    error_message TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    -- 导出文件保留期（默认 7 天，见 application/auditexport）。到期由 worker 清理，
    -- 文件不删会让磁盘随审计量单调增长。
    expires_at    TIMESTAMPTZ
);

-- worker 每次只取最早的一条 pending；部分索引避免随历史任务增长而变慢。
CREATE INDEX idx_audit_export_pending ON audit_export_tasks (created_at)
    WHERE status = 'pending';

-- 管理端"我的导出任务"按主体倒序。
CREATE INDEX idx_audit_export_subject ON audit_export_tasks (subject_id, created_at DESC);

-- 清理任务按到期时间扫。
CREATE INDEX idx_audit_export_expires ON audit_export_tasks (expires_at)
    WHERE expires_at IS NOT NULL;

-- +goose Down

DROP TABLE IF EXISTS audit_export_tasks;
