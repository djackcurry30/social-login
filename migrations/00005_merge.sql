-- 00005: 合并操作表补列（第三期 · 账号合并链路）
--
-- 00001 建表时只放了最小字段。真正落地合并链路（§7.3）后需要多两项信息：
--
--   identity_id  触发合并的身份。排障时要回答"是哪一次授权导致的合并"，
--                只靠 target/source 两个 user_id 定位不到具体渠道与场景。
--   last_error   最近一次失败原因。merge_operations 的失败几乎都需要人工判断
--                （对端幂等是否生效、是否已被别人改过），没有原因就只能翻日志。
--   reason       本次合并的业务理由（"用户主动绑定触发" / "管理端手工推进"）。
--                合并是账号归属的重大变更，只留 target/source 无法回答"为什么"。
--
-- 另加一个 idx_merge_due 部分索引：补偿 worker 每轮扫 pending/failed，
-- 表会随合并次数增长，全表扫会逐渐变成慢查询。

-- +goose Up

ALTER TABLE merge_operations
    ADD COLUMN IF NOT EXISTS identity_id BIGINT,
    ADD COLUMN IF NOT EXISTS last_error  TEXT,
    ADD COLUMN IF NOT EXISTS reason      TEXT;

CREATE INDEX IF NOT EXISTS idx_merge_due ON merge_operations (updated_at)
    WHERE status IN ('pending', 'failed');

-- 管理端 D 组按应用 + 状态列表。
CREATE INDEX IF NOT EXISTS idx_merge_app_status ON merge_operations (app_id, status, created_at DESC);

-- +goose Down

DROP INDEX IF EXISTS idx_merge_app_status;
DROP INDEX IF EXISTS idx_merge_due;
ALTER TABLE merge_operations
    DROP COLUMN IF EXISTS reason,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS identity_id;
