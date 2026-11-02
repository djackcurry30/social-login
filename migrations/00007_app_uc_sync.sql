-- 00007: 应用与用户中心的注册同步状态
--
-- 背景：用户中心的契约 v1.1 把所有业务路径都做成 /v1/apps/{app_key}/...，
-- 未注册的 app_key 一律 400 APP.UNKNOWN。也就是说"应用已注册"是登录的
-- 【前置条件】，不是配置装饰——用户中心上线后，一个没同步过去的应用
-- 表现为该应用所有登录都失败。
--
-- 为什么状态要落库而不是只打日志：
--   §2.6 的同步是旁路的（失败只 warn，不阻塞建应用）。如果状态只进日志，
--   运维问"这个应用注册到用户中心了吗"就只能翻日志，而日志早就滚掉了；
--   管理端也无从展示。落到行上，"已同步 / 未同步 + 最近失败原因"可以
--   直接在应用列表里看到。
--
-- 为什么不建一张独立的表：
--   状态与应用一一对应，且总是跟应用一起读（列表页）。独立建表只多一次
--   join，还会多一处"忘了更新"的机会。代价是 applications 多了两个
--   运维字段，所以两个字段都写了 COMMENT 说明归属。
--
-- 为什么【不加索引】：
--   对账任务是"全量重放"（每 5 分钟把全部应用 upsert 一遍），不是
--   "只查未同步的"。全量重放能自愈"对端被回滚 / 被手工清理"这类漂移；
--   只补未同步的话，远端删了租户、本地状态仍是"已同步"，永远修不回来。
--   既然是全表扫描，索引只会增加写入成本。

-- +goose Up
ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS uc_synced_at  timestamptz NULL,
    ADD COLUMN IF NOT EXISTS uc_sync_error text        NULL;

COMMENT ON COLUMN applications.uc_synced_at IS
    '最近一次成功注册到用户中心的时间；NULL 表示从未成功同步';
COMMENT ON COLUMN applications.uc_sync_error IS
    '最近一次同步失败的原因；成功后清空。仅用于管理端展示，业务不读';

-- +goose Down
ALTER TABLE applications
    DROP COLUMN IF EXISTS uc_sync_error,
    DROP COLUMN IF EXISTS uc_synced_at;
