-- 本地演示数据：给 G 组（事件投递）页面造几条可见的记录。
--
-- 为什么要 seed：真实的 dead 需要应用配置一个坏地址、等满退避
-- （1s / 10s / 1min / 10min / 1h，合计约 1 小时）才会出现。
-- 演示与联调时等不起，直接写两条记录让页面有东西可看。
--
-- ⚠️ 只用于本地 / 测试库。生产环境不要执行。
--
-- 用法：
--   docker compose exec -T pg psql -U postgres -d social_login < scripts/seed-events-demo.sql
--
-- 清理：
--   DELETE FROM event_outbox WHERE event_id LIKE 'evt_demo_%';

INSERT INTO event_outbox (
    app_id, event_id, event_type, schema_version, payload,
    status, attempts, last_error, created_at
)
SELECT a.id, 'evt_demo_dead_001', 'user.merged', 1,
       '{"target_user_id":"u-demo-001","source_user_id":"u-demo-old","identity_id":1,"notify_source_account":true}'::jsonb,
       'dead', 5,
       'webhook 返回 500：POST https://api.example.com/hooks/login 连接超时（30s）',
       now() - interval '2 hours'
FROM applications a
ORDER BY a.id
LIMIT 1
ON CONFLICT (event_id) DO NOTHING;

INSERT INTO event_outbox (
    app_id, event_id, event_type, schema_version, payload,
    status, attempts, last_error, created_at
)
SELECT a.id, 'evt_demo_skip_001', 'auth.login.succeeded', 1,
       '{"external_user_id":"u-demo-002","platform":"wechat","scene":"mini_program"}'::jsonb,
       'skipped', 1, '应用未配置 webhook_url（EventDeliverer 返回 ErrNoWebhook）',
       now() - interval '30 minutes'
FROM applications a
ORDER BY a.id
LIMIT 1
ON CONFLICT (event_id) DO NOTHING;

INSERT INTO event_outbox (
    app_id, event_id, event_type, schema_version, payload,
    status, attempts, next_retry_at, last_error, created_at
)
SELECT a.id, 'evt_demo_pending_001', 'binding.created', 1,
       '{"external_user_id":"u-demo-003","identity_id":7,"platform":"wechat"}'::jsonb,
       'pending', 2, now() + interval '4 minutes',
       'webhook 返回 502：上游网关重启中',
       now() - interval '40 seconds'
FROM applications a
ORDER BY a.id
LIMIT 1
ON CONFLICT (event_id) DO NOTHING;

SELECT status, count(*) FROM event_outbox
WHERE event_id LIKE 'evt_demo_%'
GROUP BY status ORDER BY status;
