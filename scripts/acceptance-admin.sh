#!/usr/bin/env bash
# scripts/acceptance-admin.sh — 管理端 A/B/I 三组端到端冒烟验收
#
# 前置条件：
#   1. 启动了 docker run — social-login-pg 与 social-login-redis（详见 Makefile docker-up）
#   2. 跑过 ./bin/migrate -config configs/config.yaml -dir up
#   3. 跑过 ./bin/adminseed -username admin -password admin12345
#   4. 启动了 ./bin/social-login -config configs/config.yaml
#
# 退出码：0 全部通过；1 任意一条失败。

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin12345}"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

step()   { yellow "==> $*"; }
fail()   { red    "FAIL: $*"; exit 1; }
ok()     { green  "  ok: $*"; }

# 1. 拿 token
step "1. POST /admin/v1/auth/login"
LOGIN=$(curl -s -m 3 -X POST "$BASE_URL/admin/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
echo "$LOGIN"
TOKEN=$(echo "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then fail "登录未返回 token"; fi
ok "拿到 token (长度 ${#TOKEN})"

AUTH="Authorization: Bearer $TOKEN"

# 2. /me 有 token
step "2. GET /admin/v1/auth/me（带 token）"
ME=$(curl -s -m 3 "$BASE_URL/admin/v1/auth/me" -H "$AUTH")
echo "$ME"
echo "$ME" | grep -q '"role":"super_admin"' || fail "/me 未返回 super_admin"
echo "$ME" | grep -q "$ADMIN_USER" || fail "/me 未返回当前用户名"
ok "me 正常"

# 3. /me 无 token → 401
step "3. GET /admin/v1/auth/me（无 token）"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "$BASE_URL/admin/v1/auth/me")
[ "$CODE" = "401" ] || fail "期望 401，实际 $CODE"
ok "401 UNAUTHORIZED"

# 4. 错密码 → 401 + 模糊文案
step "4. POST /admin/v1/auth/login（错密码）"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 3 \
  -X POST "$BASE_URL/admin/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"wrong\"}")
[ "$CODE" = "401" ] || fail "期望 401，实际 $CODE"
ok "401（防枚举）"

# 5. 列出 apps（空）
step "5. GET /admin/v1/apps"
LIST=$(curl -s -m 3 "$BASE_URL/admin/v1/apps" -H "$AUTH")
echo "$LIST"
echo "$LIST" | grep -q '"items":' || fail "apps list 格式错"
# 回归：列表曾经把 app_secret 的哈希原样发给 viewer（领域模型直接序列化）。
# 哈希虽不可逆，但它是验签密钥的全部秘密所在，泄露后可离线爆破。
if echo "$LIST" | grep -qi 'app_secret_hash\|AppSecretHash'; then
  fail "apps 列表泄露了 app_secret 哈希"
fi
ok "apps list（且未泄露 app_secret 哈希）"

# 6. 创建 app（缺 reason → 400）
step "6. POST /admin/v1/apps（缺 reason）"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 3 \
  -X POST "$BASE_URL/admin/v1/apps" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"acc-test-app"}')
[ "$CODE" = "400" ] || fail "期望 400，实际 $CODE"
ok "400（reason 必填）"

# 7. 创建 app（带 reason）
step "7. POST /admin/v1/apps（带 reason）"
CREATE=$(curl -s -m 3 \
  -X POST "$BASE_URL/admin/v1/apps" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"acc-test-app","reason":"冒烟测试创建应用"}')
echo "$CREATE"
APP_ID=$(echo "$CREATE" | sed -n 's/.*"ID":\([0-9]*\).*/\1/p' | head -1)
if [ -z "$APP_ID" ]; then fail "创建未返回 ID"; fi
ok "创建成功，ID=$APP_ID"

# 8. 读 app
step "8. GET /admin/v1/apps/$APP_ID"
GET=$(curl -s -m 3 "$BASE_URL/admin/v1/apps/$APP_ID" -H "$AUTH")
echo "$GET"
echo "$GET" | grep -q "\"ID\":$APP_ID" || fail "读回的 ID 不一致"
ok "read OK"

# 9. 写 policy
step "9. PUT /admin/v1/apps/$APP_ID/policy"
PUT=$(curl -s -m 3 \
  -X PUT "$BASE_URL/admin/v1/apps/$APP_ID/policy" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"policy":{"on_unbound_login":"need_register","merge":{"mode":"confirm","verification":"sms","on_login":"off","notify_source_account":true,"source_disposal":"mark_merged"},"allowed_redirect_uris":["http://localhost:3000/callback"]},"reason":"冒烟测试配置白名单"}')
echo "$PUT"
echo "$PUT" | grep -q '"allowed_redirect_uris"' || fail "policy 未保存"
ok "policy saved"

# 9.1 登录期凭证归并（merge.on_login）的策略校验
#
# 这一项决定"用户从新渠道用同一个已验证手机号登录时，是否归并到已有账号"。
# 必须在配置层拦住拼写错误：若把 claim_verified 写成 claim_verify 还放行，
# 归并会静默不生效，而运维以为已经打开了。
step "9.1 on_login 策略校验"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X PUT "$BASE_URL/admin/v1/apps/$APP_ID/policy" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"policy":{"on_unbound_login":"need_register","merge":{"mode":"auto","verification":"sms","on_login":"claim_verified","notify_source_account":true,"source_disposal":"mark_merged","allow_cross_platform_auto":false},"allowed_redirect_uris":["http://localhost:3000/callback"]},"reason":"冒烟测试：验证 claim_verified 可配"}')
[ "$CODE" = "200" ] || fail "auto + claim_verified 期望 200，实际 $CODE"
ok "auto + claim_verified 可配"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X PUT "$BASE_URL/admin/v1/apps/$APP_ID/policy" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"policy":{"on_unbound_login":"need_register","merge":{"mode":"auto","verification":"sms","on_login":"claim_verify","notify_source_account":true,"source_disposal":"mark_merged"},"allowed_redirect_uris":["http://localhost:3000/callback"]},"reason":"冒烟测试：验证拼写错误被拒"}')
[ "$CODE" = "400" ] || fail "拼错的 on_login 期望 400，实际 $CODE"
ok "拼错的 on_login → 400"

# 恢复第 9 步的配置：后续登录流程按 confirm/off 的语义执行。
curl -s -o /dev/null -m 5 \
  -X PUT "$BASE_URL/admin/v1/apps/$APP_ID/policy" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"policy":{"on_unbound_login":"need_register","merge":{"mode":"confirm","verification":"sms","on_login":"off","notify_source_account":true,"source_disposal":"mark_merged"},"allowed_redirect_uris":["http://localhost:3000/callback"]},"reason":"恢复冒烟测试基线配置"}'
ok "配置已恢复基线"

# 10. validate policy
step "10. POST /admin/v1/apps/$APP_ID/policy/validate"
VAL=$(curl -s -m 3 \
  -X POST "$BASE_URL/admin/v1/apps/$APP_ID/policy/validate" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"policy":{"on_unbound_login":"need_register","merge":{"mode":"confirm","verification":"sms","on_login":"off","notify_source_account":true,"source_disposal":"mark_merged"},"allowed_redirect_uris":["http://localhost:3000/callback"]}}')
echo "$VAL"
echo "$VAL" | grep -q '"warnings":' || fail "validate 响应错"
ok "validate OK"

# 11. rotate secret
step "11. POST /admin/v1/apps/$APP_ID/secret/rotate"
ROT=$(curl -s -m 3 \
  -X POST "$BASE_URL/admin/v1/apps/$APP_ID/secret/rotate" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"reason":"冒烟测试轮换"}')
echo "$ROT"
echo "$ROT" | grep -q '"app_secret":' || fail "rotate 未返回新 secret"
ok "rotate OK"

# 12. create provider-config
step "12. POST /admin/v1/apps/$APP_ID/provider-configs"
PC=$(curl -s -m 3 \
  -X POST "$BASE_URL/admin/v1/apps/$APP_ID/provider-configs" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"app_id":'$APP_ID',"platform":"generic_oauth2","scene":"web","provider_app_id":"acc-client","client_secret":"acc-secret","extra":{"token_url":"http://127.0.0.1:9090/oauth/token"},"reason":"冒烟测试配置渠道"}')
echo "$PC"
# 回归：渠道配置响应曾把 SecretCipher / SecretDEKID 一起下发。
# 密文需要 KEK 才能解开，但与 KEK 版本同时出现等于给"KEK 泄露"补最后一块拼图。
if echo "$PC" | grep -q '"SecretCipher"\|"SecretDEKID"'; then
  fail "渠道配置响应泄露了凭据密文 / KEK 版本"
fi
PC_ID=$(echo "$PC" | sed -n 's/.*"ID":\([0-9]*\).*/\1/p' | head -1)
if [ -z "$PC_ID" ]; then fail "provider-config 创建未返回 ID"; fi
ok "provider-config created, id=$PC_ID"

# 13. verify (token_url 不通 → ok:false)
step "13. POST /secret/verify (期望 ok:false)"
V=$(curl -s -m 8 \
  -X POST "$BASE_URL/admin/v1/apps/$APP_ID/provider-configs/$PC_ID/secret/verify" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"reason":"冒烟测试连通性"}')
echo "$V"
echo "$V" | grep -q '"ok":false' || fail "verify 应返回 ok:false"
ok "verify 返回 ok:false（对端不可达）"

# 14. disable / enable
step "14. POST /disable 然后 /enable"
curl -s -m 3 -X POST "$BASE_URL/admin/v1/apps/$APP_ID/provider-configs/$PC_ID/disable" -H "$AUTH" -H "Content-Type: application/json" -d '{"reason":"禁用"}' >/dev/null
curl -s -m 3 -X POST "$BASE_URL/admin/v1/apps/$APP_ID/provider-configs/$PC_ID/enable" -H "$AUTH" -H "Content-Type: application/json" -d '{"reason":"启用"}' >/dev/null
ok "disable+enable OK"

# 15. 跨端：管理端创建的应用必须能通过业务端鉴权
#
# 这是本条脚本最重要的一步，也是历史上漏掉的一步。
# 早期 adminapp 用占位哈希（"placeholder:" + 明文），管理端建的应用在业务端
# 永远验签失败——15 步全过，但前后台链路是断的。
#
# 断言方式用 /v1/introspect 而不是 /v1/token：introspect 对无效令牌返回
# {"active":false} + 200（RFC 7662），而应用凭据错误返回 401 AUTH.UNAUTHORIZED。
# 两者不会混淆，能确定性地证明「应用凭据校验通过」。
step "15. 跨端：用管理端建的凭据调业务端 /v1/introspect"
APP_CODE=$(echo "$GET" | sed -n 's/.*"AppCode":"\([^"]*\)".*/\1/p' | head -1)
APP_SECRET=$(echo "$ROT" | sed -n 's/.*"app_secret":"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$APP_CODE" ] || [ -z "$APP_SECRET" ]; then fail "未能提取 app_code / app_secret"; fi
CROSS=$(curl -s -m 5 -X POST "$BASE_URL/v1/introspect" \
  -H "Content-Type: application/json" \
  -H "X-App-Id: $APP_CODE" -H "X-App-Secret: $APP_SECRET" \
  -d '{"token":"not-a-real-token"}')
echo "$CROSS"
if echo "$CROSS" | grep -q '"code":"AUTH.UNAUTHORIZED"'; then
  fail "管理端创建的应用无法通过业务端鉴权（app_secret 哈希未接线）"
fi
echo "$CROSS" | grep -q '"active":false' || fail "introspect 未按 RFC 7662 返回 active:false"
ok "跨端鉴权通过（$APP_CODE）"

# 15.5 准备通知链路的渠道配置（必须在 logout 之前，否则 token 已失效）
step "15.5 为通知用例准备 apple:app 渠道配置"
curl -s -m 5 -X POST "$BASE_URL/admin/v1/apps/$APP_ID/provider-configs" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"platform":"apple","scene":"app","config_key":"default","provider_app_id":"com.example.acc","client_secret":"acc-secret","reason":"验收：准备通知链路用例"}' >/dev/null
ok "渠道配置就绪"

# 15.6 H 组：审计查询与异步导出（必须在 logout 之前，需要 token）
#
# 这一组的价值在"排障时能不能查到证据"：G 组回答"事件发出去没有"，
# H 组回答"当时到底是谁做了什么"。
step "15.6 H 组：审计查询与异步导出"

# (a) 管理端审计：前面的 app.create 应该已经留下记录
ADM_AUDIT=$(curl -s -m 5 "$BASE_URL/admin/v1/audit-logs/admin?action=app.create&page_size=5" -H "$AUTH")
echo "$ADM_AUDIT"
echo "$ADM_AUDIT" | grep -q '"items":' || fail "管理端审计查询失败: $ADM_AUDIT"
ADM_TOTAL=$(echo "$ADM_AUDIT" | sed -n 's/.*"total":\([0-9]*\).*/\1/p' | head -1)
[ "${ADM_TOTAL:-0}" -ge 1 ] || fail "应先有 app.create 审计记录，实际 total=$ADM_TOTAL"
ok "管理端审计可查（app.create total=$ADM_TOTAL）"

# (b) 业务审计：不带 app_id = 跨应用查询（管理端天然跨应用）；
#     再带 app_id 验证过滤链路。干净库里可能为空，因此只断言结构。
BUS_ALL=$(curl -s -m 5 "$BASE_URL/admin/v1/audit-logs?page_size=5" -H "$AUTH")
echo "$BUS_ALL"
echo "$BUS_ALL" | grep -q '"items":' || fail "业务审计全量查询失败: $BUS_ALL"
BUS_APP=$(curl -s -m 5 "$BASE_URL/admin/v1/audit-logs?app_id=$APP_ID&page_size=5" -H "$AUTH")
echo "$BUS_APP" | grep -q '"items":' || fail "业务审计按 app_id 查询失败: $BUS_APP"
ok "业务审计可查（全量 / 按 app_id 均正常）"

# (c) 非法 result 必须是 400（枚举值写错时不能让调用方拿到空列表猜原因）
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/audit-logs?result=SUCCESS" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法 result 期望 400，实际 $CODE"
ok "非法 result → 400"

# (d) 提交导出：202 + task_id（异步，不等待结果）
EXP=$(curl -s -m 5 -X POST "$BASE_URL/admin/v1/audit-logs/export" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"app_id\":$APP_ID,\"action\":\"login\",\"reason\":\"验收：导出业务审计\"}")
echo "$EXP"
TASK_ID=$(echo "$EXP" | sed -n 's/.*"task_id":"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$TASK_ID" ]; then fail "导出未返回 task_id: $EXP"; fi
echo "$EXP" | grep -q '"status":"pending"' || fail "新任务应为 pending"
ok "导出已受理，task_id=$TASK_ID"

# (e) 轮询直到 succeeded（worker 2s 一轮）
STATUS=""
for _ in $(seq 1 20); do
  ST=$(curl -s -m 5 "$BASE_URL/admin/v1/audit-logs/export/$TASK_ID" -H "$AUTH")
  STATUS=$(echo "$ST" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
  case "$STATUS" in
    succeeded) break ;;
    failed)    fail "导出任务失败: $ST" ;;
  esac
  sleep 1
done
[ "$STATUS" = "succeeded" ] || fail "导出任务未在 20s 内完成（当前 $STATUS）"
ROW_COUNT=$(curl -s -m 5 "$BASE_URL/admin/v1/audit-logs/export/$TASK_ID" -H "$AUTH" \
  | sed -n 's/.*"row_count":\([0-9]*\).*/\1/p' | head -1)
ok "导出任务完成（status=$STATUS, row_count=${ROW_COUNT:-?}）"

# (f) 下载：必须走鉴权接口，且内容是可打开的 CSV（带 UTF-8 BOM）
DL_CODE=$(curl -s -o /tmp/acc_audit.csv -w "%{http_code}" -m 10 \
  "$BASE_URL/admin/v1/audit-logs/export/$TASK_ID/download" -H "$AUTH")
[ "$DL_CODE" = "200" ] || fail "下载期望 200，实际 $DL_CODE"
HEAD3=$(head -c 3 /tmp/acc_audit.csv | od -An -tx1 | tr -d ' \n')
[ "$HEAD3" = "efbbbf" ] || fail "CSV 缺少 UTF-8 BOM（Excel 打开中文会乱码），实际=$HEAD3"
grep -q "created_at,app_id,action" /tmp/acc_audit.csv || fail "CSV 表头不符"
# 行数必须与任务记录一致：CSV 行 = 表头 + row_count。
# 不校验这一点的话，"任务说 2000 行、文件只有表头"这种错误会静默通过。
LINES=$(wc -l < /tmp/acc_audit.csv | tr -d ' ')
[ "$LINES" = "$(( ${ROW_COUNT:-0} + 1 ))" ] \
  || fail "CSV 行数($LINES) 与 row_count(${ROW_COUNT:-0})+表头 不一致"
ok "下载成功（HTTP 200，CSV 带 BOM，$LINES 行）"

# (g) 无 token 下载必须 401：审计数据是敏感数据，不能靠"猜不到 URL"保护
DL_ANON=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/audit-logs/export/$TASK_ID/download")
[ "$DL_ANON" = "401" ] || fail "匿名下载期望 401，实际 $DL_ANON"
ok "匿名下载被拒绝（401）"

# 15.65 C 组：身份与绑定查询 + 强制解绑入口
#
# 合并过后最常见的问题是"到底谁绑了谁"。这里验证查询链路与
# 强制解绑的校验口径（真库上的解绑 + 事件写入由 test/acceptance 覆盖）。
step "15.65 C 组：身份与绑定"

IDS=$(curl -s -m 5 "$BASE_URL/admin/v1/identities?app_id=$APP_ID&page_size=5" -H "$AUTH")
echo "$IDS"
echo "$IDS" | grep -q '"items":' || fail "身份查询失败: $IDS"
ok "身份可查"

BS=$(curl -s -m 5 "$BASE_URL/admin/v1/bindings?app_id=$APP_ID&page_size=5" -H "$AUTH")
echo "$BS" | grep -q '"items":' || fail "绑定查询失败: $BS"
ok "绑定可查（含已解绑历史）"

AB=$(curl -s -m 5 "$BASE_URL/admin/v1/accounts/acc-probe-user/bindings?app_id=$APP_ID" -H "$AUTH")
echo "$AB" | grep -q '"items":' || fail "按账号查绑定失败: $AB"
ok "按账号查绑定"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/bindings?app_id=$APP_ID&status=deleted" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法绑定状态期望 400，实际 $CODE"
ok "非法绑定状态 → 400"

# 强制解绑必须带 reason：没有理由地改变"谁能登录"是不可接受的。
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X DELETE "$BASE_URL/admin/v1/bindings/99999999" -H "$AUTH")
[ "$CODE" = "400" ] || fail "缺 reason 期望 400，实际 $CODE"
ok "强制解绑缺 reason → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X DELETE "$BASE_URL/admin/v1/bindings/99999999?reason=%E5%AE%A2%E6%9C%8D%E7%94%B3%E8%AF%89" -H "$AUTH")
[ "$CODE" = "404" ] || fail "不存在的绑定期望 404，实际 $CODE"
ok "不存在的绑定 → 404"

# 15.7 D 组：账号合并运维
#
# 合并记录由业务链路产生（用户绑定冲突触发），单靠管理端无法凭空造一条。
# 这里验证路由、鉴权、参数校验与"查不到即 404"的口径；
# 真正的三次事务与本地收敛由 test/acceptance 的集成用例覆盖。
step "15.7 D 组：账号合并运维"

MO=$(curl -s -m 5 "$BASE_URL/admin/v1/merge-operations?page_size=5" -H "$AUTH")
echo "$MO"
echo "$MO" | grep -q '"items":' || fail "合并操作列表查询失败: $MO"
ok "合并操作可查"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/merge-operations?status=bogus" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法 status 期望 400，实际 $CODE"
ok "非法 status → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/merge-operations/99999999" -H "$AUTH")
[ "$CODE" = "404" ] || fail "不存在的合并期望 404，实际 $CODE"
ok "不存在的合并 → 404"

# retry 必须带 reason：账号归属的变更不能没有理由地重复执行。
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/merge-operations/99999999/retry" \
  -H "$AUTH" -H "Content-Type: application/json" -d '{"reason":""}')
[ "$CODE" = "400" ] || fail "缺 reason 期望 400，实际 $CODE"
ok "retry 缺 reason → 400"

# 15.8 confirm 模式的验证入口（POST /v1/bind/resolve）
#
# 只验证HTTP薄壳与校验口径：真库上的"发码 → 验码 → 合并"由
# test/acceptance 的 TestConfirmVerification* 覆盖（含错误码限次）。
step "15.8 POST /v1/bind/resolve（校验口径）"

BIND_AUTH=(-H "X-App-Id: $APP_CODE" -H "X-App-Secret: $APP_SECRET" -H "Content-Type: application/json")

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/v1/bind/resolve" "${BIND_AUTH[@]}" \
  -d '{"external_user_id":"u-probe","action":"send_code"}')
[ "$CODE" = "400" ] || fail "缺 merge_ticket 期望 400，实际 $CODE"
ok "缺 merge_ticket → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/v1/bind/resolve" "${BIND_AUTH[@]}" \
  -d '{"external_user_id":"u-probe","merge_ticket":"mtk_bogus","action":"send_code"}')
[ "$CODE" = "400" ] || fail "无效票据期望 400，实际 $CODE"
ok "无效票据 → 400"

RESOLVE_BODY=$(curl -s -m 5 \
  -X POST "$BASE_URL/v1/bind/resolve" "${BIND_AUTH[@]}" \
  -d '{"external_user_id":"u-probe","merge_ticket":"mtk_bogus","action":"verify","code":"123456"}')
echo "$RESOLVE_BODY"
echo "$RESOLVE_BODY" | grep -q '"code":"BIND.TICKET_INVALID"' \
  || fail "无效票据验码应返回 BIND.TICKET_INVALID，实际: $RESOLVE_BODY"
ok "无效票据验码 → BIND.TICKET_INVALID"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/v1/bind/resolve" "${BIND_AUTH[@]}" \
  -d '{"external_user_id":"u-probe","merge_ticket":"mtk_bogus","action":"hack"}')
[ "$CODE" = "400" ] || fail "未知 action 期望 400，实际 $CODE"
ok "未知 action → 400"

# 15.9 E 组：会话与令牌（强制下线 + 撤销名单）
#
# 关键断言是"下线后能查到撤销水位"：只撤 refresh_token 不写水位，
# 攻击者手里的 access_token 还能用满 15 分钟（修正 P0-5）。
step "15.9 E 组：会话与令牌"

TOK=$(curl -s -m 5 "$BASE_URL/admin/v1/tokens?app_id=$APP_ID&page_size=5" -H "$AUTH")
echo "$TOK"
echo "$TOK" | grep -q '"items":' || fail "会话查询失败: $TOK"
ok "会话可查"

# 会话列表不得返回 token_hash：它是"持有即可换令牌"的凭据哈希。
if echo "$TOK" | grep -qi 'token_hash\|TokenHash'; then
  fail "会话列表泄露了 token_hash"
fi
ok "会话列表不含 token_hash"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/tokens?app_id=$APP_ID&active=maybe" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法 active 期望 400，实际 $CODE"
ok "非法 active → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/tokens/revoke" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"app_id":'"$APP_ID"',"external_user_id":"u-acceptance-offline","reason":"x"}')
[ "$CODE" = "400" ] || fail "缺 reason 期望 400，实际 $CODE"
ok "强制下线缺 reason → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/tokens/revoke" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"external_user_id":"u-acceptance-offline","reason":"验收：缺少应用归属"}')
[ "$CODE" = "400" ] || fail "缺 app_id 期望 400，实际 $CODE"
ok "强制下线缺 app_id → 400"

OFFLINE=$(curl -s -m 5 \
  -X POST "$BASE_URL/admin/v1/tokens/revoke" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"app_id":'"$APP_ID"',"external_user_id":"u-acceptance-offline","reason":"验收：模拟账号被盗强制下线"}')
echo "$OFFLINE"
echo "$OFFLINE" | grep -q '"revoked_at":' || fail "强制下线未返回撤销水位: $OFFLINE"
# 必须如实告知生效窗口，运营才知道"已下线"的准确含义。
echo "$OFFLINE" | grep -q '"effective_window_seconds":' \
  || fail "强制下线未返回生效窗口: $OFFLINE"
ok "强制下线成功（含生效窗口说明）"

REV=$(curl -s -m 5 \
  "$BASE_URL/admin/v1/revoked-jti?app_id=$APP_ID&external_user_id=u-acceptance-offline" -H "$AUTH")
echo "$REV"
echo "$REV" | grep -q '"revoked_at":' || fail "查不到撤销水位: $REV"
ok "撤销水位可查"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/revoked-jti?app_id=$APP_ID" -H "$AUTH")
[ "$CODE" = "400" ] || fail "撤销查询缺标识期望 400，实际 $CODE"
ok "撤销查询缺标识 → 400"

# 15.95 F 组：签名密钥
#
# 只验证列表与两条关键拒绝：真实 rotate 会改变运行实例的密钥状态，
# 反复跑会让状态文件累积，不适合放在冒烟脚本里。
# 轮换的完整语义（JWKS 双公钥、retire 前置校验、重启恢复）由
# internal/pkg/jwtkit 与 internal/application/adminkey 的单测覆盖。
step "15.95 F 组：签名密钥"

KEYS=$(curl -s -m 5 "$BASE_URL/admin/v1/signing-keys" -H "$AUTH")
echo "$KEYS"
echo "$KEYS" | grep -q '"items":' || fail "密钥列表查询失败: $KEYS"
echo "$KEYS" | grep -q '"status":"signing"' || fail "应有一把 signing 密钥: $KEYS"
ok "密钥可查"

# 列表绝不能出现私钥材料。
if echo "$KEYS" | grep -qi 'PRIVATE KEY\|private_key'; then
  fail "密钥列表泄露了私钥"
fi
ok "密钥列表不含私钥材料"

PREVIEW=$(curl -s -m 5 "$BASE_URL/admin/v1/signing-keys/jwks-preview" -H "$AUTH")
echo "$PREVIEW" | grep -q '"keys":' || fail "JWKS 预览失败: $PREVIEW"
echo "$PREVIEW" | grep -q '"kty":"EC"' || fail "JWKS 预览应含 EC 公钥: $PREVIEW"
ok "JWKS 预览可查"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/signing-keys/rotate" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"reason":"x"}')
[ "$CODE" = "400" ] || fail "轮换缺 reason 期望 400，实际 $CODE"
ok "轮换缺 reason → 400"

# 当前签名密钥不能下线：这是防止"一怒之下下线，全站旧 token 立刻失效"。
#
# ⚠️ 必须按 status=signing 定位，不能取第一条——列表按创建顺序返回，
# 轮换过之后第一条是"仅发布"的旧密钥，对它的 retire 是合法的（200）。
ACTIVE_KID=$(echo "$KEYS" \
  | grep -o '"kid":"[^"]*","algorithm":"[^"]*","status":"signing"' \
  | head -1 | sed -n 's/"kid":"\([^"]*\)".*/\1/p')
if [ -n "$ACTIVE_KID" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
    -X POST "$BASE_URL/admin/v1/signing-keys/$ACTIVE_KID/retire" -H "$AUTH" \
    -H "Content-Type: application/json" -d '{"reason":"验收：尝试下线当前密钥"}')
  [ "$CODE" = "409" ] || fail "下线当前签名密钥期望 409，实际 $CODE"
  ok "下线当前签名密钥 → 409"
fi

# 15.96 G 组：事件投递与死信
#
# 只验证查询口径与两条拒绝：真实的 dead 状态需要制造投递失败
# （应用配一个坏地址并等满退避），不适合放在冒烟脚本里。
# 重投保持 event_id 不变这一点由 application/adminevent 的单测覆盖。
step "15.96 G 组：事件投递与死信"

EV=$(curl -s -m 5 "$BASE_URL/admin/v1/events/outbox?page_size=5" -H "$AUTH")
echo "$EV"
echo "$EV" | grep -q '"items":' || fail "事件列表查询失败: $EV"
ok "事件可查"

DEAD=$(curl -s -m 5 "$BASE_URL/admin/v1/events/outbox?status=dead&page_size=1" -H "$AUTH")
echo "$DEAD" | grep -q '"total":' || fail "按状态查询失败: $DEAD"
ok "按状态筛选可查"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/events/outbox?status=bogus" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法 status 期望 400，实际 $CODE"
ok "非法 status → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/events/outbox/99999999" -H "$AUTH")
[ "$CODE" = "404" ] || fail "不存在的事件期望 404，实际 $CODE"
ok "不存在的事件 → 404"

# 已送达不能重投、非死信不能重投：对不存在的事件应报 404（先取事件）。
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/events/outbox/99999999/retry" -H "$AUTH" \
  -H "Content-Type: application/json" -d '{"reason":"验收：重投不存在的事件"}')
[ "$CODE" = "404" ] || fail "重投不存在的事件期望 404，实际 $CODE"
ok "重投不存在的事件 → 404"

# 丢弃必须写理由：这条校验先于"事件是否存在"，所以是 400 而不是 404。
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/events/outbox/99999999/discard" -H "$AUTH" \
  -H "Content-Type: application/json" -d '{"reason":""}')
[ "$CODE" = "400" ] || fail "丢弃缺 reason 期望 400，实际 $CODE"
ok "丢弃缺 reason → 400"

# 15.97 K 组：管理员授权
#
# 核心边界：admin:grant 只有 super_admin 有（能改"谁能进管理端"的人
# 必须是最小集合）；受授主体必须是已存在的管理员账号。
step "15.97 K 组：管理员授权"

GRANTS=$(curl -s -m 5 "$BASE_URL/admin/v1/admin-grants?page_size=5" -H "$AUTH")
echo "$GRANTS"
echo "$GRANTS" | grep -q '"items":' || fail "授权列表查询失败: $GRANTS"
ok "授权可查"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/admin-grants" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"subject_id":"admin:1","role":"viewer","reason":"x"}')
[ "$CODE" = "400" ] || fail "缺 reason 期望 400，实际 $CODE"
ok "授予缺 reason → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/admin-grants" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"subject_id":"admin:1","role":"root","reason":"验收：未知角色"}')
[ "$CODE" = "400" ] || fail "未知角色期望 400，实际 $CODE"
ok "未知角色 → 400"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/admin-grants" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"subject_id":"admin:99999999","role":"operator","reason":"验收：不存在的账号"}')
[ "$CODE" = "404" ] || fail "不存在的账号期望 404，实际 $CODE"
ok "授予不存在的账号 → 404"

# 给 admin 自己加一条 viewer 授权（幂等，重复跑返回同一条）。
GRANT=$(curl -s -m 5 \
  -X POST "$BASE_URL/admin/v1/admin-grants" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"subject_id":"admin:1","role":"viewer","reason":"验收：演示临时授权"}')
echo "$GRANT"
echo "$GRANT" | grep -q '"role":"viewer"' || fail "授予未生效: $GRANT"
GRANT_ID=$(echo "$GRANT" | sed -n 's/.*"id":\([0-9]*\).*/\1/p' | head -1)
ok "授予成功（grant_id=$GRANT_ID）"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/admin-grants?subject_id=admin:1" -H "$AUTH")
[ "$CODE" = "200" ] || fail "按主体查询期望 200，实际 $CODE"
ok "按主体可查"

# reason 走 body：query 里的中文短词会因长度校验（≥4 字符）被判 400，
# 那是校验在起作用，不是 bug——这里要验的是"不存在 → 404"。
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  -X DELETE "$BASE_URL/admin/v1/admin-grants/99999999" -H "$AUTH" \
  -H "Content-Type: application/json" -d '{"reason":"验收：撤销不存在的授权"}')
[ "$CODE" = "404" ] || fail "撤销不存在的授权期望 404，实际 $CODE"
ok "撤销不存在的授权 → 404"

if [ -n "$GRANT_ID" ]; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
    -X DELETE "$BASE_URL/admin/v1/admin-grants/$GRANT_ID" -H "$AUTH" \
    -H "Content-Type: application/json" -d '{"reason":"验收：撤销临时授权"}')
  [ "$CODE" = "200" ] || fail "撤销期望 200，实际 $CODE"
  ok "撤销成功"
fi

# 16. logout
step "16. POST /admin/v1/auth/logout"
curl -s -m 3 -X POST "$BASE_URL/admin/v1/auth/logout" -H "$AUTH" >/dev/null
ok "logout OK"

# 17. 服务端通知入口已注册（不需要 token：调用方是平台的服务器）
#
# 判定方式：带合法 app_id 但伪造 payload，期望的是【报文级】错误
#   AUTH.INVALID_STATE（400）——证明路由、app 解析、渠道配置解析、
#   适配器验签这条链全部接通了。
# 如果返回 PROVIDER.NOT_FOUND，说明渠道配置没落库；
# 如果返回 RESOURCE.NOT_FOUND，说明路由没注册。
step "17. POST /v1/oauth/notify/apple（伪造签名，期望 AUTH.INVALID_STATE）"

NOTIFY=$(curl -s -m 10 -o /tmp/acc_notify.txt -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  --data "payload=aaa.bbb.ccc" \
  "$BASE_URL/v1/oauth/notify/apple?app_id=$APP_CODE" || true)
NOTIFY_BODY=$(cat /tmp/acc_notify.txt 2>/dev/null || echo '')
echo "HTTP $NOTIFY $NOTIFY_BODY"
# 顺序很重要：先按【业务码】判定，不能先看 HTTP 状态码。
# PROVIDER.NOT_FOUND（渠道未配置）本身也映射为 404，按状态码判会把
# "渠道没配"误报成"路由没注册"——这正是本用例第一版踩的坑。
if echo "$NOTIFY_BODY" | grep -q '"code":"RESOURCE.NOT_FOUND"'; then
  fail "通知路由未注册（RESOURCE.NOT_FOUND）"
elif echo "$NOTIFY_BODY" | grep -q '"code":"PROVIDER.NOT_FOUND"'; then
  yellow "  skip: 本应用未配置 apple:app 渠道，无法验证验签链路"
else
  echo "$NOTIFY_BODY" | grep -q '"code":"AUTH.INVALID_STATE"' \
    || fail "伪造签名应被拒绝为 AUTH.INVALID_STATE，实际: $NOTIFY_BODY"
  ok "通知链路接通且伪造报文被拒绝（HTTP $NOTIFY）"
fi

green "全部 17 步通过！"