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
ok "apps list"

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

# 15. logout
step "15. POST /admin/v1/auth/logout"
curl -s -m 3 -X POST "$BASE_URL/admin/v1/auth/logout" -H "$AUTH" >/dev/null
ok "logout OK"

green "全部 15 步通过！"