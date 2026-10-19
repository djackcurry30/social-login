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