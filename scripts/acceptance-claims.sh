#!/usr/bin/env bash
# scripts/acceptance-claims.sh — J 组（凭证一致性运维）端到端验收
#
# 覆盖三条真实运维链路：
#   1. 查询：凭证列表能按应用/类型/状态筛出来（含已撤销）
#   2. 读漂移：回源核对失败留下的记录能被查到，open_total 是全量
#   3. 撤销闭环：撤销凭证 → 凭证转 revoked → 名下漂移被闭环 → 重复撤销幂等
#
# 与 acceptance-admin.sh 的分工：那个脚本验证"管理端骨架（登录/RBAC/A 组）"，
# 本脚本专门验证 J 组，需要的造数走 SQL（身份只能由真实授权产生，
# 没有 API 可以直接建）。
#
# 前置条件：
#   1. docker compose up -d（pg 与 app 都在跑）
#   2. 数据库迁移已执行（migrate 服务自动跑，含 00006_claim_mismatch.sql）
#
# 退出码：0 全部通过；1 任意一条失败。

set -euo pipefail

cd "$(dirname "$0")/.."

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin12345}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
# KEEP=1 时保留造出的测试数据，便于失败后连库排查。
KEEP="${KEEP:-0}"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
step()   { yellow "==> $*"; }
fail()   { red    "FAIL: $*"; exit 1; }
ok()     { green  "  ok: $*"; }

# db 执行一条 SQL，返回裸值（-tA）。连库失败直接 fail——
# 这个脚本的价值就在于真实读写，连不上库时"跳过"等于什么都没验。
db() {
  docker compose -f "$COMPOSE_FILE" exec -T pg \
    psql -U postgres -d social_login -tAc "$1"
}

db "SELECT 1" >/dev/null 2>&1 || fail "无法连接数据库（docker compose exec pg psql 失败）。确认 pg 容器在运行。"

# 每次运行用唯一哈希，避免与历史数据撞部分唯一索引。
RUN_ID="$(date +%s)$$"
HASH="acc-${RUN_ID}-phone"

cleanup() {
  if [ "$KEEP" = "1" ]; then
    yellow "KEEP=1：保留测试数据（claim_hash=$HASH）"
    return
  fi
  # 删除顺序受外键约束：mismatch → claim → identity。
  db "DELETE FROM claim_mismatches WHERE claim_value_hash = '$HASH'" >/dev/null 2>&1 || true
  db "DELETE FROM identity_claims WHERE claim_value_hash = '$HASH'" >/dev/null 2>&1 || true
  db "DELETE FROM oauth_identities WHERE identity_key = 'acc-$RUN_ID'" >/dev/null 2>&1 || true
  if [ -n "${APP_ID:-}" ]; then
    db "DELETE FROM applications WHERE id = $APP_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. 登录
# ---------------------------------------------------------------------------
step "1. POST /admin/v1/auth/login"
LOGIN=$(curl -s -m 5 -X POST "$BASE_URL/admin/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
TOKEN=$(echo "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || fail "登录未返回 token: $LOGIN"
AUTH="Authorization: Bearer $TOKEN"
ok "拿到 token"

# ---------------------------------------------------------------------------
# 2. 空库下的只读端点（先证明路由与鉴权在，不依赖造数）
# ---------------------------------------------------------------------------
step "2. GET /admin/v1/claims（无过滤）"
LIST=$(curl -s -m 5 "$BASE_URL/admin/v1/claims?page_size=1" -H "$AUTH")
echo "$LIST" | grep -q '"items"' || fail "claims 列表格式错: $LIST"
ok "路由已注册且返回列表结构"

step "3. GET /admin/v1/claims?status=bogus（期望 400）"
CODE=$(curl -s -o /tmp/acc_claims_bad.txt -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/claims?status=bogus" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法 status 期望 400，实际 $CODE: $(cat /tmp/acc_claims_bad.txt)"
ok "400 REQUEST.INVALID"

step "4. GET /admin/v1/claims/mismatches（含 open_total）"
MM=$(curl -s -m 5 "$BASE_URL/admin/v1/claims/mismatches?page_size=1" -H "$AUTH")
echo "$MM" | grep -q '"open_total"' || fail "漂移列表缺 open_total: $MM"
ok "路由已注册且返回 open_total"

step "5. GET /admin/v1/claims/mismatches?kind=bogus（期望 400）"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
  "$BASE_URL/admin/v1/claims/mismatches?kind=bogus" -H "$AUTH")
[ "$CODE" = "400" ] || fail "非法 kind 期望 400，实际 $CODE"
ok "400 REQUEST.INVALID"

step "6. 无 token 访问 /claims（期望 401）"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$BASE_URL/admin/v1/claims")
[ "$CODE" = "401" ] || fail "期望 401，实际 $CODE"
ok "401 UNAUTHORIZED"

# ---------------------------------------------------------------------------
# 7. 撤销的参数校验（不存在的 id 也要先过 reason 校验）
# ---------------------------------------------------------------------------
step "7. POST /admin/v1/claims/999999999/revoke（缺 reason，期望 400）"
BODY=$(curl -s -m 5 -X POST "$BASE_URL/admin/v1/claims/999999999/revoke" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"app_id":1}')
echo "$BODY" | grep -q 'ADMIN.REASON_REQUIRED' \
  || fail "缺 reason 应为 ADMIN.REASON_REQUIRED，实际: $BODY"
ok "reason 必填"

step "8. POST /admin/v1/claims/999999999/revoke（有 reason，期望 404）"
CODE=$(curl -s -o /tmp/acc_claims_404.txt -w "%{http_code}" -m 5 \
  -X POST "$BASE_URL/admin/v1/claims/999999999/revoke" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"app_id":1,"reason":"验收：不存在的凭证"}')
BODY=$(cat /tmp/acc_claims_404.txt)
# 关键回归：仓储返回的裸领域错误若不在用例层翻译，会被归一化成 500。
[ "$CODE" = "404" ] || fail "不存在的凭证期望 404，实际 $CODE: $BODY"
ok "404（未被归一化成 500）"

# ---------------------------------------------------------------------------
# 9. 造数：一个应用 + 一条已验手机号凭证 + 一条未闭环漂移
# ---------------------------------------------------------------------------
step "9. 造数（应用 / 身份 / 凭证 / 漂移）"
CREATE=$(curl -s -m 5 -X POST "$BASE_URL/admin/v1/apps" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"acc-claims-app","reason":"J 组验收：创建测试应用"}')
APP_ID=$(echo "$CREATE" | sed -n 's/.*"ID":\([0-9]*\).*/\1/p' | head -1)
[ -n "$APP_ID" ] || fail "创建应用失败: $CREATE"

# 造数统一写成 "WITH t AS (INSERT ... RETURNING id) SELECT id FROM t"。
# 直接 INSERT ... RETURNING 在 psql -tA 下会额外打印一行命令标签
# （`INSERT 0 1`），把它一起塞进变量后，后续 SQL 就变成语法错误：
#   VALUES (1
#   INSERT 0 1, 'phone', ...)   ← 定位这个坑花了两次运行
IDENTITY_ID=$(db "WITH t AS (
    INSERT INTO oauth_identities
      (app_id, platform, provider_app_id, open_id, identity_key)
    VALUES ($APP_ID, 'wechat', 'acc-wx', 'openid-acc-$RUN_ID', 'acc-$RUN_ID')
    RETURNING id
  ) SELECT id FROM t")
case "$IDENTITY_ID" in '' | *[!0-9]*) fail "插入身份失败: $IDENTITY_ID" ;; esac

CLAIM_ID=$(db "WITH t AS (
    INSERT INTO identity_claims
      (app_id, identity_id, claim_type, claim_value_hash, verified, verified_at, source)
    VALUES ($APP_ID, $IDENTITY_ID, 'phone', '$HASH', true, now(), 'wechat_phone')
    RETURNING id
  ) SELECT id FROM t")
case "$CLAIM_ID" in '' | *[!0-9]*) fail "插入凭证失败: $CLAIM_ID" ;; esac

MM_ID=$(db "WITH t AS (
    INSERT INTO claim_mismatches
      (app_id, claim_id, identity_id, claim_type, claim_value_hash,
       platform, claim_source, kind, expected_user_id, detail)
    VALUES ($APP_ID, $CLAIM_ID, $IDENTITY_ID, 'phone', '$HASH',
            'wechat', 'wechat_phone', 'account_not_found', 'user-acc', '验收造数')
    RETURNING id
  ) SELECT id FROM t")
case "$MM_ID" in '' | *[!0-9]*) fail "插入漂移失败: $MM_ID" ;; esac
ok "app=$APP_ID identity=$IDENTITY_ID claim=$CLAIM_ID mismatch=$MM_ID"

# ---------------------------------------------------------------------------
# 10. 查询能命中
# ---------------------------------------------------------------------------
step "10. GET /admin/v1/claims?app_id=$APP_ID&claim_type=phone"
C=$(curl -s -m 5 "$BASE_URL/admin/v1/claims?app_id=$APP_ID&claim_type=phone" -H "$AUTH")
echo "$C" | grep -q "\"id\":$CLAIM_ID" || fail "未查到刚插入的凭证: $C"
# 哈希只能以 8 位前缀出现，且不能带出完整值（完整哈希可离线反查手机号）。
if echo "$C" | grep -q "$HASH"; then fail "凭证列表泄露了完整哈希"; fi
echo "$C" | grep -q '"status":"verified"' || fail "有效凭证状态应为 verified: $C"
ok "能查到凭证，且只返回哈希前缀"

step "11. GET /admin/v1/claims/mismatches?app_id=$APP_ID&status=open"
M=$(curl -s -m 5 "$BASE_URL/admin/v1/claims/mismatches?app_id=$APP_ID&status=open" -H "$AUTH")
echo "$M" | grep -q "\"id\":$MM_ID" || fail "未查到刚插入的漂移: $M"
echo "$M" | grep -q '"open_total":1' || fail "open_total 应为 1: $M"
echo "$M" | grep -q '"expected_user_id":"user-acc"' || fail "漂移记录应带本地归属: $M"
ok "能查到漂移，open_total=1"

# ---------------------------------------------------------------------------
# 12. 撤销并闭环
# ---------------------------------------------------------------------------
step "12. POST /admin/v1/claims/$CLAIM_ID/revoke"
R=$(curl -s -m 5 -X POST "$BASE_URL/admin/v1/claims/$CLAIM_ID/revoke" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"app_id\":$APP_ID,\"reason\":\"验收：用户申诉已换绑手机号\"}")
echo "$R" | grep -q '"already_revoked":false' || fail "首次撤销应 already_revoked=false: $R"
echo "$R" | grep -q '"resolved_mismatches":1' || fail "应闭环 1 条漂移: $R"
ok "撤销成功并闭环 1 条漂移"

step "13. 撤销后：凭证转 revoked，漂移转 resolved"
C=$(curl -s -m 5 "$BASE_URL/admin/v1/claims?app_id=$APP_ID&status=revoked" -H "$AUTH")
echo "$C" | grep -q "\"id\":$CLAIM_ID" || fail "撤销后应能在 revoked 筛选中查到: $C"
M=$(curl -s -m 5 "$BASE_URL/admin/v1/claims/mismatches?app_id=$APP_ID" -H "$AUTH")
echo "$M" | grep -q '"open_total":0' || fail "闭环后 open_total 应归零: $M"
echo "$M" | grep -q '"status":"resolved"' || fail "漂移状态应为 resolved: $M"
echo "$M" | grep -q "$ADMIN_USER" || fail "闭环记录应写明处理人: $M"
ok "状态闭环正确"

step "14. 重复撤销（幂等，already_revoked=true）"
R=$(curl -s -m 5 -X POST "$BASE_URL/admin/v1/claims/$CLAIM_ID/revoke" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"app_id\":$APP_ID,\"reason\":\"验收：重复点击\"}")
echo "$R" | grep -q '"already_revoked":true' || fail "重复撤销应 already_revoked=true: $R"
ok "幂等"

# ---------------------------------------------------------------------------
# 15. 审计留痕
# ---------------------------------------------------------------------------
step "15. GET /admin/v1/audit-logs/admin?action=claim.revoke"
A=$(curl -s -m 5 "$BASE_URL/admin/v1/audit-logs/admin?action=claim.revoke&page_size=5" -H "$AUTH")
echo "$A" | grep -q "\"target_id\":\"$CLAIM_ID\"" \
  || fail "撤销凭证必须在管理审计里留痕（before/after 快照）: $A"
ok "审计已记录 claim.revoke"

green "全部 15 步通过！"
