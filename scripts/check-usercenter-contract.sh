#!/usr/bin/env bash
# scripts/check-usercenter-contract.sh — 用户中心契约符合性检查（v1.1）
#
# 用途：用户中心（对端）交付后，先用这个脚本做一次"契约体检"，再让本服务接上去。
# 它只做一件事：**按 docs/user-center-mvp-design.md §2 的契约逐条打真实端点，
# 断言状态码、错误信封与语义**。不依赖本服务、不依赖数据库。
#
# 为什么需要它：
#   - 联调那天最怕"接上就报 ACCOUNT.UNAVAILABLE"，而原因是对端路径写错/字段名不对。
#     这里能在 30 秒内把端点的基础行为筛一遍，把"协议不符"和"逻辑不符"分开。
#   - 第 3 步（写后立即按凭证反查）是对端最难做到的一条：强一致读。
#     读写分离有延迟时它会 404——这正是 P0-6 回源核对会失效的场景，
#     必须在对端上线前暴露，而不是靠线上事故发现。
#   - 第 7 步（跨应用隔离）是 v1.1 新增的核心要求：同一个手机号在两个应用里
#     必须是两个账号。做不到的话，App2 的用户会登进 App1 的账号，那是数据越权。
#   - 第 0 步（应用注册）是登录的前置条件：未注册的应用在对端一律 400
#     APP.UNKNOWN，也就是说"注册同步没接通"等于"该应用所有登录都失败"。
#
# 用法：
#   scripts/check-usercenter-contract.sh http://uc.internal:8080 [TOKEN] --app app_web
#   scripts/check-usercenter-contract.sh http://uc.internal:8080 TOKEN --app app_web --write
#   scripts/check-usercenter-contract.sh http://uc.internal:8080 TOKEN --app a1 --app2 a2 --write
#
# 参数：
#   --app   <key>   必填。被测应用（= 本服务的 applications.app_code），必须已在对端注册
#   --app2  <key>   可选。给了就做跨应用隔离检查（需要两个已注册应用）
#   --write         执行写操作（建号/合并/换绑）。默认只读
#   --claim type:value  指定用于建号的凭证，默认 phone:19900000001
#
# 默认【只读】：只做注册 / 404 / 信封探测。唯一会写的是第 0 步——把被测应用
# 本身注册上去（幂等 upsert，它本来就必须存在），否则后续每一项都会
# 400 APP.UNKNOWN 而看不出真正的问题。
# --write 才建真实账号；契约里没有 DELETE，写操作会在对端留下数据，
# 在测试环境以外跑写操作前，必须由人确认。
#
# 退出码：0 通过；1 有不符项；2 用法/连通性错误。

set -uo pipefail

BASE="${1:-}"
TOKEN="${2:-}"
shift $(( $# > 2 ? 2 : $# )) 2>/dev/null || true

WRITE=0
APP=""
APP2=""
CLAIM_TYPE="phone"
CLAIM_VALUE="19900000001"

while [ $# -gt 0 ]; do
  case "$1" in
    --write) WRITE=1; shift ;;
    --app)   APP="${2:-}"; shift 2 ;;
    --app2)  APP2="${2:-}"; shift 2 ;;
    --claim) CLAIM_TYPE="${2%%:*}"; CLAIM_VALUE="${2#*:}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$BASE" ] || [ -z "$APP" ]; then
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  [ -n "$BASE" ] && echo >&2 && echo "缺少 --app（被测应用的 app_code）" >&2
  exit 2
fi
BASE="${BASE%/}"

PASS=0
FAIL=0
WARN=0
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

pass() { green "  ok   $*"; PASS=$((PASS+1)); }
bad()  { red   "  FAIL $*"; FAIL=$((FAIL+1)); }
skip() { yellow "  skip $*"; }
warn() { yellow "  warn $*"; WARN=$((WARN+1)); }

# req METHOD PATH [BODY] [IDEM_KEY] → 输出 "STATUS\tBODY"
req() {
  local method="$1" path="$2" body="${3:-}" idem="${4:-}"
  local args=(-s -m 10 -o /tmp/uc_body.$$ -w '%{http_code}' -X "$method" "$BASE$path")
  [ -n "$TOKEN" ] && args+=(-H "Authorization: Bearer $TOKEN")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  [ -n "$idem" ] && args+=(-H "Idempotency-Key: $idem")
  local code
  code=$(curl "${args[@]}" 2>/dev/null) || { echo -e "000\t"; return; }
  printf '%s\t%s' "$code" "$(cat /tmp/uc_body.$$ 2>/dev/null)"
  rm -f /tmp/uc_body.$$
}

# json_get KEY：从上一段响应里取一个字符串字段（不引 jq，环境不一定有）
json_get() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1
}

# has_code BODY：是否带契约要求的错误信封
has_code() { printf '%s' "$1" | grep -q '"code"[[:space:]]*:'; }

# acct APP → /v1/apps/{app}/accounts
acct() { printf '/v1/apps/%s/accounts' "$1"; }

echo "==> 目标: $BASE"
echo "==> 应用: $APP$([ -n "$APP2" ] && echo "（隔离对照: $APP2）")"
echo "==> 模式: $([ "$WRITE" = 1 ] && echo '含写操作' || echo '只读')"
echo

# ---------- 0. 应用注册接口（先注册被测应用） ----------
# 顺序放在最前是刻意的：应用未注册时，后面每一项都会返回 400 APP.UNKNOWN，
# 报错信息会把人引向"账号逻辑有问题"，而真正的原因是"应用没同步过去"。
#
# 这一步写的是被测应用本身（幂等 upsert），不产生垃圾租户；
# 对端若未实现这个接口，本服务的注册同步会全部失败，属于必须知道的事。
reg_app() {
  local key="$1"
  local r code body
  r=$(req POST "/internal/v1/apps" "{\"app_key\":\"$key\",\"name\":\"contract-check\",\"status\":\"active\"}")
  code="${r%%$'\t'*}"; body="${r#*$'\t'}"
  case "$code" in
    200|201|204) pass "应用注册接口可用：$key" ;;
    400) bad "应用注册被拒（400）：$body —— 报文格式与契约不符？" ;;
    401|403) bad "应用注册鉴权被拒（$code）：服务间 token 与账号接口不一致？" ;;
    404|405|501) bad "对端未实现应用注册接口（$code）：本服务同步会全部失败，该应用的登录都会 400 APP.UNKNOWN" ;;
    000) bad "应用注册接口不可达" ;;
    *) bad "应用注册返回 $code：$body" ;;
  esac
}
reg_app "$APP"
[ -n "$APP2" ] && reg_app "$APP2"

# ---------- 0b. 连通性 + 应用已注册 ----------
step0=$(req GET "$(acct "$APP")/__probe_$$")
code="${step0%%$'\t'*}"; body="${step0#*$'\t'}"
if [ "$code" = "000" ]; then
  red "无法连接 $BASE（网络不通 / 地址错误 / 服务未启动）"
  exit 2
fi
case "$code" in
  401|403) bad "鉴权被拒（$code）：TOKEN 缺失或无效，后续检查无意义"; echo; yellow "提示：把对端要求的 token 作为第 2 个参数传入"; exit 1 ;;
  400)
    if printf '%s' "$body" | grep -q 'APP\.UNKNOWN'; then
      red "应用 $APP 未在用户中心注册（APP.UNKNOWN）"
      echo "  先注册应用再联调：本服务建应用时会同步调用 POST /internal/v1/apps，"
      echo "  存量应用需要跑一次性补注册脚本（见 docs/user-center-mvp-design.md §2.6）。"
      exit 1
    fi
    bad "探测请求返回 400：$body"
    ;;
  404)
    pass "连通性正常，未知账号返回 404"
    if has_code "$body"; then
      pass "404 带错误信封（ACCOUNT.NOT_FOUND）"
    else
      warn "404 未带错误信封 {code,message}；适配层只能按状态码兜底"
    fi
    ;;
  200) bad "查询不存在的账号返回 200（契约要求 404）" ;;
  *)   bad "未知账号返回 $code（契约要求 404）" ;;
esac

# ---------- 1. 按凭证反查：不存在的凭证 ----------
r=$(req GET "$(acct "$APP")/by-claim?type=$CLAIM_TYPE&value=__nobody_$$")
code="${r%%$'\t'*}"; body="${r#*$'\t'}"
case "$code" in
  404) pass "by-claim 对不存在的凭证返回 404" ;;
  200) bad "by-claim 对不存在的凭证返回 200；若对端把空结果当成功，我方会误判为'账号存在'" ;;
  *)   bad "by-claim 返回 $code（契约要求 200/404/409）" ;;
esac

# ---------- 2. 创建必须要求幂等键 ----------
r=$(req POST "$(acct "$APP")" '{"claims":[],"nickname":"contract-check","avatar_url":""}')
code="${r%%$'\t'*}"; body="${r#*$'\t'}"
case "$code" in
  400|422)
    pass "缺少 Idempotency-Key 时被拒绝（$code）"
    if has_code "$body"; then pass "400 带错误信封"; else warn "400 未带错误信封"; fi
    ;;
  200|201) bad "缺少 Idempotency-Key 仍然创建成功——对端没有强制幂等，P0-4 无法成立" ;;
  404|405|501) skip "对端不提供创建能力（$code），跳过建号相关检查" ;;
  *) bad "缺少幂等键返回 $code（应为 400/422）" ;;
esac

if [ "$WRITE" = 1 ] && [ "$code" != "404" ] && [ "$code" != "405" ] && [ "$code" != "501" ]; then
  # ---------- 3. 幂等创建 ----------
  KEY="contract-check-$$-$(date +%s)"
  BODY="{\"claims\":[{\"type\":\"$CLAIM_TYPE\",\"value\":\"$CLAIM_VALUE\",\"source\":\"wechat_phone\"}],\"nickname\":\"contract-check\",\"avatar_url\":\"\"}"

  r=$(req POST "$(acct "$APP")" "$BODY" "$KEY")
  code="${r%%$'\t'*}"; body="${r#*$'\t'}"
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    UID1=$(printf '%s' "$body" | json_get user_id)
    if [ -n "$UID1" ]; then pass "创建成功，user_id=$UID1"; else bad "创建响应缺少 user_id"; fi
  elif [ "$code" = "409" ]; then
    if has_code "$body" && printf '%s' "$body" | grep -q 'ACCOUNT\.CLAIM_TAKEN'; then
      yellow "  注意 凭证 $CLAIM_VALUE 已被占用（ACCOUNT.CLAIM_TAKEN）。请换一个未占用的 --claim 重跑"
    else
      yellow "  注意 凭证 $CLAIM_VALUE 已被占用（409），但未返回 ACCOUNT.CLAIM_TAKEN 信封。请换 --claim 重跑"
    fi
    UID1=""
  else
    bad "创建失败，返回 $code：$body"
    UID1=""
  fi

  if [ -n "${UID1:-}" ]; then
    # ---------- 4. 同一幂等键重放 ----------
    r2=$(req POST "$(acct "$APP")" "$BODY" "$KEY")
    code2="${r2%%$'\t'*}"; body2="${r2#*$'\t'}"
    UID2=$(printf '%s' "$body2" | json_get user_id)
    if [ "$code2" = "200" ] || [ "$code2" = "201" ]; then
      if [ "$UID1" = "$UID2" ]; then pass "幂等键重放返回同一账号（$UID2）"
      else bad "幂等键重放建出了另一个账号（$UID1 → $UID2）——重复首次登录会产生两个账号"; fi
    else
      bad "幂等键重放返回 $code2（应返回同一账号）"
    fi

    # ---------- 5. 写后立即反查（强一致读） ----------
    r3=$(req GET "$(acct "$APP")/by-claim?type=$CLAIM_TYPE&value=$CLAIM_VALUE")
    code3="${r3%%$'\t'*}"; body3="${r3#*$'\t'}"
    UID3=$(printf '%s' "$body3" | json_get user_id)
    case "$code3" in
      200)
        if [ "$UID3" = "$UID1" ]; then pass "写后立刻按凭证反查命中同一账号（强一致读成立）"
        else bad "写后反查命中另一个账号（$UID3 ≠ $UID1），数据不一致"; fi
        ;;
      404|409) bad "写后立刻反查返回 $code3——对端可能读写分离（弱一致）。P0-6 的回源核对会读到旧数据或误判，必须改成强一致读" ;;
      *) bad "写后反查返回 $code3" ;;
    esac

    # ---------- 6. 合并参数校验 ----------
    r4=$(req POST "$(acct "$APP")/merge" "{\"target_user_id\":\"$UID1\",\"source_user_id\":\"$UID1\",\"reason\":\"contract\"}" "contract-self-$$")
    code4="${r4%%$'\t'*}"; body4="${r4#*$'\t'}"
    case "$code4" in
      409|400)
        pass "target==source 被拒绝（$code4）"
        if has_code "$body4" && printf '%s' "$body4" | grep -q 'ACCOUNT\.MERGE_REJECTED'; then
          pass "拒绝合并带 ACCOUNT.MERGE_REJECTED 信封"
        else
          warn "拒绝合并未带 ACCOUNT.MERGE_REJECTED；适配层只能按状态码判为'参数问题'"
        fi
        ;;
      *) bad "target==source 返回 $code4（应 409/400）" ;;
    esac

    r5=$(req POST "$(acct "$APP")/merge" "{\"target_user_id\":\"$UID1\",\"source_user_id\":\"__missing_$$\",\"reason\":\"contract\"}" "contract-missing-$$")
    code5="${r5%%$'\t'*}"
    case "$code5" in
      404) pass "source 不存在返回 404" ;;
      *) bad "source 不存在返回 $code5（应 404）" ;;
    esac

    # ---------- 7. 跨应用隔离（v1.1 核心） ----------
    if [ -n "$APP2" ]; then
      r6=$(req POST "$(acct "$APP2")" "$BODY" "contract-iso-$$-$(date +%s)")
      code6="${r6%%$'\t'*}"; body6="${r6#*$'\t'}"
      UID6=$(printf '%s' "$body6" | json_get user_id)
      if [ "$code6" = "200" ] || [ "$code6" = "201" ]; then
        if [ -n "$UID6" ] && [ "$UID6" != "$UID1" ]; then
          pass "同一凭证在 $APP2 建出独立账号（$UID6），应用隔离成立"
        else
          bad "同一凭证在 $APP2 命中了 $APP 的账号（$UID6）——两个应用共用账号空间，数据越权"
        fi
        # 反向确认：在 APP2 里反查不得命中 APP 的账号
        r7=$(req GET "$(acct "$APP2")/by-claim?type=$CLAIM_TYPE&value=$CLAIM_VALUE")
        code7="${r7%%$'\t'*}"; body7="${r7#*$'\t'}"
        UID7=$(printf '%s' "$body7" | json_get user_id)
        if [ "$code7" = "200" ] && [ "$UID7" != "$UID6" ]; then
          bad "APP2 反查命中 $UID7，但建号返回的是 $UID6——同一凭证在本应用内对应了两个账号"
        elif [ "$code7" = "200" ]; then
          pass "APP2 反查只命中本应用账号"
        fi
        yellow "  注意 已在 $APP2 创建测试账号 ${UID6:-?}，需在对端侧清理"
      else
        warn "在 $APP2 建号返回 $code6，跳过隔离比对（APP2 是否已注册？）"
      fi

      # 跨应用合并必须被拒绝（R3）
      if [ -n "${UID6:-}" ]; then
        r8=$(req POST "$(acct "$APP")/merge" "{\"target_user_id\":\"$UID1\",\"source_user_id\":\"$UID6\",\"reason\":\"contract\"}" "contract-cross-$$")
        code8="${r8%%$'\t'*}"
        case "$code8" in
          404|409|400) pass "跨应用合并被拒绝（$code8）" ;;
          *) bad "跨应用合并返回 $code8——必须拒绝（R3），否则两个业务的账号会被搅在一起" ;;
        esac
      fi
    else
      skip "跳过跨应用隔离检查（未提供 --app2）"
    fi

    # ---------- 8. 换绑 ----------
    NEWVAL="${CLAIM_VALUE%?}9"
    r9=$(req PUT "$(acct "$APP")/$UID1/claims/$CLAIM_TYPE" "{\"value\":\"$NEWVAL\",\"source\":\"sms\"}")
    code9="${r9%%$'\t'*}"; body9="${r9#*$'\t'}"
    case "$code9" in
      200)
        if printf '%s' "$body9" | grep -q "$NEWVAL"; then
          pass "换绑成功，账号已切换到 $NEWVAL"
        else
          bad "换绑返回 200 但账号里没有新值"
        fi
        # 旧号必须释放
        r10=$(req GET "$(acct "$APP")/by-claim?type=$CLAIM_TYPE&value=$CLAIM_VALUE")
        code10="${r10%%$'\t'*}"
        case "$code10" in
          404) pass "换绑后旧凭证已释放（撤销即释放）" ;;
          *) bad "换绑后旧凭证仍可反查（$code10）——旧号会被永久占用，用户重新注册会撞'凭证被占用'" ;;
        esac
        ;;
      404|405|501) skip "对端未实现换绑端点（$code9）" ;;
      *) bad "换绑返回 $code9：$body9" ;;
    esac

    # ---------- 9. 注销（内部接口，路径在 /internal/v1 下） ----------
    #
    # 这一项专门盯路径：注销挂在 /internal/v1 而不是 /v1。写错前缀时对端返回
    # 404，而 404 与"账号不存在"同码——适配层若不区分信封，就会把"打错了"
    # 当成"已注销"，本地清理照做、对端账号还活着。
    r11=$(req POST "/internal/v1/apps/$APP/accounts/$UID1/close" "")
    code11="${r11%%$'\t'*}"; body11="${r11#$'\t'}"
    case "$code11" in
      200)
        case "$body11" in
          *closed*) pass "注销成功（内部接口路径正确）" ;;
          *) passing "注销返回 200 但未声明 closed 状态" ;;
        esac
        ;;
      404) bad "注销返回 404：检查是否用了 /v1 前缀（注销在 /internal/v1 下）" ;;
      401|403) bad "注销鉴权失败（$code11）：检查服务 token" ;;
      *) bad "注销返回 $code11：$body11" ;;
    esac

    # 重复注销必须幂等：客户端超时重试与"本地级联失败后再点一次"都会走到这里。
    r12=$(req POST "/internal/v1/apps/$APP/accounts/$UID1/close" "")
    code12="${r12%%$'\t'*}"
    case "$code12" in
      200) pass "重复注销幂等" ;;
      404) pass "重复注销返回 404（视为已注销，需适配层按信封区分）" ;;
      *) bad "重复注销返回 $code12，应幂等成功" ;;
    esac

    yellow "  注意 本次检查已在对端创建测试账号 $UID1 并注销，需在对端侧清理"
  fi
else
  skip "跳过建号/幂等/强一致读/合并/隔离/换绑检查（未加 --write，或对端不支持创建）"
fi

echo
echo "==> 结果：通过 $PASS 项，不符 $FAIL 项，警告 $WARN 项"
if [ "$FAIL" -gt 0 ]; then
  red "契约不符合，先修对端再联调。检查项含义见 docs/user-center-mvp-design.md §2"
  exit 1
fi
if [ "$WARN" -gt 0 ]; then
  yellow "基础项通过，但有 $WARN 项警告：错误信封缺失会让 409 的语义降级（见 §2.5）"
fi
green "契约符合"
