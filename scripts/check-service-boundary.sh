#!/usr/bin/env bash
# scripts/check-service-boundary.sh — 两个服务的代码边界护栏
#
# 规则（2026-11-02 确认）：
#
#   同一 git 仓库、同一 Go module  —— 可以
#   共用 internal/pkg/**（通用工具） —— 可以
#   两个服务的【业务代码】互相 import —— 禁止，必须完全独立隔离
#
# 为什么需要这个脚本而不是靠自觉：
#
#	同仓库最大的风险不是"今天错了"，而是"某天有人图省事 import 了一个类型"。
#	这种引用一旦出现，两个服务就被焊死了：改 UC 的领域模型会编译不过登录中心，
#	而 CI 只会说"某处类型不匹配"，看不出根因是边界破了。等发现时通常已经有
#	七八处，拆回独立要动业务代码。
#
#	所以用脚本把"不允许"变成"跑不过"。检查分三层：
#	  1. 传递依赖（go list -deps）：能抓到 A→B→usercenter 这种间接引用
#	  2. 直接 import（grep，含 _test.go）：go list -deps 不含测试依赖，
#	     而测试恰恰是最容易破例的地方（"就一行断言，放这儿吧"）
#	  3. 交叉点白名单：只有 test/contract 允许同时引用两边，且必须在注释里说明
#
# 用法：
#   scripts/check-service-boundary.sh        # 有违规退出 1
#   make boundary                            # 同上（也挂在 make lint 里）
#
# 退出码：0 通过；1 有越界引用。

set -uo pipefail

cd "$(dirname "$0")/.."

MODULE="github.com/djackcurry30/social-login"
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[90m%s\033[0m\n' "$*"; }

pass() { green "  ok   $*"; }
bad()  { red   "  FAIL $*"; FAIL=$((FAIL+1)); }

# 登录中心的业务包前缀（用户中心不得引用其中任何一个）
LOGIN_BIZ='application|domain|infrastructure|interfaces|bootstrap|testsupport|embedweb'

# internal/pkg 下【混进了业务概念】的两个包，用户中心同样不得引用：
#   errs    里有 AUTH.* / BIND.* / PROVIDER.* 这些登录侧的业务错误码
#   adminx  是管理端的会话与权限工具
# 「放在 pkg 目录下」不等于「通用」。判断标准是：包里的标识符换到另一个
# 服务里是否仍然成立——errs.CodeBindIdentityTaken 显然不成立。
PKG_BIZ='errs|adminx'

echo "==> 服务边界检查"
echo "    用户中心：cmd/usercenter + internal/usercenter/**"
echo "    登录中心：cmd/server + internal/{application,domain,infrastructure,interfaces,bootstrap}/**"
echo "    允许共用：internal/pkg/**（pkg 下的 errs / adminx 含登录侧业务概念，除外）"
echo

# ------------------------------------------------------------
# 1. 传递依赖：能抓到间接引用（A 引用 B，B 引用 usercenter）
# ------------------------------------------------------------
echo "[1/3] 传递依赖（go list -deps）"

deps_of() {
  go list -deps "$1" 2>/dev/null || {
    red "无法解析 $1 的依赖（依赖未下载？）"
    exit 2
  }
}

hits=$(deps_of ./cmd/server | grep -E "^${MODULE}/internal/usercenter($|/)" || true)
if [ -n "$hits" ]; then
  bad "登录中心（cmd/server）的依赖图里出现了用户中心："
  printf '%s\n' "$hits" | sed 's/^/         /'
else
  pass "登录中心不依赖用户中心"
fi

hits=$(deps_of ./cmd/usercenter | grep -E "^${MODULE}/internal/((${LOGIN_BIZ})|pkg/(${PKG_BIZ}))($|/)" || true)
if [ -n "$hits" ]; then
  bad "用户中心（cmd/usercenter）的依赖图里出现了登录中心业务包："
  printf '%s\n' "$hits" | sed 's/^/         /'
else
  pass "用户中心不依赖登录中心业务包"
fi

# ------------------------------------------------------------
# 2. 直接 import：含测试文件（go list -deps 不覆盖 _test.go 的依赖）
# ------------------------------------------------------------
echo
echo "[2/3] 直接 import（含 _test.go）"

# 匹配 import 行，允许带别名：`foo "path"` 或 `_ "path"` 或直接 "path"
import_pat() { printf '^[[:space:]]*([A-Za-z0-9_.]+[[:space:]]+)?"%s' "$1"; }

# 2a. 用户中心（含测试）不得 import 登录中心业务包
hits=$(grep -rnE --include='*.go' \
        -e "$(import_pat "${MODULE}/internal/(${LOGIN_BIZ})/")" \
        -e "$(import_pat "${MODULE}/internal/pkg/(${PKG_BIZ})")" \
        internal/usercenter cmd/usercenter 2>/dev/null || true)
if [ -n "$hits" ]; then
  bad "用户中心引用了登录中心的包："
  printf '%s\n' "$hits" | sed 's/^/         /'
  dim "         修法：需要跨服务断言时放到 test/contract/；需要工具函数时放 internal/pkg/"
else
  pass "用户中心没有引用登录中心的包"
fi

# 2b. 登录中心（含测试）不得 import 用户中心
hits=$(grep -rnE --include='*.go' "$(import_pat "${MODULE}/internal/usercenter/")" \
        internal cmd 2>/dev/null \
        | grep -vE '^(internal/usercenter|cmd/usercenter)/' || true)
if [ -n "$hits" ]; then
  bad "登录中心引用了用户中心的包："
  printf '%s\n' "$hits" | sed 's/^/         /'
  dim "         修法：走 HTTP 契约（infrastructure/account），不要引用对端类型"
else
  pass "登录中心没有引用用户中心的包"
fi

# ------------------------------------------------------------
# 3. 白名单：test/ 下的跨服务引用只允许发生在 test/contract
# ------------------------------------------------------------
echo
echo "[3/3] 跨服务交叉点的白名单"

# test/acceptance 是登录中心的端到端验收：它可以用登录中心的包，
# 但不得直接引用用户中心的类型（对端只能通过 HTTP 访问）。
hits=$(grep -rnE --include='*.go' "$(import_pat "${MODULE}/internal/usercenter/")" \
        test/acceptance 2>/dev/null || true)
if [ -n "$hits" ]; then
  bad "test/acceptance 直接引用了用户中心的包（对端必须通过 HTTP 访问）："
  printf '%s\n' "$hits" | sed 's/^/         /'
else
  pass "test/acceptance 通过 HTTP 访问用户中心，未引用其类型"
fi

# test/contract 是唯一允许同时引用两边的地方；确认它没有悄悄扩散：
# 该目录下每个文件都必须属 package contract，避免有人往里塞业务逻辑。
if [ -d test/contract ]; then
  stray=$(grep -rLE --include='*.go' '^package contract' test/contract 2>/dev/null || true)
  if [ -n "$stray" ]; then
    bad "test/contract 下存在不属于 package contract 的文件："
    printf '%s\n' "$stray" | sed 's/^/         /'
  else
    pass "test/contract 是唯一的跨服务契约守卫目录"
  fi
fi

echo
if [ "$FAIL" -gt 0 ]; then
  red "==> 边界被打破：$FAIL 处"
  echo "    规则与理由见 docs/user-center-mvp-design.md §15"
  exit 1
fi
green "==> 边界完好：两个服务的业务代码零相互依赖"
