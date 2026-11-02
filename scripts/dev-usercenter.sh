#!/usr/bin/env bash
# scripts/dev-usercenter.sh — 本地起用户中心（建库 → 迁移 → 启动）
#
# 为什么要这个脚本：用户中心是独立服务、独立数据库，`docker compose up`
# 虽然会建库，但日常改代码时更常用"宿主机 go run + compose 里的 PG"。
# 手动敲三条命令（建库、迁移、启动）容易漏掉第一条，而漏掉的症状是
# 迁移报 `database "user_center" does not exist`——看起来像配置错，其实是库没建。
#
# 用法：
#   scripts/dev-usercenter.sh              # 建库 + 迁移 + 前台启动
#   scripts/dev-usercenter.sh -migrate     # 只建库 + 迁移
#
# 环境变量：
#   PG_CONTAINER  本地 PG 容器名（默认 social-login-pg-1）
#   UC_DSN        覆盖连接串（默认 postgres://postgres:postgres@127.0.0.1:15432/user_center）
#   UC_CONFIG     配置文件路径（默认 configs/usercenter.yaml）

set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-social-login-pg-1}"
UC_CONFIG="${UC_CONFIG:-configs/usercenter.yaml}"
UC_DSN="${UC_DSN:-postgres://postgres:postgres@127.0.0.1:15432/user_center?sslmode=disable}"

cd "$(dirname "$0")/.."

echo "==> 确保数据库 user_center 存在"
if docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  # 用 psql 的 -tAc 拿纯值，避免把 "CREATE DATABASE" 这类命令回显当成结果判断。
  exists=$(docker exec "$PG_CONTAINER" psql -U postgres -d postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname='user_center'")
  if [ "$exists" = "1" ]; then
    echo "    已存在，跳过"
  else
    docker exec "$PG_CONTAINER" psql -U postgres -d postgres -c "CREATE DATABASE user_center" >/dev/null
    echo "    已创建"
  fi
else
  echo "    ⚠️ 未找到容器 $PG_CONTAINER；若 PG 在别处，请自行建库后重试" >&2
fi

echo "==> 执行迁移"
go run ./cmd/usercenter -config "$UC_CONFIG" -migrate up

if [ "${1:-}" = "-migrate" ]; then
  echo "==> 仅迁移，退出"
  exit 0
fi

echo "==> 启动用户中心（Ctrl-C 退出）"
echo "    健康检查: curl http://127.0.0.1:8099/readyz"
echo "    契约检查: bash scripts/check-usercenter-contract.sh http://127.0.0.1:8099 dev-usercenter-token --app app_contract_a --app2 app_contract_b --write"
exec go run ./cmd/usercenter -config "$UC_CONFIG"
