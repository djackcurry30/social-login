.PHONY: help tools tidy fmt vet lint build run test test-unit test-acceptance test-all \
        mock seed keygen migrate-up migrate-down migrate-status clean docker-up docker-down \
        compose-up compose-down compose-reset compose-logs image

# Go 参数。构建信息通过 -ldflags 注入，便于线上用 /healthz 确认部署版本。
GO              ?= go
BINARY          ?= bin/social-login
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT          ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILT_AT        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS         := -s -w \
                   -X github.com/djackcurry30/social-login/internal/bootstrap.Version=$(VERSION)

CONFIG          ?= configs/config.yaml
PG_CONTAINER    ?= social-login-pg
REDIS_CONTAINER ?= social-login-redis

help:
	@echo "常用目标："
	@echo "  make build           构建二进制到 $(BINARY)"
	@echo "  make run             本地启动服务（读取 $(CONFIG)）"
	@echo "  make test            跑全部测试（单元 + 验收）"
	@echo "  make test-unit       只跑单元测试（不依赖外部服务）"
	@echo "  make test-acceptance 跑第一期验收（需要 PG 与 Redis）"
	@echo "  make docker-up       用容器起本地 PG 与 Redis"
	@echo "  make compose-up      一条命令起全栈（app + pg + redis）"
	@echo "  make compose-down    停止全栈容器"
	@echo "  make compose-reset   停止全栈并清空数据卷"
	@echo "  make compose-logs    跟踪 app 容器日志"
	@echo "  make keygen          生成主密钥与签名密钥"
	@echo "  make mock            启动自建 OAuth2 测试服务"
	@echo "  make seed            写入本地联调数据（应用 + 渠道配置）"
	@echo "  make migrate-up      执行数据库迁移"
	@echo ""
	@echo "验收测试的环境变量："
	@echo "  TEST_DATABASE_URL  默认 postgres://postgres:postgres@127.0.0.1:5432/social_login?sslmode=disable"
	@echo "  TEST_REDIS_ADDR    默认 127.0.0.1:6379"

## 依赖整理
tidy:
	$(GO) mod tidy

## 代码质量
fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: fmt vet

## 构建与运行
#
# 注意：管理端前端在 web/ 下构建；前端产物需要"复制"一份到
# internal/embedweb/dist 才能被 go:embed 嵌入。
# - web-dist       同步（先 npm run build，再 cp 到 embedweb/dist）
# - build          只构建 Go 后端二进制（前端用 fallback 到 node 自服务）
build:
	@mkdir -p $(dir $(BINARY))
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/server

web-build:
	cd web && npm install --no-audit --no-fund
	cd web && npm run build

web-sync: web-build
	rm -rf internal/embedweb/dist
	cp -r web/dist internal/embedweb/dist
	@echo "前端已同步到 internal/embedweb/dist"

run:
	$(GO) run ./cmd/server -config $(CONFIG)

## 测试
#
# 注意：验收测试刻意【不】用内存桩替代数据库。
# 它要验证的部分唯一索引（uk_claims_verified / uk_bindings_active）、
# 事务隔离、递归 CTE 撤销链，都是数据库行为，桩测试不出真实语义。
test: test-unit test-acceptance

test-unit:
	$(GO) test ./internal/... -count=1

test-acceptance:
	$(GO) test ./test/... -count=1 -v

test-all: test

## 本地依赖
docker-up:
	@docker rm -f $(PG_CONTAINER) $(REDIS_CONTAINER) >/dev/null 2>&1 || true
	docker run -d --name $(PG_CONTAINER) \
		-e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres \
		-e POSTGRES_DB=social_login -p 5432:5432 \
		docker.m.daocloud.io/library/postgres:16-alpine
	docker run -d --name $(REDIS_CONTAINER) -p 6379:6379 \
		docker.m.daocloud.io/library/redis:7-alpine
	@echo "等待 PostgreSQL 就绪..."
	@for i in $$(seq 1 30); do \
		docker exec $(PG_CONTAINER) pg_isready -U postgres -d social_login >/dev/null 2>&1 && break; \
		sleep 1; \
	done
	@docker exec $(PG_CONTAINER) pg_isready -U postgres -d social_login

docker-down:
	-docker rm -f $(PG_CONTAINER) $(REDIS_CONTAINER)

## 全栈容器化（app + pg + redis，一条命令起）
#
# 与上面的 docker-up 的区别：
#   docker-up      只起 PG 与 Redis 两个依赖，app 在宿主机用 go run 跑
#   compose-up     把 app 也打进镜像，连同依赖一起编排
# 访问入口：http://localhost:8080/admin（admin / admin12345）
image:
	docker build -t social-login:local .

compose-up:
	docker compose up -d --build
	@echo ""
	@echo "管理端: http://localhost:8080/admin  (admin / admin12345)"
	@echo "日志:   make compose-logs"

compose-down:
	docker compose down

# 连数据卷一起清掉，下次 up 是一套全新环境
compose-reset:
	docker compose down -v

compose-logs:
	docker compose logs -f app

## 密钥与本地数据
keygen:
	$(GO) run ./cmd/keygen -out keys -kid k-$$(date -u +%Y%m%d)

mock:
	$(GO) run ./cmd/mockoauth2 -addr 127.0.0.1:9090

seed:
	$(GO) run ./cmd/seed -config $(CONFIG) \
		-app-code app_demo \
		-redirect-uri "http://localhost:3000/callback" \
		-oauth2-base-url "http://127.0.0.1:9090"

## 迁移
#
# 服务启动时也会自动执行迁移（migrate.enabled=true）。
# 生产环境必须把该开关关掉，由发布流程显式执行下面的命令——
# 让应用启动顺带改 schema，会在多副本滚动发布时引发并发迁移与半途失败。
migrate-up:
	$(GO) run ./cmd/migrate -config $(CONFIG) -dir up

migrate-down:
	$(GO) run ./cmd/migrate -config $(CONFIG) -dir down

migrate-status:
	$(GO) run ./cmd/migrate -config $(CONFIG) -dir status

clean:
	rm -rf bin keys
	rm -f .acc-test.log .unit-test.log
