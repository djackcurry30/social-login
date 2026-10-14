# 技术栈选型

> 配套文档：`architecture-design.md`（v0.9）· `design-review.md`
> 本文档只回答一个问题：**用哪些 Go 生态的库来实现这套设计，以及为什么不用别的。**
> 每一项都给出「选了什么 / 为什么不选常见的替代品」，避免后续在 PR 里反复争论。

---

## 0. 先定两个基础决策（影响面最大，必须先拍板）

### 0.1 数据库：PostgreSQL 16（不是 MySQL）

架构文档写的是「MySQL 或 PostgreSQL」，编码前必须二选一。**本项目选 PostgreSQL**，理由不是偏好，而是设计里已经用到了 PostgreSQL 的独有特性：

| 设计中的依赖点 | PostgreSQL | MySQL 8 |
| --- | --- | --- |
| **部分唯一索引**（`uk_claims_verified WHERE verified = true AND revoked_at IS NULL`） | 原生支持（§6.2 的核心约束 P0-1） | ❌ 不支持，需用生成列 + 唯一索引绕过，语义等价但可读性差、易写错 |
| **`FOR UPDATE SKIP LOCKED`**（补偿任务与 Outbox worker 多副本安全拉取，§12） | 原生支持 | 8.0 支持 |
| **JSONB**（`policy` / `extra` / `profile_snapshot` / `detail` / `before_state`） | JSONB 可建 GIN 索引，可直接索引查询 | JSON 可查询但无等价索引能力 |
| **`INET` 类型**（`auth_audit_logs.client_ip`） | 原生 | ❌ 需存 VARCHAR |

切换成本对比：**现在选 PostgreSQL = 0 成本；用 MySQL 写完之后再迁移 = 重写全部迁移脚本 + 改索引写法 + 改 IP 存储**。

> 若团队 MySQL 运维能力强、且不接受引入新数据库，需明确接受上面 4 项降级方案，并在 `migrations/` 中统一使用生成列写法。**这是一个必须显式决策的点，不能默认。**

### 0.2 Web 框架：chi v5（不是 gin / echo / fiber）

**选 chi**，理由：

1. **100% 实现 `net/http` 的 `http.Handler` 接口**。中间件、测试、`httptest` 全部走标准库，不引入框架专有 context。本项目有 5 类中间件（app 鉴权、管理员 RBAC、限流、审计、trace），需要自由组合，chi 的中间件模型最干净。
2. 本项目有**两套完全独立的鉴权体系**（业务端 `appId+secret`、管理端 Bearer+RBAC），需要按路径前缀挂载不同中间件链。chi 的 `Route`/`Group`/`Mount` 天然适配（§15.2）。
3. 零依赖、可读、维护活跃。

**否决原因**：

| 框架 | 否决理由 |
| --- | --- |
| **gin** | 自研 `gin.Context`，与标准库中间件不互通；本项目大量中间件需复用（限流、审计），会产生适配层 |
| **echo** | 同 gin，且抽象层更多 |
| **fiber** | 基于 fasthttp，**不是 `net/http` 接口**，`httptest`、OpenTelemetry 官方中间件、部分标准库生态都无法直接用 |
| **纯标准库** | Go 1.22+ 的 `ServeMux` 已支持 method + path 参数，简单场景够用；但本项目需要「中间件按路由分组挂载」，手写会很啰嗦。**chi 本质上是标准库的薄封装，保留升级到纯标准库的可能** |

---

## 1. 总览

| 分层 | 用途 | 选型 | 版本 |
| --- | --- | --- | --- |
| 语言 | — | **Go** | ≥ 1.23（最低 1.22，需 `net/http` 增强路由） |
| Web | 路由 + 中间件 | **go-chi/chi** | v5 |
| 配置 | 多源配置加载 | **knadh/koanf** | v2 |
| 数据库 | 驱动 | **jackc/pgx** | v5 |
| 数据库 | SQL → 类型安全代码 | **sqlc** | v1 |
| 数据库 | 迁移 | **pressly/goose** | v3 |
| 缓存/队列 | Redis 客户端 | **redis/go-redis** | v9 |
| 缓存/队列 | 分布式锁 | **go-redis + Lua**（自研薄封装） | — |
| 认证 | JWT 签发与校验 | **golang-jwt/jwt** | v5 |
| 认证 | JWK / JWKS（Apple 验签 + 自建 JWKS） | **lestrrat-go/jwx** | v2 |
| 认证 | 通用 OAuth2 客户端 | **golang.org/x/oauth2** | latest |
| HTTP 客户端 | 三方平台调用 | **标准库 + 自研薄封装** | — |
| 校验 | 请求 DTO | **go-playground/validator** | v10 |
| 日志 | 结构化日志 | **标准库 log/slog** | 内置 |
| 可观测 | 链路追踪 | **OpenTelemetry**（otel + otelhttp + otlp） | latest |
| 可观测 | 指标 | **prometheus/client_golang** | v1 |
| 错误 | 错误码与包装 | **自研 `pkg/errs`** | — |
| 加密 | 凭据加密 / 哈希 | **标准库 crypto**（AES-GCM / ECDSA / SHA-256） | 内置 |
| 测试 | 断言与 mock | **stretchr/testify** | v1 |
| 测试 | 依赖容器 | **testcontainers-go** | — |
| 测试 | 接口 mock 生成 | **go.uber.org/mock**（原 golang/mock） | latest |
| 代码生成 | OpenAPI → server stub / client | **oapi-codegen** | v2 |
| 质量 | 静态检查 | **golangci-lint** | v1 |
| 质量 | 漏洞扫描 | **govulncheck** | latest |
| 构建 | 任务编排 | **Makefile**（不引入 task runner） | — |
| 本地依赖 | PG + Redis | **docker-compose** | — |
| 容器化 | 运行镜像 | **多阶段构建 + distroless** | — |

---

## 2. 逐项说明

### 2.1 配置：koanf v2

**为什么不用 viper**：viper 依赖树庞大（引入 fsnotify、cast、afero 等十几个包），且有全局单例状态的坏味道。koanf 是它的轻量替代，多源合并（默认值 → YAML → 环境变量）的模型更清晰，无全局状态。

**配置分层约定**（对应架构 §9）：

```
configs/config.yaml          # 默认值，入库
configs/config.local.yaml    # 本地覆盖，.gitignore 排除
环境变量 AUTH__DB__DSN        # 最高优先级，容器部署用
```

**敏感项不走配置文件**：DB 密码、Redis 密码、KMS 凭据一律只从环境变量读，配置文件里只放占位符。这与 `.gitignore` 的凭据规则是一套防线。

### 2.2 数据库访问：sqlc + pgx，不用 ORM

**这是本项目最需要解释的一个选择。**

**为什么不用 GORM**：本设计里有大量 ORM 会碍事的场景：

| 场景 | GORM 的痛点 |
| --- | --- |
| `CREATE UNIQUE INDEX ... WHERE verified = true`（P0-1） | ORM 无能力表达，仍需手写 SQL 迁移 |
| 部分唯一索引冲突要**转成业务语义**（并发绑定兜底，§5.2） | 需要精确捕获 PG 错误码 `23505` + 约束名，GORM 的错误包装会丢失细节 |
| `SELECT ... FOR UPDATE SKIP LOCKED`（worker 拉取） | 需 `Raw()` 绕过 |
| `UPDATE ... WHERE status = 'pending' AND attempts < N RETURNING *` | 需 `Raw()` 绕过 |
| JSONB 字段的部分更新（`policy.merge.mode`） | 需 `Raw()` 绕过 |

结论：**核心查询路径最终都要落回手写 SQL，那不如一开始就 SQL 优先**，用 sqlc 拿到类型安全，而不是引入一个"半可用"的 ORM。

**为什么不用 ent**：ent 的 schema-as-code 会与 `migrations/` 中的手写 DDL 形成**两个真相源**——设计里已经把所有约束（部分唯一索引、生成列）写成 SQL 了，再用 ent 描述一遍必然漂移。

**sqlc 的工作流**：

```
internal/infrastructure/persistence/queries/*.sql   ← 手写 SQL（唯一真相源）
        ↓ sqlc generate
internal/infrastructure/persistence/sqlcgen/        ← 生成的类型安全代码（入库）
```

生成的代码入库（不放进 `.gitignore`），保证 CI 无需装 sqlc 也能编译；同时在 CI 中加一步 `sqlc diff` 检测"改了 SQL 但忘了 generate"。

**连接池**：`pgxpool`，参数在 bootstrap 中按 CPU 核数与环境变量配置，不用默认值。

### 2.3 迁移：goose，不用 AutoMigrate

**为什么不用 GORM AutoMigrate**：生产环境的 schema 变更必须是**显式、可审阅、可回滚**的。AutoMigrate 的"自动加列不删列"语义在涉及部分唯一索引、生成列时会静默做错事。而且本项目第一版就有 11 张表（含 outbox），AutoMigrate 完全不可控。

**为什么选 goose 而不是 golang-migrate**：goose 支持 `-- +goose Up/Down` 注释式 SQL，也能嵌入二进制（`goose.SetBaseFS`），可以在启动时按需执行；golang-migrate 的 CLI 依赖更多。

**规范**：
- 迁移文件命名 `migrations/0001_init_oauth_tables.sql`，序号连续不跳号
- **每个迁移必须写 `Down`**，除了数据回填类
- 涉及大表变更（如 `oauth_identities` 加索引）必须使用 `CREATE INDEX CONCURRENTLY`，并在迁移中标注不可回滚

### 2.4 Redis：go-redis v9

事实标准，无需解释。补充两个使用约定：

- **不使用 `KEYS`**，全部走 `SCAN`（生产环境 `KEYS` 会阻塞）
- **Lua 脚本统一放 `internal/infrastructure/cache/lua/`**，用 `go:embed` 嵌入，禁止在 Go 代码里内联长脚本文本
- 分布式锁用 `SET NX PX` + 唯一 token + Lua 校验后才能删除（**不能用简单的 `DEL`，会误删他人锁**）

### 2.5 认证：golang-jwt + jwx 分工使用

两个库并存是刻意的，职责不重叠：

| 库 | 用途 | 理由 |
| --- | --- | --- |
| **golang-jwt/jwt v5** | 签发/校验本服务的 `access_token`、`id_token` | API 简单，`MapClaims` + `RegisteredClaims` 够用 |
| **lestrrat-go/jwx v2** | ① 校验 Apple `id_token`（拉取并解析 Apple JWKS）<br>② **生成**本服务的 JWKS（§8.3 的 `/v1/jwks`）<br>③ ES256 密钥的 JWK 序列化 | jwx 的 `jwk`/`jws` 子包是 Go 生态里唯一完整覆盖 JWK 全族的实现，golang-jwt 不带 JWKS 生成能力 |

**不用 `golang-jwt` 硬扛 JWKS**：它的 `jwk` 包能力有限，Apple 的密钥轮换（按 `kid` 匹配、找不到时强制刷新）实现起来会很难看。

**密钥保管**：ES256 私钥从环境变量/KMS 注入，**绝不入库、绝不进代码库**（`.gitignore` 已有 `*.pem` / `*.key`）。

### 2.6 HTTP 客户端：标准库 + 自研薄封装（不用 resty）

**为什么不用 resty**：resty 的默认行为里有一些不适合本项目的隐式设计——自动重试（会造成非幂等的 `code2session` 被重试）、默认的 JSON 反序列化（本项目需要保留 `Raw map[string]any` 原始响应供排障）、以及错误处理会吞掉 HTTP 状态码细节。

**自研封装要提供的能力**（`internal/pkg/httpclient`）：

```
· 每渠道独立的超时（微信 3s / Apple 5s / 支付宝 3s 可配）
· 只对幂等请求开启重试（GET / 明确标记的请求），超时与 5xx 退避重试
· 全量 OpenTelemetry 埋点（生成 span，记录 URL/状态码/耗时）
· 响应体大小上限（防三方返回超大 body 打爆内存）
· 敏感字段脱敏（access_token / secret 不出现在日志与 trace 中）
· 保留 Raw 响应供 profile_snapshot 落库
```

**重试的幂等性判定**必须显式声明——`Exchange`（换 token）不能重试，`UserInfo`（拉用户信息）可以。

### 2.7 校验：validator v10

用于 HTTP 层 DTO 校验（`/v1/authorize` 的必填参数、`policy` 结构等）。约定：

- **所有校验错误一次性返回全部问题**（`validator.ValidationErrors` 全量展开），不是遇到第一个就返回——前端一次改完
- `policy` 的业务一致性校验（§7.5.4 的 REJECT/WARN）**不用 tag 表达**，因为涉及跨字段与外部状态（是否启用了 claim 渠道），实现在 `application/adminops/policy_validator.go` 里

### 2.8 日志：标准库 slog

Go 1.21 引入的 `log/slog` 已足够，不引入 zap/zerolog。

**约定**（对应架构 §11.3）：自定义 `slog.Handler` 做两件事：

1. 从 `context.Context` 中提取 `trace_id`，自动注入每条日志
2. 对 `openid` / `external_user_id` / 手机号做自动脱敏

**日志分级纪律**：三方原始响应只在 DEBUG 级别记录，生产默认 INFO。`access_token`、`appSecret`、`code` 永不进日志。

### 2.9 可观测：OpenTelemetry + Prometheus

- **trace**：`otelhttp` 包装 handler 与 HTTP 客户端；`trace_id` 从 `/authorize` 生成写入 ticket，回调时取出续接（§11.2）
- **metric**：Prometheus 拉取模式，`/metrics` 端点**只在管理端网络暴露**（§15.2），不与业务 API 同端口
- **`runtime/trace`**：仅用于本地定位 CPU/调度问题，不进生产链路

### 2.10 错误处理：自研 `pkg/errs`

**为什么不用 `cockroachdb/errors` 或 `pkg/errors`**：本项目需要的是**业务错误码**体系（`AUTH.INVALID_STATE`、`BIND.IDENTITY_TAKEN`，§5.3），不是堆栈追踪。自研约 100 行即可：

```go
type Error struct {
    Code    string   // AUTH.INVALID_STATE
    Message string   // 面向调用方的提示
    HTTP    int      // HTTP 状态码
    Cause   error    // 内部原因，不对外暴露
    Details map[string]any // 保留三方平台原始错误
}
```

**关键约定**：`Details` 里可以放三方平台的原始错误（便于排障），但**必须经过脱敏**；`Cause` 只在日志输出，不出现在 HTTP 响应里。

### 2.11 加密

| 用途 | 方案 | 说明 |
| --- | --- | --- |
| 渠道凭据加密（第一期） | **AES-256-GCM**，主密钥从环境变量读 | §13 修正 P2-4：第一期不做 KMS 但**绝不明文入库** |
| 渠道凭据加密（第四期） | **KMS 信封加密**：主密钥加密 DEK，DEK 加密凭据 | §D6，加密层做成接口，第一期与第四期互换实现 |
| JWT 签名 | **ES256**（P-256），标准库 `crypto/ecdsa` + jwx 序列化 | §8.3 |
| `app_secret` 存储 | **SHA-256 + 随机盐** | ⚠️ **不用 bcrypt/argon2**：`app_secret` 是 32 字节高熵随机串，不存在暴力破解风险，慢哈希只会让每次请求都付出 CPU 代价。慢哈希只适用于低熵的**用户密码**——而本项目不存用户密码 |
| `claim_value_hash` | **SHA-256 + 全局静态盐** | 手机号空间小（11 位数字），必须加盐防彩虹表；但要用**静态盐**而非每行随机盐，否则无法按哈希值查找 |
| `refresh_token` 存储 | **SHA-256**（不加盐） | 随机串，直接哈希可查 |

> `claim_hash` 的"加盐但必须可查"是个容易踩的坑：**每行随机盐会直接让按哈希查询失效**，功能就没了。必须用应用级静态盐。

### 2.12 测试

| 层次 | 工具 | 约定 |
| --- | --- | --- |
| 单元测试 | `testing` + `testify/require` | 领域层与适配器纯逻辑，不碰真实依赖 |
| 接口 mock | `go.uber.org/mock` + `//go:generate` | 为 `Provider` / `AccountProvider` / `IdentitySource` 生成 mock |
| 集成测试 | `testcontainers-go` | **真起 PG + Redis 容器**——本项目大量依赖部分唯一索引与 `SKIP LOCKED`，用 sqlmock 会测不出真实行为 |
| HTTP 层 | `net/http/httptest` | 直接测 chi handler |
| 三方平台 | `httptest.Server` 做假平台 | **不 mock HTTP 客户端库内部**，起一个假服务器更真实 |

**必须写集成测试的三处**（架构里的高风险点）：

1. **并发绑定冲突**：两个 goroutine 同时为同一 identity 建绑定，验证唯一索引兜底（§5.2）
2. **合并的孤儿窗口**：模拟"远端 Merge 成功但本地事务提交失败"，验证补偿任务能自愈（§13 第三期 P0-3 专项验收）
3. **`identity_claims` 部分唯一索引**：验证"未验证的手机号不占用唯一键""撤销后可重新占用"（P0-1）

`go test -race` 是 CI 必跑项。

### 2.13 代码生成

| 生成器 | 输入 | 输出 | 触发 |
| --- | --- | --- | --- |
| **sqlc** | `queries/*.sql` + `schema` | 类型安全的 DB 代码 | `make gen` |
| **oapi-codegen** | `api/openapi.yaml` | server interface + DTO | `make gen` |
| **mockgen** | SPI 接口 | mock 实现 | `make gen` |

**`api/openapi.yaml` 是接口契约的唯一真相源**：先改 OpenAPI，再生成 stub，再填实现。禁止先写 handler 再补文档。

CI 中加 `make gen && git diff --exit-code` —— 检测"改了源但忘了重新生成"。

### 2.14 质量与安全

| 工具 | 用途 | 接入方式 |
| --- | --- | --- |
| **golangci-lint** | 静态检查（含 `errcheck`、`gosec`、`bodyclose`、`contextcheck`） | pre-commit + CI |
| **govulncheck** | 依赖漏洞扫描 | CI 每周 + 每次 `go.mod` 变更 |
| **`go vet`** | 内置 | CI |
| **gitleaks** 或 **git-secrets** | **防止凭据误提交** | pre-commit hook |

> **`gitleaks` 这类工具对本项目是刚需**——会频繁接触 `.p8`、appSecret、KMS 材料。`.gitignore` 只能防"已知扩展名"，防不住"把密钥贴进 YAML 或注释里"。建议加上 pre-commit 拦截。

---

## 3. 开发环境

### 3.1 ⚠️ 当前环境缺少 Go

```
$ go version
bash: go: command not found
```

**编码前必须先安装 Go**（当前工作机未装）。两种方式：

```bash
# 方式一：官方安装包（推荐）
# https://go.dev/dl/  下载 go1.23.x.windows-amd64.msi 安装

# 方式二：包管理器
winget install GoLang.Go
# 或 choco install golang
```

安装后确认：

```bash
go version && go env GOPATH GOMODCACHE GOPROXY
```

**国内环境建议设置模块代理**（否则拉依赖会超时）：

```bash
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
```

### 3.2 本地依赖服务

不要求开发机装 PG/Redis，用容器：

```bash
docker compose -f deployments/docker-compose.dev.yml up -d
```

包含：PostgreSQL 16、Redis 7、MailHog（若要测邮件验证码）。

### 3.3 开发提效

| 用途 | 工具 | 说明 |
| --- | --- | --- |
| 热重载 | **air** | 改代码自动重启 |
| Mock 三方平台 | `testserver/` 下的假平台 | 本地不依赖真实微信/支付宝 |
| 调试 | Delve（`dlv`） | VS Code / GoLand 直接接 |

**假平台（fake provider）是第一期的关键交付物**：第一期还没有真实渠道，需要 `testserver/fake_oauth2` 提供标准的授权码流程，才能端到端验证。它同时也是集成测试的依赖。

---

## 4. 依赖管理策略

| 项 | 约定 |
| --- | --- |
| 模块路径 | **待确认**（见下方说明） |
| 版本锁定 | `go.mod` + `go.sum` 全部入库 |
| vendor | **不提交**（默认已 `.gitignore`）。若需要完全离线构建再执行 `go mod vendor` 并删除忽略规则 |
| Go 版本声明 | `go.mod` 中写 `go 1.23`，不使用 `toolchain` 指令强制升级 |
| 依赖引入审批 | **核心链路禁止引入新依赖**（授权流程、合并流程、加解密）；辅助工具类可放宽 |
| 依赖数量上限 | 目标 ≤ 25 个直接依赖。每引入一个需在 PR 说明"为什么标准库或现有依赖做不到" |

### ⚠️ 待确认：Go module 路径

架构文档中用的是占位符 `github.com/xxx/social-login`。**编码前需要确定真实的仓库地址**，例如：

```
github.com/17track/social-login      ← 按实际仓库填
```

确认方式：

```bash
# 若已创建远程仓库
git remote add origin <你的仓库地址>
go mod edit -module=$(basename $(git remote get-url origin) .git) ...
```

**这个路径一旦定下，后续所有 `import` 都依赖它，改动成本随文件数线性增长**，所以要在写第一行代码前确定。

---

## 5. 仓库结构

```
social-login/
├── .gitignore                     ← 已建（凭据规则优先）
├── .golangci.yml
├── .gitleaks.toml
├── Makefile                       ← 唯一构建入口
├── go.mod / go.sum
├── README.md
├── docs/
│   ├── architecture-design.md     ← v0.9
│   ├── design-review.md
│   └── tech-stack.md              ← 本文档
├── api/
│   └── openapi.yaml               ← 接口契约唯一真相源
├── cmd/
│   ├── server/main.go             ← 在线服务（业务端 + 管理端）
│   └── worker/main.go             ← 后台任务：补偿 + Outbox 投递（§12）
├── internal/
│   ├── bootstrap/                 ← 配置加载、依赖装配、优雅退出
│   ├── config/                    ← 配置结构体定义（koanf 绑定）
│   ├── interfaces/http/
│   │   ├── handler/               ← 业务端 /v1/*
│   │   ├── handler/admin/         ← 管理端 /admin/v1/*（§15 的 A~K 组）
│   │   ├── middleware/            ← app 鉴权、限流、trace、恢复
│   │   ├── middleware/adminmw/    ← 管理员 RBAC、IP 白名单、高危操作审计
│   │   └── dto/
│   ├── application/               ← 用例编排（事务边界）
│   │   ├── authflow/  binding/  token/  tenantconfig/  adminops/
│   ├── domain/
│   │   ├── identitysource/        ← D8 留口
│   │   ├── provider/              ← SPI + Registry
│   │   ├── identity/  binding/  ticket/  account/
│   ├── infrastructure/
│   │   ├── provider/adapters/     ← wechat/ alipay/ apple/ generic_oauth2/
│   │   ├── persistence/           ← pgx + sqlcgen
│   │   ├── cache/                 ← redis + lua/
│   │   ├── crypto/                ← 凭据加密、claim 哈希、KMS 客户端
│   │   ├── accountclient/         ← HTTPAccountProvider
│   │   └── eventbus/              ← outbox 投递
│   └── pkg/                       ← errs / log / httpclient / jwtkit
├── migrations/                    ← goose SQL
├── configs/
│   ├── config.yaml
│   └── config.example.local.yaml  ← 提交示例，真实 local 配置被忽略
├── deployments/
│   ├── docker-compose.dev.yml
│   └── Dockerfile
├── queries/                       ← sqlc 输入（*.sql）
├── sqlc.yaml
├── testserver/
│   └── fake_oauth2/               ← 假三方平台，第一期关键交付物
└── scripts/
```

---

## 6. 明确不引入的东西（避免过度工程）

| 不引入 | 原因 |
| --- | --- |
| **Kubernetes / Helm** | 当前规模是单服务 + worker，docker-compose 或直接二进制足够。上 K8s 是运维成本先于收益 |
| **消息队列（Kafka/RabbitMQ/NATS）** | Outbox + Redis 已能满足事件投递与后台任务。**引入 MQ 会带来"MQ 与 DB 的一致性问题"，而 Outbox 模式本身就是为解决它而生的** |
| **Service Mesh / Istio** | 单服务，无必要 |
| **gRPC** | 对外是 HTTP/OAuth2 生态，管理端也无高频内部调用。若未来用户中心要求 gRPC，在 `accountclient` 单独加实现即可 |
| **依赖注入框架（wire/fx）** | 项目规模可控，`bootstrap` 手写装配更透明、易调试。**若 `bootstrap` 超过 300 行再评估 wire** |
| **ORM（GORM/ent）** | 见 §2.2 |
| **分布式事务框架（Seata 等）** | 架构已用「三阶段独立事务 + 幂等 + 补偿」解决跨服务一致性（§7.3），不需要额外框架 |
| **全链路配置中心（Nacos/Apollo）** | 配置变更用「DB + Redis Pub/Sub 广播」已实现（§9.2）。配置中心是第四期再评估项 |
| **自研 JWT / 自研加密** | 永远不自己实现密码学 |
| **`context.TODO()`** | lint 规则禁止；所有链路必须传递 context |

---

## 7. 与架构文档的对应关系

| 架构设计中的关键机制 | 由哪些技术栈支撑 |
| --- | --- |
| Provider SPI + 编译期注册（D1/D7） | 纯标准库 + `init()` 注册，无框架依赖 |
| 部分唯一索引兜底并发绑定（§5.2） | **PostgreSQL 部分唯一索引** + pgx 精确捕获 `23505` |
| 三次独立事务 + 补偿（P0-3） | **pgx 显式事务控制** + `FOR UPDATE SKIP LOCKED` + `event_outbox` 表 |
| JWKS 与密钥轮换（P0-2/§8.3） | **jwx**（JWK 生成与序列化）+ KMS/环境变量 |
| Apple 验签与 client_secret 签发（C2） | **jwx**（JWKS 解析）+ **golang-jwt**（ES256 签名） |
| 配置化合并行为（R2/§7.5） | **koanf** 读配置 + **JSONB** 存储 + `adminops/policy_validator` |
| 管理端与业务端隔离（§15.2） | **chi 的路由分组与独立中间件链** + 网关按路径分流 |
| 可观测性（§11） | **OpenTelemetry** + **prometheus/client_golang** + **slog** |
