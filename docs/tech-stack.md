# 技术栈选型

> 配套文档：`architecture-design.md`（v0.9）· `design-review.md`
> 本文档回答一个问题：**用哪些 Go 生态的库来实现这套设计，以及为什么不用别的。**
>
> ---
> **v2 修订说明（重要）**：v1 的选型偏向"技术纯度"（chi / sqlc / koanf / slog / 自研 HTTP 封装），
> 但**团队熟悉度是一阶因素，不是可以忽略的偏好**——一个团队不熟的"更优"技术栈，
> 长期维护成本和踩坑概率都高于一个"够用但大家都会"的栈。
> v2 按「**主流优先，只在主流方案真的会出错时才偏离**」的原则重选，偏离处均标注理由与缓解措施。
>
> **v2 复盘修正（第二轮）**：v2 初稿把 HTTP 客户端从「标准库 + 轻量封装」改成 resty，属**过度纠正**——
> `net/http` 本身就是主流，把它换成第三方库只为"看起来一致"是不成立的。
> 已回退至「标准库 + 轻量封装」，并更正初稿中一处**不实警告**：resty 的 `retryCount` 默认即为 `0`，
> 不存在"必须手动关闭否则会重试非幂等接口"的坑——那是我为变更找理由时写错的。

---

## 0. 选型原则（v2）

按优先级排序，冲突时上位优先：

| 优先级 | 原则 | 说明 |
| --- | --- | --- |
| 1 | **团队熟悉度** | 主流、社区大、遇到问题能搜到答案。这是维护成本的直接决定因素 |
| 2 | **正确性** | 主流方案若会导致**数据错误或安全缺陷**，必须偏离并说明 |
| 3 | 性能 | 本服务是 IO 密集型（等三方平台响应），性能不是瓶颈项 |
| 4 | 简洁 / 优雅 | 最不重要。可读性由团队约定保证，不靠换库 |

**结论**：v2 只保留 4 处"非最主流"的选择，每一处都对应一个**具体的、会导致出错的**技术原因（见 §4）。

---

## 1. 基础决策

### 1.1 数据库：PostgreSQL 16 ✅ 已确认

设计里已经用到 4 项 PostgreSQL 独有特性，切换成本随代码量增长：

| 设计中的依赖点 | PostgreSQL | MySQL 8 |
| --- | --- | --- |
| **部分唯一索引**（`uk_claims_verified WHERE verified = true AND revoked_at IS NULL`，P0-1 的核心约束） | 原生支持 | ❌ 不支持，须用生成列绕过 |
| **`FOR UPDATE SKIP LOCKED`**（补偿任务与 Outbox worker 多副本安全拉取，§12） | 原生 | 8.0 支持 |
| **JSONB + GIN 索引**（`policy` / `extra` / `profile_snapshot`，§6.2） | 支持 | JSON 可查但无等价索引能力 |
| **`INET` 类型**（`auth_audit_logs.client_ip`） | 原生 | ❌ 需存 VARCHAR |

### 1.2 Web 框架：gin v1.10+

**选 gin。** 理由是团队熟悉度 + 生态完整，且**不存在技术障碍**：

| 关注点 | gin 的实际表现 |
| --- | --- |
| 与标准库中间件互通 | `gin.WrapH(mw)` 可把 `func(http.Handler) http.Handler` 直接包成 gin 中间件，方向是通的 |
| 可观测性 | **`otelgin` 是 OpenTelemetry 官方中间件**，无需自研 |
| 两套鉴权链按路径挂载 | `r.Group("/v1")` 与 `r.Group("/admin/v1")` 各挂各的中间件，天然支持（§15.2） |
| handler 单元测试 | `httptest` 正常可用（`router.ServeHTTP(w, req)`） |
| 路由性能 | gin 更快，但**对本服务无意义**——瓶颈是调三方平台的网络 IO，不是路由匹配 |

**v1 原选的 chi 为什么改掉**：chi 的优势是"100% 实现 `net/http` 接口"，但 gin 通过 `WrapH` 已能覆盖实际需要；而团队不熟悉会带来真实的排障成本。

> ⚠️ **v1 中我列的 gin 否决理由（"自研 context 与标准库中间件不互通"）是不严谨的**——那只适用于 fiber。
> gin 的 `*gin.Context` 确实不是 `context.Context`，但 `WrapH` 提供了双向可用的桥接，不构成阻碍。

**gin 使用约定**：

```
· 禁用 gin.Default()，只用 gin.New() + 自研 Recovery（记录 trace_id，不泄漏堆栈）
· 禁用 gin 自带 Logger，访问日志统一走 zap（ginzap 或自研中间件）
· 错误响应体统一为项目错误码格式（§5.3），不用 gin 的 ShouldBind 错误直出
· handler 内禁止把 *gin.Context 往下层传；向下只传 context.Context（c.Request.Context()）
```

> ⚠️ **fiber 不在此列**：它基于 fasthttp，**不是 `net/http` 接口**——`httptest`、OTel 官方中间件、部分标准库生态都用不了。**这是技术障碍，不是偏好。**

---

## 2. 总览

| 分层 | 用途 | 选型 | 主流度 |
| --- | --- | --- | --- |
| 语言 | — | **Go** ≥ 1.23 | — |
| Web | 路由 + 中间件 | **gin** v1.10+ | ★★★★★ |
| 配置 | 多源配置加载 | **viper** v1 | ★★★★★ |
| 数据库 | ORM | **GORM** v2（pgx 驱动） | ★★★★★ |
| 数据库 | 迁移 | **goose** v3 或 **golang-migrate**（团队选） | ★★★★ |
| 缓存 | Redis 客户端 | **go-redis** v9 | ★★★★★ |
| 认证 | JWT 签发与校验 | **golang-jwt/jwt** v5 | ★★★★★ |
| 认证 | JWKS 拉取与验签（Apple） | **MicahParks/keyfunc** v3 | ★★★★ |
| 认证 | 通用 OAuth2 客户端 | **golang.org/x/oauth2** | ★★★★★ |
| HTTP 客户端 | 三方平台调用 | **标准库 net/http** + 轻量封装（每渠道独立 client） | ★★★★★（标准库） |
| 容错 | 渠道熔断 | **sony/gobreaker/v2** | ★★★★ |
| 校验 | 请求 DTO | **go-playground/validator** v10 | ★★★★★ |
| 日志 | 结构化日志 | **zap** v1 + lumberjack 轮转 | ★★★★★ |
| 可观测 | 链路追踪 | **OpenTelemetry** + `otelgin` + `otelhttp` | ★★★★★ |
| 可观测 | 指标 | **prometheus/client_golang** | ★★★★★ |
| 错误 | 错误码与包装 | **自研 `pkg/errs`**（约 100 行）+ `pkg/errors` 包装 | ★★★ |
| 加密 | 凭据加密 / 哈希 | **标准库 crypto**（AES-GCM / ECDSA / SHA-256） | ★★★★★ |
| 测试 | 断言 + mock | **testify** v1 | ★★★★★ |
| 测试 | 依赖容器 | **testcontainers-go** | ★★★★ |
| 测试 | 接口 mock 生成 | **go.uber.org/mock** | ★★★★ |
| 代码生成 | OpenAPI → stub / DTO | **oapi-codegen** v2 | ★★★★ |
| 质量 | 静态检查 | **golangci-lint** | ★★★★★ |
| 质量 | 漏洞扫描 | **govulncheck** | ★★★★ |
| 质量 | 凭据防泄漏 | **gitleaks** | ★★★★ |
| 构建 | 任务编排 | **Makefile** | ★★★★★ |
| 容器化 | 本地依赖 | **docker-compose** | ★★★★★ |

---

## 3. 逐项说明（重点是与 v1 的差异）

### 3.1 配置：viper v1（v1 用 koanf）

**改为 viper**：主流度远高，团队大概率用过。

**唯一注意点**：**不要用包级全局单例**（`viper.Get()` 那套），用实例：

```go
v := viper.New()
v.SetConfigFile("configs/config.yaml")
v.SetEnvPrefix("AUTH")
v.SetEnvKeyReplacer(strings.NewReplacer(".", "__"))
v.AutomaticEnv()          // 环境变量覆盖配置文件
```

**配置分层约定**（对应架构 §9）：

```
configs/config.yaml          # 默认值，入库
configs/config.local.yaml    # 本地覆盖，已被 .gitignore 排除
环境变量 AUTH__DB__DSN        # 最高优先级，容器部署用
```

**敏感项不走配置文件**：DB 密码、Redis 密码、KMS 凭据一律只从环境变量读，配置文件里只放占位符。这与 `.gitignore` 的凭据规则构成两道防线。

### 3.2 数据访问：GORM v2（v1 用 pgx + sqlc）

**改为 GORM v2。** 这个决定需要展开说，因为 v1 推荐 sqlc 的论据有一部分成立、有一部分被我夸大了。

**v1 的论据重新校准：**

| v1 的说法 | 实际情况 | 是否成立 |
| --- | --- | --- |
| GORM 无法表达部分唯一索引 | **成立，但不影响**——DDL 本来就在 `migrations/` 手写 SQL，ORM 管不着 | ❌ 不是阻碍 |
| GORM 做不了 `FOR UPDATE SKIP LOCKED` | **不成立**。GORM v2 原生支持：`db.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})` | ❌ 我错了 |
| GORM 捕获不到 `23505` 与约束名 | **基本成立但可解**。GORM 透传驱动错误，`errors.As(err, &pgErr)` 取 `*pgconn.PgError` 可拿到 `ConstraintName` | ⚠️ 可行 |
| GORM 做 `RETURNING` 麻烦 | **不成立**。GORM v2 支持 `clause.Returning{}` | ❌ 我错了 |
| JSONB 局部更新需 `Raw()` | **成立**。`jsonb_set(...)` 需 `gorm.Expr` 或读改写 | ✅ 成立，但影响小 |
| 复杂多表查询链式 API 变丑 | **成立**。identity / claim 维度的匹配查询用 `Raw()` 更清楚 | ✅ 成立 |

**结论**：GORM 在本项目**完全可用**，只有约 6 处复杂查询需要 `db.Raw()`。"GORM 管 CRUD + Raw 管复杂查询"是被广泛验证的混合模式，不是妥协。

**但必须守住两条不变量**（这两条与用什么库无关，才是真正重要的）：

**① DDL 的唯一真相源是 `migrations/` 里的手写 SQL，禁止 AutoMigrate 管生产 schema**

设计里的约束都很细，AutoMigrate 表达不了：

```sql
-- 例：identity_claims 的部分唯一索引（P0-1），AutoMigrate 无法表达
CREATE UNIQUE INDEX uk_claims_verified
    ON identity_claims (app_id, claim_type, claim_value_hash)
    WHERE verified = true AND revoked_at IS NULL;
```

AutoMigrate 的"只加不删"语义在涉及部分唯一索引、生成列时会**静默做错事**，且不可审计、不可回滚。
约定：`migrations/` 是唯一真相源，GORM 只负责读写数据；本地开发也走迁移脚本，不跑 AutoMigrate。

**② `app_id` 强制隔离用 GORM 全局 Callback 实现，不靠人自觉**

架构 §9.1 要求"每条查询都必须带 `app_id`，Repository 层强制注入"。用手写 SQL 只能靠 code review 保证，**而用 GORM 反而能做中心化强制**：

```go
// 全局回调：任何 Query 前自动注入 app_id 条件，缺失则 panic
db.Callback().Query().Before("gorm:query").Register("inject_app_scope", func(tx *gorm.DB) {
    appID, ok := tx.Statement.Context.Value(ctxKeyAppID).(int64)
    if !ok {
        panic("missing app scope: 所有查询必须携带 app_id（架构 §9.1）")
    }
    tx.Statement.AddClause(clause.Where{Exprs: []clause.Expression{
        clause.Eq{Column: "app_id", Value: appID},
    }})
})
```

这比"每条 SQL 记得写 `WHERE app_id = ?`"可靠得多——**漏写在开发阶段就会 panic，而不是线上串号**。

**③ `db.Raw()` 的使用纪律**

允许用 `Raw()` 的场景仅限：多表 join、批量更新、窗口函数、JSONB 操作。用 `Raw()` 时**必须显式带 `app_id` 参数**（全局 Callback 不拦原生 SQL），并在 PR 中说明为什么绕过。

### 3.3 迁移：goose 或 golang-migrate（团队选）

两者都是纯 SQL 迁移，都够用，**按团队熟悉的选**。

**为什么不用 GORM AutoMigrate**：见 §3.2 ①。生产 schema 变更必须显式、可审阅、可回滚。

**规范**：
- 文件命名 `0001_init_oauth_tables.sql`，序号连续不跳号
- **每个迁移必须写 `Down`**（数据回填类可标注不可回滚）
- 大表加索引用 `CREATE INDEX CONCURRENTLY`，并在注释标注不可回滚

### 3.4 日志：zap v1（v1 用 slog）

**改为 zap。** v1 选 slog 的理由是"标准库、零依赖、不会被废弃"，但**对这个服务不成立**：

| 维度 | 实际情况 |
| --- | --- |
| 性能 | zap 更快，但本服务日志量低（登录事件，不是数据管道），**性能优势用不上** |
| 生态 | zap 明显更成熟：`lumberjack` 日志轮转、`ginzap` 对接 gin 访问日志、`zapcore` 自定义 encoder |
| 团队熟悉度 | 国内 Go 团队普遍在用 zap，不用重新学 |
| 迁移性 | slog ↔ zap 有互转桥接（`zapslog` / `slog-zap`），不是单向门 |

**使用约定**：

```
· 统一 gin.New() + 自研 Recovery，访问日志走 zap（不用 gin.Default() 自带 logger）
· 用 zapcore 自定义 Encoder 做两件事：
    ① 从 context 注入 trace_id（§11.2 的链路贯穿）
    ② 对 openid / external_user_id / 手机号自动脱敏（§11.3）
· 日志分级纪律：三方原始响应只在 Debug 级别记录；access_token / appSecret / code 永不进日志
· 轮转交给 lumberjack，不自研
```

### 3.5 HTTP 客户端：标准库 net/http + 轻量封装（**v2 一度改为 resty，已回退**）

> **回退说明**：v2 初稿把这一项从"标准库 + 自研封装"改成了 resty，理由是"整体转向主流"。
> 复盘后确认**这是一次过度纠正**，已回退。理由见下。

**结论：用 `net/http` + 一个约 150 行的轻量封装，不引入第三方 HTTP 客户端库。**

**核心判断：`net/http` 本身就是主流。** 在"团队熟悉度优先"这条原则下，`net/http` 是唯一一个**熟悉度必然为 100%** 的选项——任何 Go 开发者都会用它。为了"看起来和其他选型一致"而换成第三方库，反而凭空增加了一个依赖。

**曾为本次变更列出的理由，逐条复核后都不成立：**

| v2 初稿的理由 | 复核结果 |
| --- | --- |
| resty "官方配置"后即可规避非幂等重试 | **⚠️ 我写错了**。resty v2 的 `retryCount` **默认就是 0**，不存在"必须手动关掉"的危险默认值。初稿里 `SetRetryCount(0). // ★ 关键` 的写法会让人误以为有个需要防的坑——**这个坑不存在** |
| resty 便于保留原始响应（`profile_snapshot` 需存） | 标准库同样能拿到原始 body，**无差异** |
| resty 便于接入 OTel | **反而更差**：`otelhttp.NewTransport()` 是 **OpenTelemetry 官方**的 `http.RoundTripper`，一行接入；resty 生态里的 `otelresty` 是**社区维护**，多一层维护风险 |
| resty 减少样板代码 | ✅ 成立，但收益不足以换掉标准库、多一个依赖 |

**自研封装需要提供的 5 项能力**（`internal/pkg/httpx`，约 150 行）：

```go
// 每渠道一个 Client，独立超时；Transport 用官方 OTel 中间件
wechat := httpx.New(httpx.Config{
    Name:    "wechat",
    Timeout: 3 * time.Second,
    Transport: otelhttp.NewTransport(http.DefaultTransport), // 官方，一行
})
apple := httpx.New(httpx.Config{Name: "apple", Timeout: 5 * time.Second, ...})
```

| 能力 | 实现要点 |
| --- | --- |
| **每渠道独立超时** | 微信 3s / Apple 5s / 支付宝 3s，可配；连接超时统一 1s |
| **不做重试**（约束 C6） | 不提供任何重试选项。**fail-safe 优于 fail-dangerous**——不实现就不会有人用错 |
| **取消隔离** | 对"已发出即不可撤销"的调用提供 `httpx.Detached(ctx)`，内部用 `context.WithoutCancel` + 独立超时 |
| **OpenTelemetry 埋点** | 官方 `otelhttp.NewTransport()` + `otelhttp.NewHandler`，不自研 |
| **响应体大小上限** | `io.LimitReader(resp.Body, maxBodyBytes)`，防三方返回超大 body 打爆内存 |
| **保留原始响应** | 读取 body 后同时返回字节切片与反序列化结果，原始字节供 `profile_snapshot` 落库 |
| **敏感字段脱敏** | 对 `access_token` / `secret` / `code` 在日志与 trace attributes 中做掩码 |
| **失败分类** | 把三方错误映射为 `retryable: true/false`（架构 §5.5），供接入方决定是否重开授权流程 |

**调用方不做任何自动重试（约束 C6）**：

```go
// httpClient 不提供 WithRetry 之类的选项——不重试是设计约束，不是配置项
resp, err := httpClient.Do(ctx, req)   // 一次失败即失败
```

`UserInfo`、`Exchange`、`code2session`、`Refresh`、`Unbind` **全部不重试**。

**为什么连 `UserInfo`（幂等接口）也不重试**：见 `architecture-design.md` §5.5。核心原因是**"按接口逐个判断幂等性"是个必然出错的抽象**——只要有例外，就有人判断错。而且重试单位应当是「整个授权流程」而非「单个 HTTP 请求」，接入方重开一次授权比我们重放一个已发出的请求语义更清楚。

**不重试就必须补上的三件事**（详见架构 §5.5）：

| 事项 | 要求 |
| --- | --- |
| **分层超时** | 连接 1s / 读写 2~3s / 单渠道总超时（微信 3s、Apple 5s）。**不重试 + 无超时 = 连接与 goroutine 被耗尽** |
| **渠道熔断** | 依赖 `HealthChecker`（P2-3）做健康探测，连续失败达阈值后快速失败。**没有熔断，"不重试"就变成了纯粹的慢** |
| **取消隔离** | `Exchange` / `Refresh` 这类"已发出即不可撤销"的调用，**必须用 `context.WithoutCancel` 脱离调用方 context**，避免客户端断开导致 code 被消费但结果丢失 |

**若团队确实在用 resty**：改回去是 10 分钟的事（封装层换实现，调用方不变）。但**需要团队明确表态**——这是我唯一没有依据的推断。

### 3.6 熔断：sony/gobreaker/v2（新增）

**为什么需要**：约束 C6 决定对三方渠道不重试。但不重试本身**不减少对故障平台的调用量**——没有熔断时，平台故障期间每个请求都会占住一个 goroutine 和一个连接、白等满超时，进而耗尽共享连接池，把 Apple / 支付宝的登录也一起拖垮。**熔断是把"平台故障"隔离在单渠道内的必要机制。**

**选型**：`sony/gobreaker/v2` —— Go 生态最主流的熔断库，经典三态模型（Closed / Open / Half-Open），v2 支持泛型，无额外依赖。

| 候选 | 结论 |
| --- | --- |
| **sony/gobreaker/v2** | ✅ 选用 |
| afex/hystrix-go | ❌ 已长期不活跃 |
| go-kit/kit/circuitbreaker | ❌ 本质是对 gobreaker 的封装，多一层无收益 |
| 自研 | ❌ 状态迁移与并发边界容易写错 |

**四条实现纪律（详见架构 §5.6）：**

| # | 纪律 | 后果 |
| --- | --- | --- |
| 1 | **只有 `retryable` 的错误计入熔断**，`PROVIDER.REJECTED`（code 无效）**绝不计数** | 否则攻击者用无效 code 高频打回调即可熔断整个微信渠道 —— 从"平台保护"变成**服务级拒绝服务** |
| 2 | **超时率与慢请求率独立统计、独立阈值** | 只看错误率防不住平台"半死"（高延迟 + 低错误率）。超时是**慢失败**，占满整个超时窗口；5xx 是**快失败**，几乎不占资源。两者混在一起算会严重延误熔断 |
| 3 | **慢请求率只统计【成功】的慢请求** | 业务拒绝（code 无效）也是可被攻击者构造的。若把它计入慢请求率，攻击者就能远程触发熔断 —— 与第 1 条是同一条攻击路径 |
| 4 | **配置放服务级**，不放 `applications.policy` | 熔断保护的是所有应用**共享**的连接池；做成应用级等于"一个应用能为全体关掉保护" |

**⚠️ 一个实现约束（gobreaker 的能力边界）**：`gobreaker.Settings.ReadyToTrip(counts Counts)` **拿不到失败分类**——它只提供 `Requests / TotalSuccesses / TotalFailures / ConsecutiveSuccesses / ConsecutiveFailures`。因此：

| 组件 | 职责 |
| --- | --- |
| **gobreaker** | 只负责**状态机**（三态并发安全迁移、Half-Open 放行控制） |
| **自维护的分类滑动窗口**（`internal/pkg/guards/breaker`，每 platform 一个 60s/6 桶环形计数器） | 负责**失败分类统计**（`success` / `slow` / `timeout` / `conn_err` / `server_err` / `business_reject`） |
| `Settings.IsSuccessful` | 把 retryable 错误、超时、慢请求判为 failure，使 gobreaker 自身 counts 正确 |
| `Settings.ReadyToTrip` | 回调里读取**自维护窗口**，按四类阈值判定 |

**不引入第三方滑动窗口库** —— 分类计数与熔断判定耦合紧密，自己写更可控，且只存计数器、内存开销可忽略。

**与 `HealthChecker` 的分工**：熔断器（被动统计真实调用）是**唯一的熔断决策来源**；`HealthChecker`（主动探测）只用于管理台展示与告警。**不能用主动探测决定熔断**——探测走的不是真实业务路径，可能探测正常而业务接口异常。

**多副本限制**：熔断器是进程内状态，N 个副本 = N 个独立熔断器。初期接受（各自熔断、探针放大 N 倍、状态可能不同步）。**不引入 Redis 共享状态**——熔断是降级保护机制，不应有强外部依赖，否则 Redis 故障时保护也失效。副本数 > 20 后再考虑"熔断事件广播"。

**入站超时是另一回事**（架构 §5.7）：渠道熔断是**出站**（保护我们不被平台拖垮），入站超时是**入站**（保护我们不被慢请求拖垮），机制不同、互补但不可互相替代。入站用 `http.Server` 三段超时 + gin 中间件按路由分组（授权链路 8s / 管理端 30s / 导出 10s），并保证超时后通过 `context` 真正取消下游。



### 3.7 认证：golang-jwt v5 + keyfunc v3（v1 用 golang-jwt + jwx）

**jwx 换成 MicahParks/keyfunc v3。** 原因：

- **keyfunc v3 是"用 JWKS 验签"这件事在 Go 里的主流库**，且**直接与 `golang-jwt/jwt/v5` 集成**：`keyfunc.NewDefault([]string{jwksURL})` 返回 `func(*jwt.Token) (interface{}, error)`，直接喂给 `jwt.Parse`
- **自动处理 Apple 的密钥轮换**：遇到未知 `kid` 时自动刷新 JWKS，正是我们需要的（§4.4 ②）
- jwx 能力更全（JWK / JWS / JWE 全家桶），但本项目只需"拉 JWKS + 验签"，用不上它的全部能力

**职责分工**：

| 用途 | 用什么 |
| --- | --- |
| 签发 / 校验本服务的 `access_token`、`id_token` | **golang-jwt/jwt v5**，标准库 `crypto/ecdsa` 做 ES256 |
| 校验 Apple `id_token` | **golang-jwt + keyfunc**（keyfunc 负责拉取与轮换 Apple JWKS） |
| 生成并发布**本服务的** JWKS（`/v1/jwks`，§8.3） | **手写约 30 行**（EC 公钥的 JWK 就是 base64url 的 x / y + kid），**不引依赖** |

最后一条值得说明：EC 公钥的 JWK 序列化就是两个 base64url 字段，为它引一个 JOSE 全家桶不划算。若团队更希望用库，`go-jose/go-jose` 是 Go 里最标准的 JOSE 实现。

**密钥保管**：ES256 私钥从环境变量 / KMS 注入，**绝不入库、绝不进代码库**（`.gitignore` 已有 `*.pem` / `*.key`）。

### 3.8 错误处理：自研 `pkg/errs`（保留）

**这一项保持自研**，因为主流替代品解决的是不同问题：

| 库 | 解决的问题 | 为什么不够用 |
| --- | --- | --- |
| `github.com/pkg/errors` | 错误包装 + 堆栈 | 没有**业务错误码**概念 |
| `cockroachdb/errors` | 更全的包装 + PII 擦除 | 同样没有业务错误码；依赖重 |
| `samber/oops` | 结构化错误属性 | 较新，生态小 |

本项目对外要返回 `AUTH.INVALID_STATE`、`BIND.IDENTITY_TAKEN` 这类**稳定的、可被业务方编程判断的**错误码（§5.3），这是产品契约，不是日志信息。

自研约 100 行：

```go
type Error struct {
    Code     string         // AUTH.INVALID_STATE，对外稳定契约
    Message  string         // 面向调用方的提示
    HTTP     int            // HTTP 状态码
    Cause    error          // 内部原因，只进日志，不进响应
    Details  map[string]any // 保留三方平台原始错误（脱敏后）
}
```

**约定**：`Details` 可放三方平台原始错误便于排障，**但必须脱敏**；`Cause` 只在日志输出，**绝不出现在 HTTP 响应里**。

内部包装仍可用 `pkg/errors` 的 `%w`，在 HTTP 边界统一转成 `errs.Error`。

### 3.9 加密（保留）

| 用途 | 方案 | 说明 |
| --- | --- | --- |
| 渠道凭据加密（第一期） | **AES-256-GCM**，主密钥从环境变量读 | §13 修正 P2-4：第一期不做 KMS 但**绝不明文入库** |
| 渠道凭据加密（第四期） | **KMS 信封加密**：主密钥加密 DEK，DEK 加密凭据 | §D6，加密层做成接口，两期实现可互换 |
| JWT 签名 | **ES256**（P-256），标准库 `crypto/ecdsa` | §8.3 |
| `app_secret` 存储 | **SHA-256 + 随机盐** | ⚠️ **不用 bcrypt / argon2**，理由见下 |
| `claim_value_hash` | **SHA-256 + 应用级静态盐** | ⚠️ 不能用每行随机盐，理由见下 |
| `refresh_token` 存储 | **SHA-256**（不加盐） | 高熵随机串，直接哈希可查 |

> ⚠️ **两条容易踩的坑，与用什么库无关，必须写进代码注释：**
>
> **1. `app_secret` 不用慢哈希。** 它是 32 字节高熵随机串，不存在暴力破解风险，bcrypt / argon2 只会让**每次请求都白付 CPU**（认证中间件是热路径）。慢哈希只适用于低熵的**用户密码**——而本服务不存用户密码。
>
> **2. `claim_value_hash` 必须用应用级静态盐，不能用每行随机盐。** 手机号只有 11 位数字、空间小，必须加盐防彩虹表；但**每行随机盐会让"按哈希值查询手机号"直接失效**——归并判定功能就没了。这是一对相互制约的需求，必须用静态盐。

### 3.10 测试（保留，均为主流）

| 层次 | 工具 | 约定 |
| --- | --- | --- |
| 单元测试 | `testing` + `testify/require` | 领域层与适配器纯逻辑，不碰真实依赖 |
| 接口 mock | `go.uber.org/mock` + `//go:generate` | 为 `Provider` / `AccountProvider` / `IdentitySource` 生成 |
| 集成测试 | `testcontainers-go` | **真起 PG + Redis 容器**（需本地 Docker） |
| HTTP 层 | `net/http/httptest` | 直接测 gin handler（`router.ServeHTTP(w, req)`） |
| 三方平台 | `httptest.Server` 起假平台 | **不 mock HTTP 客户端库内部**，起假服务器更真实 |

**为什么集成测试必须用真数据库**：本项目大量依赖**部分唯一索引**与 **`SKIP LOCKED`** 的行为，`sqlmock` 这类假驱动**测不出真实行为**，等于白测。

**必须写集成测试的三处**（架构里的高风险点）：

1. **并发绑定冲突**：两个 goroutine 同时为同一 identity 建绑定，验证唯一索引兜底（§5.2）
2. **合并的孤儿窗口**：模拟"远端 `Merge` 成功但本地事务提交失败"，验证补偿任务能自愈（§13 第三期 P0-3 专项验收）
3. **`identity_claims` 部分唯一索引**：验证"未验证的手机号不占用唯一键""撤销后可重新占用"（P0-1）

**替代方案**：若团队不想引入 `testcontainers-go`（需 Docker 且启动有开销），可退化为"本地 docker-compose 起 PG + 用环境变量切换测试库"。**但绝不能退化为 sqlmock。**

`go test -race` 是 CI 必跑项。

### 3.11 代码生成（保留）

| 生成器 | 输入 | 输出 | 触发 |
| --- | --- | --- | --- |
| **oapi-codegen** | `api/openapi.yaml` | server interface + DTO | `make gen` |
| **mockgen** | SPI 接口 | mock 实现 | `make gen` |

**`api/openapi.yaml` 是接口契约的唯一真相源**：先改 OpenAPI，再生成 stub，再填实现。禁止先写 handler 再补文档。

CI 中加 `make gen && git diff --exit-code` —— 检测"改了源但忘了重新生成"。

### 3.12 质量与安全（保留）

| 工具 | 用途 | 接入方式 |
| --- | --- | --- |
| **golangci-lint** | 静态检查（含 `errcheck`、`gosec`、`bodyclose`、`contextcheck`） | pre-commit + CI |
| **govulncheck** | 依赖漏洞扫描 | CI 每周 + 每次 `go.mod` 变更 |
| **`go vet`** | 内置 | CI |
| **gitleaks** | **防止凭据误提交** | pre-commit hook |

> **`gitleaks` 对本项目是刚需**——会频繁接触 `.p8`、appSecret、KMS 材料。`.gitignore` 只能防"已知扩展名"，防不住"把密钥贴进 YAML 或注释里"。

---

## 4. 保留下来的 4 处"非最主流"选择及理由

每一处都对应一个**具体的、会导致出错的**技术原因，而不是偏好：

| # | 选择 | 主流替代 | 为什么必须偏离 |
| --- | --- | --- | --- |
| 1 | **手写 SQL 迁移为 DDL 唯一真相源**（不用 GORM AutoMigrate） | AutoMigrate | AutoMigrate 表达不了部分唯一索引（P0-1 的核心约束）；"只加不删"语义会**静默做错事**，且不可审计、不可回滚 |
| 2 | **自研 `pkg/errs`** | `pkg/errors` | 需要**对外稳定的业务错误码**（`AUTH.INVALID_STATE` 等），这是产品契约；主流库解决的是包装与堆栈，不是错误码。自研仅约 100 行 |
| 3 | **`claim_value_hash` 用静态盐**（不用随机盐） | 随机盐 | 随机盐会让"按哈希查手机号"**直接失效**，归并判定功能就没了。这是需求约束，不是选型 |
| 4 | **`app_secret` 用 SHA-256 而非 bcrypt / argon2** | bcrypt | 它是高熵随机串，慢哈希只会让认证热路径**白付 CPU**；慢哈希只适用于低熵用户密码 |

> 第 3、4 条严格说不是"库选型"，而是**用法约定**，但它们的出错后果比选错库更严重，所以一并列出。

---

## 5. 明确不引入的东西

| 不引入 | 原因 |
| --- | --- |
| **fiber** | 基于 fasthttp，**不是 `net/http` 接口**——`httptest`、OTel 官方中间件、部分标准库生态都用不了。**这是技术障碍，不是偏好** |
| **Kubernetes / Helm** | 当前规模是单服务 + worker，docker-compose 足够；上 K8s 是运维成本先于收益 |
| **消息队列（Kafka / RabbitMQ / NATS）** | Outbox + Redis 已够。**引入 MQ 会带来"MQ 与 DB 的一致性问题"，而 Outbox 模式本身就是为解决它而生** |
| **Service Mesh / Istio** | 单服务，无必要 |
| **gRPC** | 对外是 HTTP / OAuth2 生态。若未来用户中心要求 gRPC，在 `accountclient` 单独加实现即可 |
| **依赖注入框架（wire / fx）** | `bootstrap` 手写装配更透明、易调试。**若 `bootstrap` 超过 300 行再评估 wire** |
| **分布式事务框架（Seata 等）** | 架构已用「三阶段独立事务 + 幂等 + 补偿」解决跨服务一致性（§7.3），不需要额外框架 |
| **配置中心（Nacos / Apollo）** | 配置变更用「DB + Redis Pub/Sub 广播」已实现（§9.2）。第四期再评估 |
| **自研 JWT / 自研加密** | 永远不自己实现密码学 |
| **`context.TODO()`** | lint 规则禁止；所有链路必须传递 context |

---

## 6. 开发环境

### 6.1 ⚠️ 当前环境缺少 Go（阻塞编码）

```
$ go version
bash: go: command not found
```

**编码前必须先安装 Go：**

```bash
# 方式一：包管理器（推荐）
winget install GoLang.Go
# 或 choco install golang

# 方式二：官方安装包 https://go.dev/dl/
```

安装后确认并设置国内代理（否则拉依赖会超时）：

```bash
go version && go env GOPATH GOMODCACHE GOPROXY
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
```

### 6.2 本地依赖服务

不要求开发机装 PG / Redis，用容器：

```bash
docker compose -f deployments/docker-compose.dev.yml up -d
```

包含：PostgreSQL 16、Redis 7。

### 6.3 开发提效

| 用途 | 工具 | 说明 |
| --- | --- | --- |
| 热重载 | **air** | 改代码自动重启 |
| Mock 三方平台 | `testserver/fake_oauth2` | 本地不依赖真实微信 / 支付宝，也是集成测试依赖 |
| 调试 | Delve（`dlv`） | VS Code / GoLand 直接接 |

**假平台（fake provider）是第一期的关键交付物**：第一期还没有真实渠道，需要它提供标准授权码流程才能端到端验证。

---

## 7. 依赖管理策略

| 项 | 约定 |
| --- | --- |
| 模块路径 | **待确认**（见 §7.1） |
| 版本锁定 | `go.mod` + `go.sum` 全部入库 |
| vendor | **不提交**（默认已 `.gitignore`）。若需完全离线构建再执行 `go mod vendor` 并删除忽略规则 |
| Go 版本声明 | `go.mod` 中写 `go 1.23`，不使用 `toolchain` 指令强制升级 |
| 依赖引入审批 | **核心链路禁止引入新依赖**（授权流程、合并流程、加解密）；辅助工具类可放宽 |
| 依赖数量上限 | 目标 ≤ 25 个直接依赖。每引入一个需在 PR 说明"为什么标准库或现有依赖做不到" |

### 7.1 ⚠️ 待确认：Go module 路径

架构文档中用的是占位符 `github.com/xxx/social-login`。**编码前需要确定真实仓库地址**：

```
github.com/<你的组织>/social-login
```

**这个路径一旦定下，后续所有 `import` 都依赖它，改动成本随文件数线性增长**，必须在写第一行代码前确认。

---

## 8. 仓库结构

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
│   ├── config/                    ← 配置结构体（viper 绑定）
│   ├── interfaces/http/
│   │   ├── handler/               ← 业务端 /v1/*（gin）
│   │   ├── handler/admin/         ← 管理端 /admin/v1/*（§15 的 A~K 组）
│   │   ├── middleware/            ← app 鉴权、限流、trace、Recovery（zap）
│   │   ├── middleware/adminmw/    ← 管理员 RBAC、IP 白名单、高危操作审计
│   │   └── dto/
│   ├── application/               ← 用例编排（事务边界）
│   │   ├── authflow/  binding/  token/  tenantconfig/  adminops/
│   ├── domain/
│   │   ├── identitysource/        ← D8 留口
│   │   ├── provider/              ← SPI + Registry
│   │   └── identity/  binding/  ticket/  account/
│   ├── infrastructure/
│   │   ├── provider/adapters/     ← wechat/ alipay/ apple/ generic_oauth2/
│   │   ├── persistence/           ← GORM models + Repository（含 app_id 全局 Callback）
│   │   ├── cache/                 ← go-redis + lua/
│   │   ├── crypto/                ← 凭据加密、claim 哈希、KMS 客户端
│   │   ├── accountclient/         ← HTTPAccountProvider
│   │   └── eventbus/              ← outbox 投递
│   └── pkg/                       ← errs / logx(zap) / httpx(net/http 封装) / jwtkit
├── migrations/                    ← 手写 SQL（DDL 唯一真相源）
├── configs/
│   ├── config.yaml
│   └── config.example.local.yaml  ← 提交示例，真实 local 配置被忽略
├── deployments/
│   ├── docker-compose.dev.yml
│   └── Dockerfile
├── testserver/
│   └── fake_oauth2/               ← 假三方平台，第一期关键交付物
└── scripts/
```

---

## 9. 与架构文档的对应关系

| 架构设计中的关键机制 | 由哪些技术栈支撑 |
| --- | --- |
| Provider SPI + 编译期注册（D1 / D7） | 纯标准库 + `init()` 注册，无框架依赖 |
| 部分唯一索引兜底并发绑定（§5.2） | **PostgreSQL 部分唯一索引** + GORM 经 `errors.As` 取 `*pgconn.PgError.ConstraintName` |
| `app_id` 强制隔离（§9.1） | **GORM 全局 Callback 自动注入**（比手写 SQL 更可靠） |
| 三次独立事务 + 补偿（P0-3） | GORM 显式事务 + `clause.Locking{Options:"SKIP LOCKED"}` + `event_outbox` 表 |
| JWKS 与密钥轮换（P0-2 / §8.3） | 手写 JWK 序列化（约 30 行）+ KMS / 环境变量 |
| Apple 验签与 client_secret 签发（C2） | **golang-jwt + keyfunc**（JWKS 拉取与轮换）+ ES256 签名 |
| 配置化合并行为（R2 / §7.5） | **viper** 读配置 + **JSONB** 存储 + `adminops/policy_validator` |
| 管理端与业务端隔离（§15.2） | **gin RouteGroup + 独立中间件链** + 网关按路径分流 |
| 可观测性（§11） | **otelgin + otelhttp** + **prometheus/client_golang** + **zap** |
| 三方调用差异处理（§4.3） | **net/http** + `pkg/httpx`（每渠道独立 client 与超时，不重试） |
| 重试边界（C6 / §5.5） | `pkg/httpx` 不提供重试选项；错误映射为 `retryable` 供接入方判断 |
| 渠道熔断（§5.6） | **sony/gobreaker/v2**（状态机）+ 自维护分类滑动窗口（四类独立阈值） |
| 入站超时保护（§5.7） | `http.Server` 三段超时 + gin 路由分组超时中间件 + `context` 向下传递 |
