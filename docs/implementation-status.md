# 实现状态对照 · 设计规划 vs 当前代码

> 基线：`docs/architecture-design.md`（§5.3 业务端 API、§13 分期路线、§15.4 管理端 API）
> 代码：commit `d4bf54d`（main）+ 第二期改动（未提交）
> 核对时间：2026-10-19（第二期交付后复核）
> 核对方式：逐条比对路由注册、包结构、表结构与依赖，不依据注释宣称

---

## 0. 一页结论

| 维度 | 规划 | 已实现 | 完成度 |
| --- | --- | --- | --- |
| 业务端 API（§5.3） | 14 | 12 | 86% |
| 渠道适配器（§4） | 4 平台 / 9 场景 | 4 平台 / 10 场景 | 100% |
| 管理端 API（§15.4） | 54 端点 / 11 组 | 22 端点 / 3 组 | 41% |
| 管理端前端 | 11 组界面 | 3 模块 6 页 | 约 30% |
| 分期路线 | 四期 | 第一期、第二期完成；三/四期未开始 | — |

**一句话**：第一期（骨架 + 最小闭环 + 管理端 A/B/I 组）与第二期（微信 4 场景 / 支付宝 3 场景 / Apple 2 场景 / 渠道熔断 / 服务端通知）已交付；第三期（合并）与第四期（生产化）未动。

**原先的 P0 缺陷已修复**（见 §1）。

---

## 1. ✅ 已修复：管理端与应用端的密钥哈希没有接线

> 状态：**已修复**（第二期）。下方保留原始分析，便于回溯"为什么曾经前后台链路是断的"。

**现象（曾实测复现）**

1. 通过 `POST /admin/v1/apps` 创建应用，返回的 `app_secret` 可以拿到；
2. 用该 `app_code` + `app_secret` 调 `POST /v1/token`，返回
   `{"code":"AUTH.UNAUTHORIZED","message":"应用凭据无效"}`（HTTP 401）。

**根因**

`internal/bootstrap/app.go:214` 显式传了 `HashSecret: nil`：

```go
HashSecret: nil, // 用 adminapp 默认实现
```

而 `adminapp.defaultHashSecret`（`service.go:482`）是占位实现：

```go
return "placeholder:" + plain, nil   // 明文直接拼在哈希位
```

业务端 `middleware.AuthenticateApp` 用 `crypto.AppSecretHasher.Verify()` 做 HMAC 比对，
与 `placeholder:<明文>` 永远不匹配。

**双重后果**

| 后果 | 严重性 |
| --- | --- |
| 管理端建的应用在业务端**完全不可用**，前后台链路断开 | 功能阻断 |
| `app_secret` **以明文形式落库**（`applications.app_secret_hash`） | 安全事故 |

**修复方式（已实施）**

1. `bootstrap/app.go` 把 `appSecretHasher` 注入 `adminapp.Deps.HashSecret`，做"同一把哈希器"——
   管理端写入、业务端校验必须共用同一个盐与算法：

   ```go
   HashSecret: func(plain string) (string, error) {
       if plain == "" {
           return "", errs.New(errs.CodeInvalidRequest, "app_secret 不能为空")
       }
       return appSecretHasher.Hash(plain), nil
   },
   ```

2. `adminapp.defaultHashSecret` 改为**显式报错**，不再静默退化为 `placeholder:`。
   这一条比第 1 条更重要：静默降级会让同类问题在下次重构时再次发生而无人察觉。

3. `scripts/acceptance-admin.sh` 增加第 16 步跨端用例：用管理端创建的
   `app_code` / `app_secret` 调 `/v1/introspect`，断言不得返回 `AUTH.UNAUTHORIZED`。

**遗留**：历史数据里若已有 `placeholder:` 记录，需要一次性修数据
（重新轮换密钥即可，无需手工改库）。

---

## 2. 业务端 API（§5.3）

| 方法 | 路径 | 状态 | 说明 |
| --- | --- | --- | --- |
| GET | `/v1/authorize` | ✅ | |
| GET | `/v1/oauth/callback/{platform}` | ✅ | |
| GET | `/v1/jwks` | ✅ | 公钥集可发布 |
| GET | `/.well-known/openid-configuration` | ✅ | |
| POST | `/v1/token` | ⚠️ | 仅 `authorization_code` / `refresh_token`；`grant_type=silent` 显式返回未实现 |
| POST | `/v1/introspect` | ⚠️ | 纯本地验签；`check_revocation=true` 返回未实现 |
| GET | `/v1/userinfo` | ✅ | |
| POST | `/v1/revoke` | ⚠️ | refresh_token 可撤；access_token 只能等过期（无 jti 黑名单） |
| POST | `/v1/bind` | ✅ | |
| DELETE | `/v1/bind/{identity_id}` | ✅ | |
| GET | `/v1/bindings` | ✅ | |
| POST | `/v1/bind/resolve` | ❌ | **冲突处置入口缺失**（C5 关键） |
| POST | `/v1/account/merge` | ❌ | **账号合并缺失** |
| POST | `/v1/oauth/notify/{platform}` | ✅ | 平台服务端通知；Apple `consent-revoked` / `account-delete` 已闭环 |

**缺失 2 个**（`/v1/bind/resolve`、`/v1/account/merge`），**降级 3 个**（token 的 silent、introspect 的撤销检查、revoke 的即时生效）。

---

## 3. 渠道适配器（§4 / §13 第二期）

`internal/infrastructure/provider/adapters/` 下现有 `generic_oauth2/`、`wechat/`、`alipay/`、`apple/`
四个包，编译期注册共 **10 个 (平台, 场景)** 组合。

| 平台 | 场景 | 规划期 | 状态 |
| --- | --- | --- | --- |
| 通用 OAuth2 | web | 一期 | ✅ |
| 微信 | `app`（iOS/Android 共用） | 二期 | ✅ |
| 微信 | `mini_program` | 二期 | ✅ |
| 微信 | `official_account`（公众号 H5） | 二期 | ✅ |
| 微信 | `pc_qr`（扫码） | 二期 | ✅ |
| 支付宝 | `app` / `mini_program` / `web` | 二期 | ✅ |
| Apple | `app` / `web` | 二期（**约束 C2 硬性要求**） | ✅ |

**专项能力落地情况**

| 专项 | 状态 | 落点 |
| --- | --- | --- |
| Apple `client_secret` JWT（ES256）自动签发与续期 | ✅ | `apple.go:clientSecret`，缓存 30 天、提前 1 小时过期 |
| Apple JWKS 验签 + `kid` 未命中重取 | ✅ | `apple/jwks.go`，1 小时 TTL，URL 变化即失效 |
| Apple `nonce` 防重放 | ✅ | `verifyIDToken` 强制比对，缺 nonce 一律拒绝 |
| Apple 首次授权的 name / email 落库 | ✅ | `parseAppleName`，`email_verified` 才标可信来源 |
| Apple `consent-revoked` / `account-delete` 处理 | ✅ | `ParseCallback` + `oauthnotify.Service`，通知入口 `/v1/oauth/notify/{platform}` |
| 微信 `unionid` 不写入（C3） | ✅ | 适配器刻意不写 `UnionID`，`identity_key = open_id` |
| 微信 48001 静默授权降级 | ✅ | `UserInfo` 把 48001 视为"未授权手机号"而非失败 |
| 微信手机号解密（R4 红线 1） | ✅ | `crypt.go`：AES-128-CBC + PKCS#7 + watermark.appid 校验 |
| 支付宝 RSA2 签名与**响应体原始字节验签** | ✅ | `sign.go:verifyRawBytes`，用 `json.RawMessage` 而非重编码 |
| 小程序 `session_key` 生命周期管理（Redis） | ⚠️ | 仅经 `TokenSet.SessionKey` 在单次请求内传递；未落 Redis，因此**跨请求的手机号解密尚不可用** |

**仍然空白**：`generic_oauth2` 之外没有其它平台的 `Unbind` 走三方侧拉黑（微信 `Unbind` 返回 NotSupported，
需走开放平台接口，属四期"Unbind 降级提示"范围）。

---

## 4. 管理端 API（§15.4）

已挂载 22 个业务端点 + 3 个 auth 端点（`login` / `me` / `logout`）。
§15.4 表内共 54 个端点，**未实现 32 个**。

| 组 | 主题 | 规划 | 已实现 | 缺口 |
| --- | --- | --- | --- | --- |
| A | 应用与策略 | 8 | 8 | — |
| B | 渠道配置 | 10 | 10 | — |
| C | 身份与绑定 | 6 | 0 | 全部 |
| D | 合并运维 | 5 | 0 | 全部 |
| E | 会话与令牌 | 3 | 0 | 全部 |
| F | 签名密钥管理 | 4 | 0 | 全部 |
| G | 事件与死信 | 4 | 0 | 全部 |
| H | 审计日志 | 4 | 0 | 全部 |
| I | 观测与健康 | 4 | 4 | — |
| J | 凭证一致性 | 3 | 0 | 全部 |
| K | 管理员授权 | 3 | 0 | 全部 |

**逐组说明**

- **C 组**：`/identities`、`/identities/{id}`、`/bindings`、`/accounts/{uid}/bindings`、`DELETE /bindings/{id}`（强制解绑）、`/bindings/{id}/transfer`（transfer 旁路）。客服工单类诉求目前无后台可用。
- **D 组**：`merge-operations` 的 list / detail / retry / resolve / impact。与第三期合并功能同批交付。
- **E 组**：`/tokens`（活跃会话查询）、`/tokens:revoke`（强制下线）、`/revoked-jti`。
- **F 组**：`/signing-keys` 的 list / rotate / retire / jwks:preview。§8.3 的"四步轮换"目前只能手工改配置文件重启。
- **G 组**：`/events/outbox` 的 list / detail / retry / discard。
- **H 组**：`/audit-logs`（业务审计）、`/audit-logs/admin`（管理审计）、`:export` 与导出任务查询。**审计数据在写、但没有任何查询入口**。
- **J 组**：`/claims`、`/claims/mismatches`、`/claims/{id}:revoke`。
- **K 组**：`/admin-grants` 的 list / create / delete。`admin_grants` 表已建但代码中零引用，角色仍硬编码在 `internal/domain/admin/admin.go`。

**通用约定的缺口**

| 约定 | 状态 |
| --- | --- |
| 游标分页 `page_size` + `page_token` | ⚠️ 仅 `apps` 列表有简化分页，无统一游标 |
| `Idempotency-Key` 请求头（24h 结果缓存） | ❌ 全局未实现 |
| 高危操作 `reason` 必填 | ✅ 已实现 |
| 影响面预估 `.../impact` 或 `?dry_run` | ⚠️ 仅 `policy:validate` 有 dry-run |
| 前后快照 `before_state` / `after_state` | ⚠️ 仅写 `reason`，无快照 |
| 双人复核 `admin_approvals` | ❌ 表未建、流程未做 |

---

## 5. 管理端前端

现有 6 个页面 / 3 个导航模块：

| 模块 | 页面 | 对应 API 组 |
| --- | --- | --- |
| 应用与策略 | 列表 / 新建 / 详情 | A |
| 渠道配置 | 渠道列表 | B |
| 观测 | 观测看板 | I |

未覆盖：C、D、E、F、G、H、J、K 八组的全部界面。
即使后端补齐，前端仍需对应新建约 8 个页面。

**二期新增的后端能力尚未上屏**：`GET /admin/v1/providers/health` 已返回
`circuit_state` / `circuit_opened_at` / `recent_failure_ratio` / `recent_timeout_ratio`，
但观测看板仍只展示"通/不通"。熔断状态与一键复位（`circuit-reset`）需要有独立视图，
否则运维只能靠翻日志判断熔断是否打开。

---

## 6. 平台能力（非 API 维度）

| 能力 | 设计位置 | 状态 | 说明 |
| --- | --- | --- | --- |
| 渠道超时分层 | §5.7 | ✅ | 连接级 `HTTPServer` + 分组 `Timeout()` + `httpx` 内 `context.WithoutCancel` |
| 上游取消隔离 | §5.7 | ✅ | `httpx/client.go:350` 用 `context.WithoutCancel` |
| 渠道熔断器 | §5.6 | ✅ | `internal/pkg/guards/breaker`（gobreaker v2 状态机 + 自维护四类信号滑动窗口）+ `providerguard` 装饰器；业务拒绝与"慢的业务拒绝"均不计入 |
| 渠道健康探测 | §11 | ✅ | `/admin/v1/providers/health` 真实 ping `token_url` |
| 事件投递 worker | §5.4 | ❌ | `event_outbox` 表已建，**无任何 Go 代码读写它**（仅出现在 GORM scope 白名单里） |
| Webhook 签名 / 重试 / 去重 / 死信 | §5.4 | ❌ | 零实现（`webhook` 关键字在代码中 0 命中） |
| 账号合并链路 | §7.3 | ❌ | 三次独立事务、幂等键、本地收敛均无 |
| 合并补偿任务 | §7.3 | ❌ | `merge_operations` 表已建，无读写代码 |
| 合并前回源核对 | §8.5 | ⚠️ | `ClaimRepository` 有 `GetByClaim` 类查询，但归并流程未落地，无调用方 |
| `policy.merge` 配置模型 + 一致性校验 | §7.5 | ✅ | 模型、`Validate()`、`policy:validate` dry-run 均可用 |
| 三种合并模式 `auto`/`confirm`/`manual` | §7.2 | ❌ | `finishBind` 的冲突分支**统一返回 `BIND.IDENTITY_TAKEN`**，未按 mode 分叉 |
| R4 红线：只采用可信来源凭证 | §7.5 | ✅ | `userAccountClaims` 过滤 `source=manual` |
| `jti` 撤销黑名单 | §8.4 | ❌ | 无 Redis 键、无写入、无查询 |
| refresh_token 轮转 | §8.2 | ✅ | 单向链，旧记录置 revoked |
| KMS 信封加密（DEK） | §D6 | ❌ | 单层本地 KEK 直加；`secret_dek_id` 写入的是 KEK ID |
| 配置热更新 | §D6 | ✅（简化） | 每请求读库，改配置立即生效；无本地缓存层 |
| 限流（含 provider 维度配额） | §10 | ❌ | 仅错误码 `RATE.LIMITED`，无中间件 |
| 指标（Prometheus） | §11.1 | ❌ | go.mod 无 prometheus 依赖 |
| 分布式追踪 | §11.2 | ❌ | 无 otel SDK；仅有自建 `trace_id` 贯穿日志 |
| 结构化日志 | §11.3 | ✅ | zap + `RequestID` / `AccessLog` |
| 账号注销与数据删除 | §10.2 | ❌ | 无接口 |
| `Unbind` 不支持时的降级提示 | §13 四期 | ❌ | — |
| 管理员 RBAC 角色表 | §15.3 | ⚠️ | 四角色 + 权限闭包表已定义，但角色固定、无 grants 动态授权 |
| 管理端网络边界（IP 白名单） | §15.2 | ❌ | 注释声明由部署侧保证，代码零实现 |

---

## 7. 依赖外部的前置条件

| 依赖 | 状态 | 影响 |
| --- | --- | --- |
| `HTTPAccountProvider`（真实用户中心） | ❌ 未实现 | `account.provider=http` 启动即报错；当前只有内存 `StubAccountProvider`，**重启即丢账号** |
| 用户中心 `Merge` 幂等语义 | 待对齐 | 不满足则第三期补偿只能降级为"只告警" |
| 用户中心 `GetByClaim` 强一致读 | 待对齐 | 归并最后一道防线 |
| 用户中心推送 `claim.invalidated` | 待对齐 | 手机号变更后 claim 无法及时失效 |

---

## 8. 建议的推进顺序

> 第二期已交付项（HashSecret 接线、渠道熔断、微信 4 场景、支付宝 3 场景、Apple 2 场景、
> 服务端通知入口）已从下表移除，保留原序号便于与历史记录对照。

| 优先级 | 事项 | 理由 |
| --- | --- | --- |
| **P0** | 补 `event_outbox` 投递 worker | 第一期唯一未交付项；所有后续事件能力都压在它上面 |
| P1 | 小程序 `session_key` 落 Redis | 不落库则跨请求的 `getPhoneNumber` 解密不可用，R4 红线 1 实际走不通 |
| P1 | 管理端观测页展示熔断状态 + 复位按钮 | 后端已返回 `circuit_state`，前端未上屏，运维看不到熔断 |
| P2 | 管理端 G + H 组 | 渠道一接入，排障只能靠死信与审计查询 |
| P2 | `POST /v1/bind/resolve` + 三模式分叉 | 第三期核心；也是客服最常见的工单类型 |
| P3 | `HTTPAccountProvider` | 依赖用户中心就绪，需并行推进 |
| P3 | 合并链路（三事务 + 补偿 + 回源核对） | 高风险，必须与管理端 C/D/J 同批上 |
| P4 | jti 黑名单 / KMS / 限流 / 指标 | 生产化，可在灰度前补 |

---

## 9. 容易被误判为"缺失"的部分（实际已有）

| 项 | 实际情况 |
| --- | --- |
| 配置热更新 | 每请求读库，改完即生效；只是没有缓存层，不是没有能力 |
| 渠道连通性校验 | `POST .../secret/verify` 真实发起 HTTP 调用，已可用 |
| 策略 dry-run | `policy:validate` 已实现，含 REJECT / WARN 区分 |
| 审计写入 | 业务审计与管理审计都在写表，只是缺查询接口 |
| 凭证加密 | AES-GCM + 本地 KEK 已可用，缺的是 DEK 信封分层 |
| 凭据双活轮换 | `secret_cipher_prev` + `finalize` 已实现 |
| 未绑定分支 | `need_register` / `auto_create` 两条分支都走了 |
| Claim 可信源白名单 | R4 红线 1 已在 `userAccountClaims` 中落实 |
| 入站超时 | 三级（连接 / 分组 / 单渠道）都有 |

---

## 附：核对依据

- 路由：`internal/interfaces/http/router.go`、`internal/interfaces/http/admin/mount.go`
- 适配器注册：`internal/infrastructure/provider/adapters/`、`internal/bootstrap/app.go:27`
- 表结构：`migrations/00001_init.sql`、`migrations/00002_admin.sql`
- 关键缺口点：`bootstrap/app.go:214`（HashSecret nil）、`authflow/branches.go:228`（三种 mode 未分叉）、`handler/token.go:75`（silent 未实现）、`token/service.go:268`（jti 未实现）、`build.go:119`（HTTPAccountProvider 未实现）

---

## 10. 第二期交付明细

### 10.1 新增包

| 包 | 行数量级 | 职责 |
| --- | --- | --- |
| `internal/pkg/guards/breaker` | ~500 | 熔断状态机 + 四类信号滑动窗口（失败率/超时率/慢请求率/连续超时） |
| `internal/infrastructure/providerguard` | ~130 | 装饰器：把 `Exchange/UserInfo/Refresh/Unbind` 包进熔断；不包 `AuthURL`/`VerifyCallback`/`Ping` |
| `internal/infrastructure/provider/adapters/wechat` | 4 文件 | 微信 app / mini_program / official_account / pc_qr |
| `internal/infrastructure/provider/adapters/alipay` | 2 文件 | 支付宝 app / mini_program / web |
| `internal/infrastructure/provider/adapters/apple` | 3 文件 | Apple app / web（含 JWKS、client_secret JWT、id_token 验签） |
| `internal/application/oauthnotify` | ~330 | 平台服务端通知的编排（验签闸门 → 解析 → 解绑 → 审计） |

### 10.2 契约变化

| 契约 | 变更 | 原因 |
| --- | --- | --- |
| `provider.UserInfoRequest` | 新增 `Extra map[string]string` | 小程序手机号解密 / Apple `id_token` 出现在回调参数里，不在 Exchange 产出中 |
| `provider.ExchangeRequest` | 新增 `Nonce string` | Apple 的 `nonce` 必须回比对 |
| `provider.CallbackPayload` | 新增 `Audience string` | Apple JWKS 是全局的，签名有效 ≠ 发给我们的；必须按渠道配置的 client_id 校验 `aud` |
| `provider.CallbackParser` | 新增可选接口 | 验签是"能不能信"，解析是"说了什么"，两者失败语义不同，不能合并 |
| `identitysource.CallbackCapability` | 新增可选接口 | `VerifyCallback` 对"无需验签"和"未实现"都返回 nil，通知入口必须显式探测能力，不能靠 nil 推断 |
| `identitysource.Registry` | 新增 `SetWrapper()` | 熔断装饰器在 `Lookup` 时应用（注册发生在 `init()`，那时配置还不存在） |

### 10.3 两条安全红线的单测固化

| 红线 | 用例 |
| --- | --- |
| 业务拒绝（如用户点"拒绝"）不得计入熔断 | `breaker.TestBusinessRejectNeverTrips`（500 次业务拒绝仍 closed）、`TestSlowBusinessRejectNotCountedAsSlow` |
| 未实现验签的渠道不得处理服务端通知 | `oauthnotify.TestRejectsWhenVerifyNotImplemented`（能力缺失时零状态变更） |
| 通知必须校验 `aud` | `apple.TestParseCallbackRejectsAudMismatch` |
| 平台重投必须幂等 | `oauthnotify.TestIdempotentWhenAlreadyUnbound`、`TestIdentityNotFoundIsNotError` |

### 10.4 尚未闭环的三处

1. **小程序 `session_key` 未落 Redis**：目前只在一次请求内从 `TokenSet` 传到 `UserInfo`。
   如果手机号解密发生在后续独立请求里（业务方先拿 code 换登录态、再单独上报加密手机号），
   就取不到 `session_key`。补法是给 `authflow` 增加一个按 `(app_id, open_id)` 索引的 Redis 缓存，
   TTL 取微信返回值。
2. **管理端观测页未展示熔断状态**：后端 `providers/health` 已返回
   `circuit_state` / `recent_failure_ratio` / `recent_timeout_ratio`，
   且对"熔断器尚未惰性创建"的情况默认填 `closed`（`breaker.StateClosedName`），
   但前端观测看板仍只显示通/不通。
3. **通知入口没有限流**：`/v1/oauth/notify/{platform}` 是公开端点，验签前会做一次 RSA 运算。
   当前靠 64 KiB body 上限与 `Timeout(15s)` 保护，缺少按 IP 的限流（限流中间件整体未实现，见 §6）。

### 10.5 顺带修复的第二个落库缺陷（联调时发现）

**现象**：`POST /admin/v1/apps/{appId}/provider-configs` 返回
`INTERNAL.ERROR: 保存渠道配置失败: null value in column "extra" of relation "app_provider_configs" violates not-null constraint (SQLSTATE 23502)`。

**根因**：`JSONMap.Value()` 对 nil map 返回 SQL `NULL`。这个语义是**刻意**的——
`admin_audit_logs.before_state` / `after_state` 是可空列，`NULL` 表示"没记录快照"。
但 `app_provider_configs.extra` 是 `NOT NULL DEFAULT '{}'`，而管理端建渠道时通常
不填 `extra`，于是 `cfg.Extra == nil` 直接落成 `NULL` 并撞上约束。

**影响**：**任何渠道配置都建不出来**——也就是说第二期的三个适配器在真实部署里
根本配不上去。这是一个比"功能缺失"更彻底的阻断，只是没人走这条路径所以一直没暴露。

**修复**：新增 `jsonNotNull(m map[string]any) JSONMap`，凡是写 `NOT NULL` jsonb 列
一律走它（nil → `{}`）；可空列继续用 `JSONMap` 保留 NULL 语义。落点三处：

| 列 | 写入点 |
| --- | --- |
| `app_provider_configs.extra` | `providerconfig_repo.Create` |
| `oauth_identities.profile_snapshot` | `identity_repo.Upsert` |
| 审计 `detail` | `audit_repo.Write` |

后两处是同类潜在缺陷（平台什么都没返回时 Profile 为空、并非每条审计都有 detail），
尚未被触发但一定会触发。
