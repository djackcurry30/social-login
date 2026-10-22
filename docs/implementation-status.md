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

已挂载 27 个业务端点 + 3 个 auth 端点（`login` / `me` / `logout`）。
§15.4 表内共 54 个端点，**未实现 27 个**（G 组 4 个已补齐，另新增 1 个 A 组补充端点 `PUT /apps/{id}/webhook`）。

| 组 | 主题 | 规划 | 已实现 | 缺口 |
| --- | --- | --- | --- | --- |
| A | 应用与策略 | 8 | 8 | — |
| B | 渠道配置 | 10 | 10 | — |
| C | 身份与绑定 | 6 | 0 | 全部 |
| D | 合并运维 | 5 | 0 | 全部 |
| E | 会话与令牌 | 3 | 0 | 全部 |
| F | 签名密钥管理 | 4 | 0 | 全部 |
| G | 事件与死信 | 4 | 4 | — |
| H | 审计日志 | 4 | 0 | 全部 |
| I | 观测与健康 | 4 | 4 | — |
| J | 凭证一致性 | 3 | 0 | 全部 |
| K | 管理员授权 | 3 | 0 | 全部 |

**逐组说明**

- **C 组**：`/identities`、`/identities/{id}`、`/bindings`、`/accounts/{uid}/bindings`、`DELETE /bindings/{id}`（强制解绑）、`/bindings/{id}/transfer`（transfer 旁路）。客服工单类诉求目前无后台可用。
- **D 组**：`merge-operations` 的 list / detail / retry / resolve / impact。与第三期合并功能同批交付。
- **E 组**：`/tokens`（活跃会话查询）、`/tokens:revoke`（强制下线）、`/revoked-jti`。
- **F 组**：`/signing-keys` 的 list / rotate / retire / jwks:preview。§8.3 的"四步轮换"目前只能手工改配置文件重启。
- ~~**G 组**：`/events/outbox` 的 list / detail / retry / discard。~~ → **已实现**，见 §11。
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

### 10.4 尚未闭环的两处

> 原先的"小程序 `session_key` 未落 Redis"已在 §10.6 闭环。

1. **管理端观测页未展示熔断状态**：后端 `providers/health` 已返回
   `circuit_state` / `recent_failure_ratio` / `recent_timeout_ratio`，
   且对"熔断器尚未惰性创建"的情况默认填 `closed`（`breaker.StateClosedName`），
   但前端观测看板仍只显示通/不通。
2. **通知入口没有限流**：`/v1/oauth/notify/{platform}` 是公开端点，验签前会做一次 RSA 运算。
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

---

## 10.6 小程序 `session_key` 跨请求共享（R4 红线 1 的前提）

### 10.6.1 问题

`getPhoneNumber` 有两条路径，只有一条需要 `session_key`：

| 路径 | 服务端依赖 | 跨请求是否可行 |
| --- | --- | --- |
| `phone_code` → `wxa/business/getuserphonenumber` | 仅 `access_token`（已有进程内缓存） | 天然可行，**与 `session_key` 无关** |
| `encrypted_data` + `iv` → 本地 AES-128-CBC | `code2Session` 返回的 `session_key` | **不可行**，除非把密钥跨请求保存 |

业务方常见的接法是"先拿 code 换登录态，再单独上报加密手机号"。第二次请求若被
负载均衡打到另一个实例，原来的进程内实现就取不到密钥——表现为**概率性**解密失败，
单实例本地永远复现不了，滚动发布、扩缩容、进程重启都会触发。

### 10.6.2 方案

| 项 | 决定 |
| --- | --- |
| 端口 | `internal/domain/sessionkey.Store`（`Put` / `Get` / `Delete`） |
| 生产实现 | `internal/infrastructure/cache.SessionKeyStore`（Redis） |
| 测试/单机实现 | `internal/domain/sessionkey.MemoryStore` |
| 注入方式 | `bootstrap` 调 `wechat.ConfigureSessionStore(store, logger)`，**未注入时安静跳过** |
| 键 | `mp:sk:{app_code}:{open_id}` |
| 值 | `base64(KeyManager.Encrypt(session_key))` —— 与渠道凭据同一把 KEK |
| TTL | `sessionkey.DefaultTTL`（2h）。微信不返回过期时间，取与登录态同量级 |
| 丢弃 | 解密成功后立即 `Delete` |

为什么适配器不直接连 Redis：适配器由 `init()` 在包加载时注册（决策 D7），那一刻
配置与 Redis 都不存在，构造函数拿不到依赖。因此只声明端口，由 `bootstrap` 注入，
与 `Registry.SetWrapper` 的处理方式一致。这样单测不必起 Redis，适配器也不绑定基础设施。

### 10.6.3 只上 Redis 还不够的三处

1. **读取时必须允许回退**：跨请求场景下，本次 `code2Session` 返回的是**新**密钥，
   它解不开上一次的密文。所以要"先用本次密钥解，失败再回查共享存储"。
   只把密钥存进 Redis、不做这一步，照样失败。
2. **写入必须在响应返回之前**：否则客户端拿到登录态立刻发第二个请求，另一个实例
   可能还读不到。这是纯粹的时序约定，Redis 本身不保证。
3. **必须覆盖写，不能并存**：`session_key` 每次登录都会变。两份并存等于多留了一份
   能解开历史密文的密钥，`Delete` 也就失去了意义。

### 10.6.4 失败语义（R4 红线 1）

`sessionkey.ErrNotFound` 表示"密钥不可用"，**不能**当成"用户没有手机号"。
后者是正常业务结果，前者必须返回 `AUTH.INVALID_STATE` 并明确提示
"重新调用 getPhoneNumber"，否则下游会拿一个未经校验的号码继续用，红线就被绕过了。

同理，`Get` 在**密文解不开**（KEK 轮换、值被写坏）时也返回 `ErrNotFound` 而不是
内部错误：正确处置是让该用户重新授权，不是让登录 500。

### 10.6.5 测试

| 用例 | 断言 |
| --- | --- |
| `wechat.TestCrossRequestUsesStoredSessionKey` | 本次密钥为空时回查存储成功，且解密后密钥被删除 |
| `wechat.TestSessionKeyScopedPerApp` | 跨应用不复用（约束 C1），返回 `AUTH.INVALID_STATE` |
| `wechat.TestMissingSessionKeyFailsLoudly` | 密钥缺失必须报错，不得静默返回空手机号 |
| `wechat.TestSameRequestStillPreferred` | 同请求密钥优先于存储里的旧密钥 |
| `wechat.TestNoStoreKeepsSameRequestWorking` | 未注入存储时同请求解密照常工作 |
| `sessionkey.TestMemoryStore*` | 覆盖写、TTL 过期、跨应用隔离、重复删除幂等 |
| `cache.TestSessionKeyStoreEncryptsAtRest` | Redis 里的值**不含**明文密钥 |
| `cache.TestSessionKeyStoreWrongKEKIsNotFound` | KEK 轮换后按"不可用"处理，不报内部错误 |

`cache` 包的 7 个用例是集成用例：默认连 `127.0.0.1:16379`（`docker-compose.yml` 里
redis 的回环端口映射），连不上则 `t.Skip` 而不是假通过。

---

## 11. 事件外发（Transactional Outbox）+ 管理端 G 组

### 11.1 为什么这一批先做它

架构 §13 把 `event_outbox` + 投递 worker 列为**第一期**交付项，实际一直没做；
而二期又明确要求"G 组必须与渠道同批交付"。两者是同一件事的两端：
没有 worker，outbox 只是张表；没有 G 组，投递失败就只能翻库。
三期合并链路（`account.merged`）也压在它上面，所以先补这一块。

### 11.2 新增组件

| 位置 | 职责 |
| --- | --- |
| `domain/event` | `Event` / `Status` / `Store` 端口、`Backoff`（§5.4 固定序列）、`PermanentError`、`ErrNoWebhook` |
| `persistence/postgres/event_repo.go` | `Append`、`ClaimDue`、状态回写、管理端查询与重投 |
| `infrastructure/webhook` | HMAC 签名、投递、状态码分类 |
| `application/outbox` | 投递循环与状态机 |
| `application/adminevent` | G 组用例（list / detail / retry / discard） |
| `migrations/00003_webhook.sql` | `applications.webhook_url` / `webhook_secret_enc` / `webhook_secret_kid` |

### 11.3 三个关键实现选择

1. **领取用租约，不引入 `sending` 状态**
   `SELECT ... FOR UPDATE SKIP LOCKED` + 把 `next_retry_at` 推到 `now()+lease`。
   多副本天然互斥；进程崩溃时租约自然过期，事件自动回到待投递，
   不需要额外的"超时回收"任务，也不会有卡在 `sending` 的僵尸行。
2. **4xx 直接死信，5xx/408/429 才重试**
   对方返回 400/401/403/404 时重试五次只是浪费退避窗口，
   而且死信里会看不出"是对方拒收"还是"我们没送到"。
3. **未配置 webhook 落 `skipped`，不是 `sent`**
   标 `sent` 会让监控以为投递成功；一直 `pending` 会让积压指标永远飘红。
   `skipped` 让"这个应用没配投递"成为可查询的事实。

### 11.4 状态机

```
pending ──成功──> sent
   │
   ├──4xx（非 408/429）──> dead
   ├──第 5 次失败─────────> dead
   ├──未配置 webhook──────> skipped
   └──可重试──────────────> pending（下次 = now + 1s/10s/1m/10m/1h）
dead / skipped / discarded ──人工 retry──> pending（event_id 不变）
```

`discarded` 是人工丢弃，与 `dead`（投递失败）分开，
便于回答"这条是我们送不到，还是人主动放弃的"。

### 11.5 端到端验证（本地 compose 实测）

1. `PUT /admin/v1/apps/18/webhook` 配一个连不上的地址 → 200；
2. 直接写一条 `pending` 事件；
3. 8 秒后 `GET /admin/v1/events/outbox?app_id=18` → `attempts=2`，
   `next_retry_at` 已按退避推进，`last_error` 记录 `connection refused`；
4. 对 `pending` 事件调 `retry` → 400 `REQUEST.INVALID`（状态守卫生效）；
5. `discard` 带合法 reason → 200，详情变为 `discarded`，且 `last_error` **保留**了
   原来的投递失败原因（丢弃理由只进管理审计，不覆盖排障信息）；
6. `reason` 过短 → 400 `ADMIN.REASON_REQUIRED`。

### 11.6 顺手修掉的错误码映射缺陷

`errs.defaults` 里**漏了整组 `ADMIN.*`**，导致 `Status` 取零值、
`httputil.Fail` 统一折算成 **500**。表现是"管理员少填一个 reason 却收到
500 INTERNAL"，前端无法当表单校验错误处理。已补：

| 错误码 | 修正后 |
| --- | --- |
| `ADMIN.REASON_REQUIRED` | 400 |
| `ADMIN.VERIFY_FAILED` | 400 |
| `ADMIN.CONFLICT` | 409 |
| `ADMIN.SESSION_EXPIRED` / `SESSION_REVOKED` | 401 |

这个缺陷影响 A/B 组的全部 reason 校验，不只是 G 组。

### 11.7 尚未闭环

1. **业务侧没有事件发射点**：`binding.created` / `account.merged` 等尚未写入 outbox。
   原因是当前仓储层没有 unit-of-work，无法让"业务写入 + 事件写入"落在同一事务里，
   而 outbox 的全部价值正在这个原子性上——**先发射、后补事务等于制造假象**。
   等三期的合并链路（本身就需要三事务编排）一起引入事务管理器再落。
2. **worker 与在线请求同进程**：架构建议独立部署。当前靠租约保证多副本不重复，
   拆进程不需要改代码，但还没有独立进程入口。
3. ~~**H 组（审计查询）仍未实现**~~：已在 §12 交付。

---

## 12. 管理端 H 组（审计查询 + 异步导出）

### 12.1 为什么排在 G 组之后立刻做

G 组（§11）回答"事件发出去没有"，H 组回答"当时到底是谁做了什么"。
两者是同一类能力——**线上排障时的证据链**。审计数据此前一直在写
（`auth_audit_logs` / `admin_audit_logs`），但没有查询入口，等于
"有日志、无检索"，出了事故还是只能连库翻。

### 12.2 端点

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/audit-logs` | 业务审计：`app_id` / `action` / `result` / `external_user_id` / `trace_id` / `platform` / `client` / 时间范围 | `audit:read` |
| GET | `/admin/v1/audit-logs/admin` | 管理端审计：`subject_id` / `action` / `target_type` / `target_id` / `app_id` / `result` / 时间范围 | `audit:read` |
| POST | `/admin/v1/audit-logs/export` | 提交导出，返回 `task_id`（**202**） | `audit:read` |
| GET | `/admin/v1/audit-logs/export/{taskId}` | 查任务状态 | `audit:read` |
| GET | `/admin/v1/audit-logs/export/{taskId}/download` | 下载 CSV | `audit:read` |
| GET | `/admin/v1/audit-logs/exports` | **补充**：我的导出任务列表 | `audit:read` |

> 文档里写作 `/audit-logs:export`，但 gin 不允许路径段内出现冒号（会被当成参数前缀）。
> 与 A 组 `secret/rotate`、B 组 `secret/verify` 一致，统一改成斜杠分段。
>
> 最后一行是文档未列的必要补齐：`task_id` 只在提交响应里出现一次，
> 前端刷新页面就再也找不回来，任务列表页无从实现。

### 12.3 关键实现选择

1. **导出必须异步**（§5.5 ①）。审计表是仓库里唯一可能上千万行的表，
   同步等待会长时间占住连接；用 202 + task_id 让调用方立刻拿到位置。
2. **流式读取，不用 OFFSET 深翻页**。`audit.Query.Stream` 用
   `(created_at, id) < (?, ?)` 的键集游标，每批 500 行回调写盘，
   内存占用与总量无关。导出与页面筛选共用同一套 `auditFilter`——
   两份过滤逻辑迟早会出现"页面看到 3 条、导出 5 条"。
3. **`COALESCE` 收敛 NULL**。`external_user_id` / `user_agent` / `trace_id`
   等列允许为 NULL，GORM 把 NULL 扫进 `string` 会直接报
   `converting NULL to string is unsupported`。在查询列上收敛成空串，
   而不是把写入侧的模型全改成指针。
4. **task_id 用 16 字节随机 hex，不用自增**。它会出现在 URL 里，
   自增数字可枚举 = 能猜别人的导出任务。归属校验仍然做（只允许本人，
   `super_admin` 例外），但不可枚举是纵深防御而非替代品。
5. **下载走鉴权接口，不给直链**。审计含 openid、IP、UA 与错误详情，
   直链一旦外泄等于永久公开（本地文件存储也给不了预签名 URL）。
   匿名访问返回 401，已在验收脚本里固化。
6. **CSV 带 UTF-8 BOM**。不带它 Excel 会把中文按本地编码解释，
   打开就是乱码——"导出给运营看"的场景里最常见的坑。
7. **O_EXCL 创建 + 失败只删本次创建的文件**。同名文件存在说明逻辑异常
   （task_id 随机且唯一），此时宁可失败也不覆盖；反过来，失败清理时
   若把 O_EXCL 撞到的既有文件删了，就是误伤别人的数据。

### 12.4 状态机

```
pending ──(worker 领取)──► running ──► succeeded（写 file_path / row_count / expires_at）
                             └──────► failed（写 error_code / error_message）

启动时：running ──► pending（RequeueStale，进程崩溃遗留）
每小时 ：expires_at < now ──► 删文件 + 删行（PurgeExpired）
```

与 outbox 的差别：**没有退避重试**。事件对外有副作用（丢了就是事故），
导出是幂等只读操作，失败重跑由用户重新提交即可；因此也没有租约，
靠启动时一次性 `RequeueStale` 收敛崩溃遗留。

### 12.5 配置

```yaml
audit:
  export_dir: "./var/exports"   # 置空即关闭 worker（会打 Warn 说明原因）
  export_file_ttl: "168h"       # 7 天
  # export_worker_enabled: false
```

compose 里给 app 挂了 `export-data:/app/var/exports` 卷：
不挂卷的话容器一重启，已完成的任务就变成"元数据说成功、文件却不在"。

### 12.6 顺带修掉的一处暴露

`GET /admin/v1/apps` 此前把 `*tenant.Application` 直接序列化返回，
于是 `AppSecretHash` 连同内部字段一起发给了 viewer 角色。哈希虽不可逆，
但它是验签密钥的**全部秘密所在**，泄露后可离线爆破——属于不必要的暴露。

修复方式不是给领域模型加 `json:"-"`（那样任何新调用点都会重新踩坑），
而是在 `adminapp` 引入 `AppView` **白名单投影**：新增内部字段默认不外发，
要外发必须显式加一行。`Create/Update/Get/List` 四个出口全部改为返回视图。
前端 `web/src/lib/types.ts` 同步删除该字段。

回归保护：`adminapp/service_test.go` 用 JSON 层面断言"响应里不得出现
`AppSecretHash` / `app_secret_hash`"，验收脚本 step 5 也加了同样的断言。

### 12.7 测试

- `adminaudit`：11 例（非法 result / 时间格式 / 时间倒置 / 过滤透传 /
  提交状态与 task_id 长度 / 他人任务伪装 404 / 本人可读 / super_admin 可见 /
  领域错误归一化 / 未完成拒下载 / 过期拒下载 / 路径穿越收敛 / 列表）
- `auditexport`：6 例（BOM + 表头 + 行数 + detail / 失败回写并删文件 /
  同名拒绝覆盖 / 队列连续消费 / 无目录立即退出 / 过期清理）
- `adminapp`：2 例（视图不含 AppSecretHash / nil 安全）
- 验收脚本新增 step 15.6 共 7 条断言，含"匿名下载 401"

### 12.8 尚未闭环

1. 导出只有 CSV，没有 XLSX / JSON 格式选项。
2. 导出文件存在本地磁盘，多副本部署时下载请求可能落到没有该文件的实例。
   当前单副本无影响；拆多副本需要把 FilePath 换成对象存储 key
   （`audit.ExportStore` 已把"落盘"隔离在 worker 里，改动面可控）。
3. 前端还没有审计查询与导出页面（后端接口已就绪）。

---

## 13. 第三期（上）：账号合并链路 + 管理端 D 组

### 13.1 这一步解决什么

一期在 `bindConflict` 里留了一个明确的占位：

```go
// ⚠️ 当前状态：三种 merge mode 的合并链路属于第三期交付。
// 第一期在此统一返回 BIND.IDENTITY_TAKEN
```

也就是说 R1（"同一用户在同一业务应用内只有一个账号"）此前是**功能缺失**，
不是"实现得不够好"。本次把它补齐，并顺带补上出问题时的兜底手段（D 组）。

### 13.2 三次独立事务（修正 P0-3）

```
第 0 步  前置校验（只读）
        · mode=manual → 拒绝；mode=confirm → 要求验证；mode=auto → 放行
        · 取分布式锁 lock:merge:{appID}:{targetUserID}

第 1 步  事务 A：INSERT merge_operations(status=pending) 并 COMMIT
        · 幂等键确定性生成：merge:{trigger}:{appID}:{target}:{source}
        · ON CONFLICT DO NOTHING + 回查：并发重复请求命中同一行

第 2 步  无事务：AccountProvider.Merge（带幂等键）

第 3 步  事务 B：改挂绑定 + 撤销 source 令牌 + 置 done + 写 outbox + 写审计
```

**为什么第 1 步必须先提交**：如果 pending 记录与远端调用在同一事务里，
远端成功后事务回滚 → 本地没有记录 → 补偿任务扫不到 → 远端已合并、本地
仍是两个账号，**永久孤儿且不可逆**。

**为什么不用仓储组合替代事务 B**：`BindingRepository` / `SessionRepository` /
`EventRepository` 各自持有独立的 `*gorm.DB`，每次调用都在自己的连接上自动提交。
在它们外面包一层 `db.Transaction` 只是幻觉——事务是连接级的。
所以本地收敛落在 `postgres.MergeConverger` 里，用同一个 tx 操作四张表。

### 13.3 R4 三条红线的落点

| 红线 | 落点 |
| --- | --- |
| 1 · 归并依据必须是已验证凭证 | `identity.IsTrustedSource` 白名单，login 链路的 claim 归并路径使用（本批未接入，见 13.6） |
| 2 · 被合并账号必须收到通知 | 事件体 `notify_source_account` 恒为 `true`，且不读配置——单测 `TestAutoMergeConvergesWithEvent` 守住 |
| 3 · 跨平台自动合并需额外评估 | bind 路径天然同平台（同一 identity），跨平台判定属于 login 的 claim 归并路径 |

### 13.4 幂等与补偿

- `merge_operations.idempotency_key` 唯一约束 + 确定性生成 ⇒ 重复触发不会新开记录
- 补偿器每 30s 扫 `pending` / `failed`（`attempts < 3`），调 `Resume` 重放第 2~3 步
- **非幂等的远端不自动重试**：`merge.remote_idempotent=false` 时失败直接标 `dead`，
  等人工推进。非幂等的 Merge 重复执行会重复迁移订单/资产，代价远高于"合并没做完"
- `Resume` **不做前置校验**：操作在初次执行时已校验过；补偿时若配置被改成 manual
  就停手，会让"已经调过远端的合并"永远停在半路

### 13.5 管理端 D 组

| 方法 | 路径 | 权限 |
| --- | --- | --- |
| GET | `/admin/v1/merge-operations` | `merge:read` |
| GET | `/admin/v1/merge-operations/{id}` | `merge:read` |
| GET | `/admin/v1/merge-operations/{id}/impact` | `merge:read` |
| POST | `/admin/v1/merge-operations/{id}/retry` | `merge:retry` |
| POST | `/admin/v1/merge-operations/{id}/resolve` | `merge:retry` |

- `retry` 复用原幂等键（§15.4 明确要求），否则用户中心会当成新合并
- `resolve` 置 **dead 而不是 done**：done 会被下游当成"合并成功"，那是谎报
- `impact` 给出"将改绑 N 条绑定 / 撤销 M 个令牌 / 涉及哪些平台"，供二次确认

### 13.6 顺带修掉的权限缺陷

`admin.Permissions` 里 `RoleOperator` 与 `RoleConfigAdmin` 此前是**空 map**。
`Has()` 不做角色继承（刻意的显式列举），于是 operator 登录后连
`GET /admin/v1/apps` 都是 403——一个"看不到任何东西"的角色。
本次按 §15.3 的矩阵补齐：operator = viewer 读权限 + `binding:write` /
`token:revoke` / `merge:retry`；config_admin = viewer 读权限 + `app:write` /
`config:write` / `key:write` / `event:write`。

### 13.7 测试

- `application/merge`：11 例（自合并拒绝 / manual 拒绝 / confirm 要求验证 /
  成功收敛含事件与审计 / 幂等命中 / 锁冲突 / 远端失败 / 非幂等转 dead /
  收敛失败 / 补偿跳过 / 补偿重放 / 幂等键确定性）
- `application/authflow`：6 例（auto 合并签发 / confirm 返回 MERGE_REQUIRED /
  manual 返回 IDENTITY_TAKEN / 缺依赖拒绝 / 合并失败透出错误 / 内部拒绝映射）
- `application/adminmerge`：10 例
- `test/acceptance`：2 个真实依赖用例
  - `TestAccountMergeConvergesLocally`：改挂 → 令牌撤销 → outbox 事件 →
    op=done → 重复请求只有一条记录
  - `TestMergeImpactReportsCounts`：影响面数字

集成测试需要从宿主机连库，compose 已把 pg 暴露到 `127.0.0.1:15432`：

```bash
TEST_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:15432/social_login?sslmode=disable" \
TEST_REDIS_ADDR="127.0.0.1:16379" go test ./test/acceptance/ -run Merge -v
```

### 13.8 管理端 C 组（身份与绑定）

| 方法 | 路径 | 权限 |
| --- | --- | --- |
| GET | `/admin/v1/identities` | `identity:read` |
| GET | `/admin/v1/identities/{id}?app_id=` | `identity:read` |
| GET | `/admin/v1/bindings` | `binding:read` |
| GET | `/admin/v1/accounts/{externalUserId}/bindings` | `binding:read` |
| DELETE | `/admin/v1/bindings/{id}` | `binding:write` |
| POST | `/admin/v1/bindings/{id}/transfer` | `binding:transfer` |

实现要点：

- **按 `external_user_id` 查身份走 `EXISTS` 子查询而不是 JOIN**：一个账号可有
  多个身份，JOIN 会产生重复行，让 `total` 与列表长度对不上。
- **claim 只返回哈希前 8 位**：库里只有哈希与信封加密密文（§8.5），
  回显明文等于给"管理端账号被盗"额外送一批手机号。
- **强制解绑与 transfer 都在仓储内用事务**，同一事务写 outbox 事件
  （`binding.removed`）。业务方靠事件同步自己的 user 表；只管本地改而不发事件，
  两边会长期不一致且无迹可寻。
- **transfer 只动一条绑定**，不迁移账号数据、不撤销令牌——原账号仍可正常登录，
  只是少了这个登录方式。这是它与 merge 的本质差别（§7.2 的旁路）。
- **路径里只有 binding id** 时，仓储用显式跨应用作用域先读出真实 `app_id`，
  再据此写入事件与审计——不由调用方"猜"应用归属（C1 要求显式声明）。
- **重复解绑幂等**：已 unbound 的再解一次返回成功但不产生新事件，
  避免客服重复点击产生一串重复通知。

### 13.9 confirm 模式的验证流程（短信）

在这之前，`confirm`（默认模式）遇到绑定冲突只返回 `BIND.MERGE_REQUIRED`，
用户走到这一步就没有下一步了——**默认配置的应用实际不可用**。本节补齐。

#### 端点

```
POST /v1/bind/resolve        （app 凭据；Bearer 优先，其次 body 断言账号）

{"merge_ticket":"mtk_...","action":"send_code"}
  → 200 {"phone_masked":"138****00","expires_at":"...","resend_after_seconds":60}

{"merge_ticket":"mtk_...","action":"verify","code":"123456"}
  → 200 {"merged_into":"<target>","operation_id":12,"already":false}
```

#### 为什么是两段式

发码与验码刻意不合并成一个接口：发码有外部副作用（短信费用、手机响），
必须能单独限流；验码必须能单独拒绝猜想。合成一个"提交即发码+验码"会让
重试语义失控——用户点两次就是两条短信、两条码都有效。

#### 票据（`ticket.MergeTicket`，5 分钟）

| 字段 | 为什么必须在票据里 |
| --- | --- |
| target / source / identity | 前端不得重传：否则可以把"合并 A→B"改成"合并任意账号→我" |
| verification | 前端据此决定走短信还是其他方式，不该硬编码 |
| 不含验证码 | 票据泄露 ≠ 可以完成验证；码只存哈希在另一处 |

与 `bind_ticket` 分开：后者的语义是"把这个 identity 绑到我账号"，
校验条件与生命周期都不同，混用会让它的防抢绑保证失效。

#### 验证码的安全参数

| 参数 | 取值 | 理由 |
| --- | --- | --- |
| 长度 | 6 位数字 | **必须左补零**（`000123` 也是合法码，截断会缩小猜测空间） |
| 存储 | `sha256(ticketID + ":" + code)` | 6 位只有 100 万种可能，不加盐等于给 Redis 快照配一张反查表 |
| 尝试上限 | 5 次 | 成功率 5e-6；再多一个数量级就够脚本刷开 |
| 重发间隔 | 60s | 防短信轰炸（成本与投诉），也让"换条短信再猜"慢到不划算 |
| 有效期 | 5 分钟 | 与票据同步：票据没了码也不该活着 |
| 递增原子性 | Lua 脚本 + 保留 PTTL | 并发提交不能把 attempts 卡在 1；改写时保留原 PTTL，避免猜错一次就续期 |

#### 失败时的处置

| 场景 | 行为 |
| --- | --- |
| 码错（未到上限） | 返回剩余次数，票据保留 |
| 码错到上限 | **挑战 + 票据一起作废**，用户需从绑定冲突重新开始 |
| 未发码就验码 | `REQUEST.INVALID` |
| 票据过期/伪造 | `BIND.TICKET_INVALID` |
| 调用者 ≠ 票据 target | 403（票据属于别人，不能替他合并） |
| source 在用户中心没有手机号 | `BIND.MERGE_REQUIRED` + `hint: existing_binding` |

#### 短信通道

`sms.provider`：`log`（只写日志，仅开发）/ `none`（未配置，发码直接报错）。

**release 模式下 `log` / `none` 会让进程启动失败** —— 用户收不到码而接口
返回 200，这种"看起来正常、实际不可用"的状态最难排查。

#### 仍未做

- **`existing_binding` 验证方式**：用 source 账号上的另一个已绑定渠道
  完成一次授权来证明控制权。它需要给 `/v1/authorize` 增加一个"验证用途"的
  模式，侵入核心链路，单独排期。当前 source 无手机号时返回
  `hint: existing_binding`，前端可提示改用其他登录方式。
- **`strict`**：服务端行为与 `sms` 相同，区别是前端多一步二次确认弹窗。

### 13.10 尚未交付

1. **`existing_binding` 验证方式**：短信验证已完成（§13.9），
   用"已绑定渠道再授权一次"证明控制权的方式未做。
2. **login 链路的 claim 归并**（`on_login=claim_verified` / `detect_only`）：
   `finishLogin` 目前只做 detect_only 的提示，`claim_verified` 的写数据路径未接。
3. **J 组**（claim 一致性与 mismatch 排查）：未做。C 组已在 §13.8 交付。
4. **HTTPAccountProvider**：`account.provider=http` 仍显式报错，等用户中心联调。
5. **管理端前端**：D 组接口已就绪，页面未做。

---

## 14. 第四期（上）：会话与令牌（E 组）+ jti 撤销名单（修正 P0-5）

### 14.1 这一步补的是什么

此前 `Introspect` 对 `check_revocation=true` 的回应是：

```go
return nil, errs.New(errs.CodeProviderNotSupported,
    "check_revocation 尚未实现（第四期），当前仅支持本地验签")
```

也就是**安全敏感操作（改密、提现、绑定新渠道）拿不到强校验**，
只能接受 15 分钟的撤销窗口。这既是 P0-5 的欠项，也让 E 组的
"强制下线"无法兑现承诺。

### 14.2 分层撤销的落地（§8.4）

| 场景 | 处理 | 生效延迟 |
| --- | --- | --- |
| 普通登出 | 撤销该设备 refresh_token | ≤ 15 min |
| 管理员强制下线 | 撤销全部 refresh_token **+ 写账号撤销水位** | 强校验下立即 |
| 已知 jti 的精确撤销 | 写 jti 黑名单（TTL = 令牌剩余有效期） | 强校验下立即 |

**为什么账号级用"水位"而不是枚举 jti**：管理员强制下线时根本不知道
有哪些 access_token 在飞（它们是本地签发的 JWT，服务端不存）。
水位 = "该账号在 T 之前签发的令牌全部失效"，一条 Redis 键就够，
且 TTL 只需覆盖一个 access_token 生命周期——过了这个时间旧令牌自然过期。

键：
```
oauth:revoked_jti:{jti}            = "1"        TTL = 令牌剩余有效期
oauth:revoked_user:{appID}:{user}  = unixNano   TTL = access TTL + 1min
```

### 14.3 端点（§15.4 E 组）

| 方法 | 路径 | 权限 |
| --- | --- | --- |
| GET | `/admin/v1/tokens` | `token:read` |
| POST | `/admin/v1/tokens/revoke` | `token:revoke` |
| GET | `/admin/v1/revoked-jti` | `token:read` |

实现要点：

- **会话列表不返回 `token_hash`**：它是"持有即可换令牌"的凭据哈希，
  管理端只需要定位会话（id / 设备 / 时间）。
- **`active` 是三态**（`""` / `true` / `false`）：用 bool 的话
  "查全部"与"查已撤销"无法区分，而排查客诉恰恰要能只看已失效的会话。
- **`app_id` 强制必填**：会话按应用隔离（C1），不指定可能把用户
  在别的应用里的会话一起踢掉。
- **返回 `effective_window_seconds`**：未开启强校验的调用方仍可能接受
  旧令牌的剩余时间。运营对用户说"已下线"时需要知道这句话的准确含义。
- **撤销名单未装配时直接失败**，不做半套——半套会让运营以为下线成功。

### 14.4 边界语义

`session.Revoked` 把两处判定收敛成一个函数（jti 命中 / 水位比对），
避免"introspect 说有效、网关说无效"这类分叉：

- 水位使用 `!issuedAt.After(at)`：**撤销与签发同毫秒时归入撤销一侧**，
  宁可多踢一个，不要漏一个。
- 查询失败**上抛错误**而不是返回 false：调用方明确要求强校验，
  一次 Redis 抖动不该变成安全缺口。
- 撤销名单为 nil 时返回 false（不声称已撤销）：如果"安全默认"返回 true，
  一次装配遗漏就会让所有强校验请求被判无效——全站不可用。

### 14.5 测试

- `domain/session`：4 例（nil 保守 / jti 命中 / 水位边界 / 错误上抛）
- `application/adminsession`：9 例
- 集成测试（真 DB + 真 Redis）：`TestForceOfflineInvalidatesAccessToken`
  - 下线前强校验 active=true
  - 下线后强校验 **active=false**
  - 默认模式**仍为 active**（≤15 分钟窗口，这是设计权衡而非 bug）
  - refresh_token 全部撤销
  - 撤销水位可查
- 验收脚本新增 15.9 共 8 条断言，17 步全过

### 14.6 尚未交付（第四期剩余）

1. **F 组**（签名密钥管理：`rotate` / `retire`，§8.3 四步）
2. **K 组**（管理员授权：`admin_grants` 表已建，当前仍按 `admin_users.role` 单角色）
3. **限流**（入站限流中间件整体未做，含 provider 维度配额）
4. **KMS 信封加密升级**（当前单 KEK 本地主密钥）
5. **账号注销与数据合规**（含 `Unbind` 不支持的降级提示）
6. **双人复核流程**

---

## 15. 第四期（中）：入站限流

### 15.1 三档维度里的两档

架构 §6.3 列了四档（app+IP / identity / platform 日配额 / global）。
本批落地两档，另两档暂缓，理由都在代码注释里写清了：

| 维度 | 状态 | 说明 |
| --- | --- | --- |
| `rl:notify:{platform}:ip:{ip}` | ✅ | 平台通知入口无鉴权、公网可达，是被刷的首选目标 |
| `rl:app:{appID}:ip:{ip}` | ✅ | 业务端，挂在 `AppAuth` 之后才拿得到 app_id |
| `rl:global:{route}:ip` | ⏸ 不挂 | 按路由计数而 `/admin/assets` 一次页面加载就是几十个请求，3000/min 很易误伤 |
| `rl:identity:{identityID}` | ⏸ 未做 | 需要 identity 上下文，属于授权流程内部 |
| `rl:platform:{platform}:day` | ⏸ 未做 | 依赖渠道配额元数据（`Metadata` 里还没有日配额字段） |

### 15.2 为什么用固定窗口

目标是"挡量级"而不是精确整形。一次 `INCR` 就能判定，成本最低；
代价是窗口边界的突刺（两个窗口交界处可能瞬时双倍），对防刷完全够用。
令牌桶能整形，但需要多几个 Redis 往返，在这个场景不划算。

窗口号写进 key（`...:{unix/60}`）而不是只靠 TTL：
只靠 TTL 时"第一个请求决定窗口对齐"，两个请求可能落在同一 key
但属于不同实际窗口，计数被摊薄。

### 15.3 三个边界决定了它安不安全

1. **Redis 故障时 fail-open**。限流是保护措施，不是正确性前提。
   一次 Redis 抖动让全站 429，可用性损失远大于"这段时间没限流"。
2. **阈值 0 = 该维度不限制**，而不是"全部拒绝"。配置漏填把全部请求
   拒掉，比不限制危险得多。
3. **429 带 `Retry-After`**（距窗口结束的秒数，不是固定 60）。
   不带它客户端会立即重试，限流本身变成流量放大器。

### 15.4 默认关闭

`ratelimit.enabled: false`。阈值与业务量强相关，猜一个值上线**比不限制更危险**：
阈值偏低时正常用户成片收到 429，而运维的第一反应往往是"服务坏了"。
打开前必须按实际 QPS 校准。

### 15.5 测试

`middleware/ratelimit_test.go`：6 例
- 未启用放行 / 超限返回 429（含 Retry-After 与 `RATE.LIMITED`）
- Redis 故障 fail-open / TTL 只设一次 / 阈值 0 跳过 / Retry-After 落在窗口内

「Redis 故障 fail-open」这条专门抽了 `Counter` 接口来造：
拿着真 Redis 很难把"Redis 挂了"这个分支稳定复现。

### 15.6 尚未交付

- `rl:identity`：需要 identity 上下文，接在授权流程内部（防止撞库与暴力绑定）
- `rl:platform:{platform}:day`：需要 `Provider.Metadata` 增加日配额字段
- 管理端按应用调整阈值（当前是服务级配置，与 `provider_guard` 同级）

---

## 16. 第四期（下）：签名密钥轮换（F 组）

### 16.1 把四步轮换变成两个按钮

§8.3 的轮换顺序是硬约束：

```
① 生成新密钥并开始签名
② JWKS 同时发布新旧两把公钥
③ 等旧 token 全部过期（> access TTL）
④ 从 JWKS 移除旧密钥
```

顺序颠倒的后果很具体：提前下线旧密钥 = 所有用它签的 token **立刻验签失败**，
业务方那边表现为"刚才还能用的令牌突然无效了"，而本服务一切正常。

因此实现上把 ① ② 合成 `rotate`，把 ③ ④ 合成 `retire`，并让 `retire`
**在服务端强制执行 ③**——不是靠运维记得等 15 分钟。

| 方法 | 路径 | 权限 |
| --- | --- | --- |
| GET | `/admin/v1/signing-keys` | `key:read` |
| GET | `/admin/v1/signing-keys/jwks-preview` | `key:read` |
| POST | `/admin/v1/signing-keys/rotate` | `key:write` |
| POST | `/admin/v1/signing-keys/{kid}/retire` | `key:write` |

### 16.2 retire 的前置校验

判据不是 `created_at` 而是 **`demoted_at`（停止签名的时刻）**：

一把已经 signing 了三个月的密钥，即使刚 rotate 出去，
也还有大量用它签发的 token 没过期——用 `created_at + TTL` 判断会直接放行，
那正是最危险的情况。

```
可下线时刻 = demoted_at + access_ttl + 1min 宽限
```

1 分钟宽限不是随手加的：JWT 的 `exp` 与服务端时钟存在毫秒级偏差，
恰好卡在边界上的 token 会因"服务端认为过期、验签方认为还没"而失败。

拒绝时返回 `retirable_at` 与 `wait_seconds`——运维能据此安排窗口，
而不是反复点按钮试。

### 16.3 密钥存哪（§8.3 的妥协与边界）

文档要求"私钥由 KMS / 配置中心托管"。**当前没有 KMS**，因此退化为
`security.key_dir` 下的状态文件（目录 0700 / 文件 0600），并在代码与配置里
明确标注"生产应换 KMS"。

为什么必须有持久化，而不能只改内存：只改内存时进程一重启就回到配置里那把
旧密钥——**轮换等于没做，而且 JWKS 会突然少一把公钥**，旧 token 全部验签失败。
所以：

- 未配置 `key_dir` 时 `rotate` / `retire` **明确拒绝**，不造"轮换成功"的假象
- 启动时**优先**从状态文件加载（高于 `jwt.signing_keys` 配置）
- 状态文件存在但读不出来时**不回退**到配置：那会让正在生效的密钥被无声替换

落盘内容：当前签名密钥存私钥（PKCS#8 PEM），**旧密钥只存公钥**（SPKI PEM）。
旧密钥已经不需要签名，继续持有私钥只会扩大泄漏面。

写入用"临时文件 + 原子 rename"：直接覆盖时若进程在写一半崩溃，
会留下无法解析的文件——那就意味着服务重启后无法签发令牌。

### 16.4 并发

`Signer` 原先的注释是"keys 在构造后只读，无需加锁"。轮换打破了这个前提，
因此三处读路径（Issue / Parse / JWKS / List）都加了读锁，
`Rotate` / `Retire` 持写锁。`Issue` 只在"取密钥"这一刻持读锁，
签名运算本身不占锁——否则轮换期间签发会排队。

### 16.5 实测（本地 compose）

```
rotate  → published_keys: 2，JWKS 返回 2 个 kid
retire  → 409，wait_seconds: 957，details.retirable_at 有值
list    → 旧密钥 status=published，带 demoted_at / retirable_at
重启   → 日志"签名密钥从状态文件加载（管理端轮换过）"，active 仍是新 kid
```

### 16.6 测试

- `jwtkit`：8 例
  - rotate 后旧 token 仍可验签（第 2 步的核心）
  - 不能下线当前签名密钥 / 不能提前下线（含 `retirable_at` 断言）
  - TTL 后可下线且旧 token 失效
  - 列表给出 `retirable_at`
  - 文件存储往返（重启后 active 正确、旧 token 仍可验签、旧密钥无私钥）
  - JWKS 不含私钥字段
- `adminkey`：8 例
  - 缺 reason / 未配置 store 拒绝 / 落盘失败不切换内存 / 提前 retire 拒绝

### 16.7 尚未交付

- **KMS 接入**：当前是单 KEK + 本地文件，`KeyStore` 已经是接口，
  换 KMS 只需要新实现
- **紧急轮换流程**（密钥泄漏）：需要"立即切换 + 撤销受影响 token"的组合动作，
  当前 `rotate` + `tokens/revoke` 可人工拼出，但没有一键入口
- **轮换周期提醒**：90 天建议值没有内置检查

---

## 17. 第四期：管理员授权（K 组）

### 17.1 与 `admin_users.role` 的关系：并存取并集

`admin_users.role` 只能表达"一个人一个角色"。现实里常见两种需求它表达不了：

- **临时提权**："这个人这个月临时加 operator 处理一批客诉"
- **按应用限定**："只允许他管这个应用"

`admin_grants` 用 `subject_id + role + scope_app_id + expires_at` 覆盖这两种。

**关键决定是"并存取并集"而不是"grants 取代 role"**：

```go
func (u *User) Can(perm string) bool {
    if u.Role.Has(perm) { return true }          // 基础角色
    for _, g := range u.Grants {                  // 附加授权
        if g.Effective(now) && g.Role.Has(perm) { return true }
    }
    return false
}
```

如果改成"只认 grants"，K 组上线瞬间所有现有管理员会全部失去权限——
因为 `admin_grants` 从一期就是空表。那是上线事故，不是设计。

### 17.2 端点

| 方法 | 路径 | 权限 |
| --- | --- | --- |
| GET | `/admin/v1/admin-grants` | `admin:grant` |
| POST | `/admin/v1/admin-grants` | `admin:grant` |
| DELETE | `/admin/v1/admin-grants/{id}` | `admin:grant` |

`admin:grant` 只有 `super_admin` 拥有（`Role.Has` 对它恒真）。这条边界很重要：
**能改"谁能进管理端"的人必须是最小集合**——`test/domain/admin` 里
`TestViewerCannotGrant` 专门守住它（含 operator / config_admin）。

### 17.3 几个实现细节

- **grants 在仓储层加载**（`FindByID` / `FindByUsername` 后调 `attachGrants`），
  而不是让中间件再查一次：中间件在每一个管理端请求的热路径上，
  而这两个方法有多个调用点（登录、鉴权、管理端查询），漏掉任何一处
  都会让权限判定不一致。
- **受授主体必须存在**：不校验会建出"授予了一个不存在的人"的记录——
  列表里看得见、永远不生效，排查时会被当成"授权没起作用"。
- **`subject_id` 形如 `admin:<id>`**：与 `admin_audit_logs.subject_id` 同一套命名，
  便于把"谁被授权"与"谁做了什么"直接对上。将来切 SSO 时换成 IdP 的 sub，
  校验逻辑改成"在 IdP 中存在"，接口不变。
- **`expires_at` 必须是未来**：过去的到期时间等于"授予即失效"，几乎必然是填错。
- **`ScopeAppID` 当前被鉴权层忽略**：现有 52 个管理端接口没有"按应用"的权限边界。
  真正的按应用隔离需要中间件拿到目标 `app_id`（路径参数或请求体），
  那是一次跨所有端点的改动。字段先留着，语义写在 `Grant` 的注释里。

### 17.4 实测（本地 compose）

把 admin 的 `role` 临时改成 `viewer`，再逐项验证：

```
viewer            → GET /tokens      200（token:read 有）
viewer            → POST /tokens/revoke 403（token:revoke 无）
viewer            → GET /admin-grants  403（admin:grant 无）
+ grant operator  → POST /tokens/revoke 200   ← grants 生效
                    GET /admin-grants   403   ← 没有溢出
撤销 grant        → POST /tokens/revoke 403   ← 立即回到基线
```

最后一行值得注意：**撤 grant 不需要重新登录**——鉴权中间件每请求都从库读
`User` 与 `Grants`，所以权限变更是即时生效的。

### 17.5 测试

- `domain/admin`：7 例（并集判定 / 过期与撤销 / super_admin 恒真 /
  viewer/operator/config_admin 都拿不到 admin:grant / nil 安全 / Effective 三态 / SubjectOf）
- `application/admingrant`：11 例（reason / 未知角色 / subject 格式 / 账号不存在 /
  过去的 expires_at / granted_by / 撤销 404 归一化 / 过滤透传 / 仓储错误透出）
- 验收脚本新增 15.97 共 8 条断言，17 步全过

### 17.6 尚未交付

- **管理员账号管理**（创建 / 停用 / 改密）：当前靠 `cmd/adminseed` 引导，
  管理端没有入口。K 组只解决"授权"，不解决"开户"。
- **按应用限定的鉴权**（`ScopeAppID` 生效）：需要中间件拿到目标 app_id。
- **双人复核**（`admin_approvals`）：表未建，高危操作的审批流未做。

---

## 18. 管理端前端：补齐 C/D/E/F/H/K 六组页面

### 18.1 为什么先做这一步

此前前端只有 A（应用）/ B（渠道）/ I（观测）三个页面，而刚交付的六个组
只有接口——**这意味着合并运维、强制下线、密钥轮换、审计导出、授权管理
在实际运维中都点不到**。接口做完了却用不起来，等于没做完。

### 18.2 新增页面

| 页面 | 路由 | 对应组 | 主要动作 |
| --- | --- | --- | --- |
| 身份与绑定 | `/identities` | C | 多维查询、详情（claims + 绑定历史）、强制解绑、transfer |
| 会话与令牌 | `/sessions` | E | 按账号查会话、强制下线、查撤销水位 |
| 合并运维 | `/merges` | D | 列表、影响面预估、重试、人工收尾 |
| 审计日志 | `/audit` | H | 业务/管理端审计查询、异步导出、任务轮询、下载 |
| 签名密钥 | `/signing-keys` | F | 列表、rotate、retire、JWKS 预览 |
| 管理员授权 | `/admin-grants` | K | 列表、授予（临时授权）、撤销 |

新增两个通用件：
- `components/FormDialog.tsx` — 通用表单对话框（业务字段 + reason）
- `lib/utils.ts` 的 `fmtTime` / `fmtBytes` — 列表时间与文件大小格式化

### 18.3 几个前端决定

**导出下载用 `fetch` + `blob`，不用 `<a href>`**
下载走鉴权接口，直链没有 `Authorization` 头会 401。审计含 openid / IP / UA，
不能做成公开直链——这一点后端已经做了，前端必须配合。

**导出任务自动轮询**
有 `pending` / `running` 任务时每 2 秒拉一次，而不是给用户一个"手动刷新"按钮。
异步导出本来就是不想让人盯着看，再要求手动刷新是矛盾的。

**`retire` 失败时原样展示后端 details**
后端在"旧 token 未过期"时返回 `retirable_at` 与 `wait_seconds`。
前端如果只显示"操作失败"，运维就只能反复点。这里把 `wait_seconds`
换算成人话展示。

**强制下线后展示生效窗口**
接口返回 `effective_window_seconds`，页面明确写"未开启强校验的调用方最长仍有
N 分钟窗口"。运营对用户说"已下线"时得知道这句话的准确含义。

**授权页把"只做加法"写在最显眼处**
grants 与 `admin_users.role` 取并集，撤销立即生效（无需对方重新登录）。
这两条如果不在界面上说明，会被误认为"给某人降权"。

### 18.4 顺带修掉的验收脚本缺陷

F 组步骤原本这样取"当前签名密钥"：

```bash
ACTIVE_KID=$(echo "$KEYS" | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p' | head -1)
```

它取的是**列表第一条**。密钥列表按创建顺序返回，在只有一把密钥时侥幸正确；
一旦执行过 rotate，第一条就变成"仅发布"的旧密钥，对它的 retire 是合法的
（返回 200），脚本却断言 409——于是本地演练过一次轮换后，验收就红了。

改成按 `status=signing` 精确定位：

```bash
grep -o '"kid":"[^"]*","algorithm":"[^"]*","status":"signing"'
```

这类"依赖顺序的测试"在状态发生变化时才暴露，正好被这次真实轮换抓到。

### 18.5 验证

- `npm run build`（`tsc -b` 全量类型检查 + vite 打包）通过
- `npm test` 8 例通过
- 容器重建后 `/admin` 与 assets 正常，bundle 内含新页面路由
- 逐项核对前端依赖的响应结构（identity 详情 / merge impact / 审计 / 导出任务），
  字段名与类型全部对齐
- 后端验收脚本 17 步、61 条断言全过

### 18.6 尚未做

- J 组页面（claim 一致性）与 G 组事件死信的**前端**（接口已有）
- 应用详情页里还没有"该应用的合并策略"可视化（策略在 A 组的 policy 编辑器里）
- 分页只有上一页/下一页，没有页码跳转（审计量级上来后会需要）

---

## 19. 导航归纳与权限感知

### 19.1 之前分组的问题

上一批页面是"按接口分组倒推"的，上线后有三处说不过去：

| 问题 | 为什么不对 |
| --- | --- |
| 「观测看板」在「渠道配置」下 | 它看的是全局健康度与汇总指标，不是"配置某个渠道" |
| 「新建应用」占一个导航位 | 它是列表页里的动作，不是独立页面。点进去后"返回"没有落点 |
| 「审计日志」与「签名密钥 / 管理员授权」并列 | 一个是查询、两个是配置，性质不同 |

另外**没有任何权限感知**：viewer 也能看到"管理员授权"，点进去吃 403。

### 19.2 现在的分组（按使用场景，不按接口编号）

```
接入配置     应用列表、渠道配置
             ↑ 上线前做一次，之后很少动

账号运营     身份与绑定、会话与令牌、合并运维
             ↑ 日常高频：查身份、踢会话、推进卡住的合并

运行与审计   观测看板、审计日志
             ↑ 出问题时去的地方

系统设置     签名密钥、管理员授权
             ↑ 低频高危
```

「新建应用」从导航移除——`AppsPage` 右上角本来就有按钮，路由 `/apps/new` 保留。

### 19.3 权限感知：菜单级 + 按钮级

**菜单级**：`/admin-grants` 标记 `roles: ['super_admin']`，其他角色看不到入口。

**按钮级**：`/auth/me` 现在多返回一个 `permissions`（有效权限集），前端据此
禁用按钮并给出 `title` 提示：

| 页面 | 按钮 | 需要的权限 |
| --- | --- | --- |
| 签名密钥 | 轮换 / 下线 | `key:write` |
| 会话与令牌 | 强制下线 | `token:revoke` |
| 身份与绑定 | 强制解绑 / 转移 | `binding:write` / `binding:transfer` |
| 合并运维 | 重试 / 人工收尾 | `merge:retry` |
| 管理员授权 | 授予 / 撤销 | `admin:grant` |

**为什么权限集从后端拿，而不是前端内置一份 role→perm 表**：
两份表必然漂移。后端加了一个权限、忘了改前端，按钮就一直灰着，
而没人会想到是前端的问题。所以 `permissions` 由 `admin.User.Permissions()`
计算后下发（基础角色 ∪ 生效 grants，super_admin 为 `["*"]`）。

`can()` 在 me 还没加载完时返回 `true`（乐观）：先让按钮可点，点了后端会拦。
反过来（默认禁用）会让首屏闪一下"全部不可用"，体验更差。

### 19.4 顺带

- 左下角显示当前账号与角色（`超级管理员` / `配置管理员` / `运营` / `只读`）。
  权限异常时第一件事就是确认"我是谁"，不该让人去翻 localStorage。
- 底部版本号原本写死"v0.1 · 第一期"——已经到第四期了，换成了功能描述。

### 19.5 验证

```
super_admin → permissions: ["*"]
viewer      → ["app:read","audit:read","binding:read","config:read",
               "event:read","identity:read","key:read","merge:read","token:read"]
```

- `domain/admin` 单测 +4 例（通配 / 含 grants / 过期排除 / nil 安全）
- `npm run build`（tsc 全量类型检查）与 `npm test` 通过

---

## 20. G 组页面：事件投递与死信

### 20.1 先说名字：这一页为什么不叫「死信」

进去看这一页的不只后端——还有客服、测试、运营。对他们来说
"outbox / dead letter" 是两个不知道要不要在意的词。所以：

- **导航与标题**用「事件投递」（描述它是什么），不用「事件死信」（描述失败态）
- **死信**作为五种状态之一出现，并且每一处都带一句人话解释
- 页面顶部把完整链路讲一遍，而不是假设读者知道消息队列

这不是"降低技术含量"，是让**判断动作**变得可能：一个人只有理解了
"停在 dead 意味着业务方永久收不到通知"，才知道该不该点重投。

### 20.2 页面讲的那四步

```
① 产生  用户登录成功，本服务要把"这个用户是谁、从哪个渠道来"告诉业务系统
② 排队  不当场调业务方接口（它发版/超时不该让用户登录失败），
        先写入待投递表，后台循环去送
③ 重试  失败自动重试 5 次：1s / 10s / 1min / 10min / 1h
④ 死信  5 次全失败，或对方明确拒收（4xx）→ 停止重试，等人来看
```

第 ④ 步的关键补充是**为什么要有人管**：失败是静默的。登录本身成功了，
用户拿到令牌能进 App，但业务方表里没有这个人——本服务一切正常，
用户也感知不到错误。这句话比任何术语都更能解释这一页的存在理由。

### 20.3 状态字典

| 状态 | 页面标签 | 要不要处理 |
| --- | --- | --- |
| `pending` | 待投递 | 不用，几分钟内会走完 |
| `sent` | 已送达 | 不用 |
| `dead` | 死信 | **要**：重投或丢弃 |
| `skipped` | 已跳过 | 应用没配 `webhook_url`，配好后重投 |
| `discarded` | 已丢弃 | 不用，理由已进审计 |

`skipped` 单列一档是刻意的：它**不是故障**。早期如果把它和 dead 混在一起，
运维会把"应用根本没配 webhook"当成"投递坏了"，去查对方接口。

### 20.4 三档计数条

`待投递 / 死信 / 已跳过` 三个可点击的数字，点击即切换筛选。

为什么要有它：列表默认只筛 `dead`，如果只有列表，"死信 0 条"与
"根本没有事件产生"看起来完全一样。计数条让这两种情况分开。

### 20.5 两个动作的文案边界

**重投**：理由选填（`FormDialog` 新增 `reasonOptional`）。重投本身是常规
运维动作，强制填理由只会让人写"重投"两个字。但填了会进审计——
事后能回答"这条是谁捞出来的、当时怎么判断的"。

页面上明确写了两条：`event_id` 不变（业务方按它去重，不会重复处理）；
以及"重投前先确认对方已经修好，否则立刻又变死信"。

**丢弃**：理由必填。文案强调"丢弃不等于删除"，并且提示如果只是
"不想让它一直失败"，更好的做法是让对方修好配置后重投。

### 20.6 实现细节

- **列表不带 payload**：单条事件体可能很大，列表只用来定位；详情按需请求。
- **日期选择器换算成 RFC3339**：后端按 RFC3339 解析，直接传 `2026-10-21`
  会 400。前端换算成本地时区的 `T00:00:00` / `T23:59:59`。
- **重投白名单与后端一致**（`dead` / `skipped` / `discarded`）：按钮在
  `pending` 时不可点，避免"点了才 400"。
- **`event:write` 控制重投与丢弃**：viewer / operator 只能看。

### 20.7 验收

G 组此前没有任何验收覆盖（接口在二期就交付了，但一直没人跑）。本次补
`15.96`：列表、按状态筛选、非法 status → 400、不存在 → 404、
重投不存在 → 404、丢弃缺 reason → 400，共 6 条断言。

> 真实的 `dead` 不在冒烟脚本里造：需要给应用配一个坏地址并等满退避
> （最长约 1 小时），不适合每次验收都跑。重投保持 `event_id` 不变这一点
> 由 `application/adminevent` 的单测覆盖。

### 20.8 当前状态

- `npm run build`（`tsc -b` 全量类型检查）与 `npm test` 8 例通过
- `web/dist` 已同步进 `internal/embedweb/dist`，`go build ./...` 通过
- ⚠️ **容器未重建**：本次改动期间本机 Docker daemon 未运行
  （`npipe:////./pipe/docker_engine` 连接失败），因此没有实机跑过页面与验收脚本。
  启动 Docker Desktop 后执行 `docker compose up -d --build app` +
  `bash scripts/acceptance-admin.sh` 即可验证。

管理端前端至此覆盖 A/B/C/D/E/F/G/H/I/K —— **十组页面齐全**，只剩 J 组
（claim 一致性，属三期遗留）没有页面。

### 20.9 实机部署验证（2026-10-22）

镜像构建成功，容器启动，`/healthz` 200，G 组四个路由全部注册。验收脚本
在 15.96 处**抓到一个真实缺陷**：

```
FAIL: 不存在的事件期望 404，实际 500
```

#### 缺陷：事件不存在时返回 500

`postgres.EventRepository.Get` 正确返回了哨兵错误 `event.ErrNotFound`，
但 `adminevent.Service.Get` 直接把它透出去：

```go
e, err := s.deps.Events.Get(ctx, id)
if err != nil {
    return nil, err        // ← err 是普通 error，不是 *errs.Error
}
```

`httputil.Fail` 里 `errs.From(err)` 对普通 error 返回 nil，于是被归一化成
500。运维看到 500 会以为服务崩了，实际只是"这条事件不在了"——可能被清理
任务删了、或者前端拼错了 id。

修复是在用例层加 `load()` 统一翻译（基础设施层不该依赖 HTTP 语义）：

```go
func (s *Service) load(ctx context.Context, id int64) (*event.Event, error) {
    e, err := s.deps.Events.Get(ctx, id)
    if err != nil {
        if errors.Is(err, event.ErrNotFound) {
            return nil, errs.New(errs.CodeNotFound, "事件不存在").WithDetail("id", id)
        }
        return nil, err
    }
    return e, nil
}
```

`Get` / `Retry` / `Discard` 三个入口全走它——只修 `Get` 会让"点重投"
仍然 500。单测 `TestMissingEventIs404` 一次断言三个入口。

**为什么之前没发现**：G 组是唯一一组"接口二期就交付、但既没有验收脚本
断言、也没有覆盖 404 路径的单测"的模块。其它组（C/D/E/F/H/K）都有
`adminxxx.CodedNotFound` 的显式翻译，只有它漏了。这次补上验收覆盖才暴露。

#### 实测通过的链路（HTTP，真库）

```
GET  /admin/v1/events/outbox?status=dead     total=1，命中 evt_demo_dead_001
GET  /admin/v1/events/outbox/37              payload 完整返回
POST /admin/v1/events/outbox/37/retry        → pending, attempts=0, next_retry_at 已设
        （随后被 dispatcher 领取，应用未配 webhook → skipped，链路真实跑通）
POST /admin/v1/events/outbox/38/discard      → discarded
POST /admin/v1/events/outbox/38/discard(空)  → 400
POST /admin/v1/events/outbox/38/retry        → 200（discarded 允许捞回）
GET  /admin/v1/events/outbox?status=bogus    → 400
```

前端：`/admin` 200，bundle `index-DmDVo5Qz.js` 内含「事件投递」「死信」
「events/outbox」，与本地构建产物一致。

验收脚本在修复前跑到 15.96 停止，**此前 54 条断言全部通过**。

#### ⚠️ 未完成：镜像重建

修复提交后需要重建镜像才能让运行实例生效，但本次验证期间本机
Rancher Desktop 的 docker API 代理反复中断：

```
docker-proxy: error accepting client connection: bad file descriptor
failed to connect to the backend: timed out dialing Hyper-V socket
```

容器本身健康（HTTP 全通），只有 Windows 侧的 docker CLI 通道断了。
`rdctl shell` 也被执行沙箱拦在 `wsl.exe` 上，无法从虚拟机内操作。

VM 配置是 qemu / 2GB 内存 / 2 CPU —— 构建 Go + Node 时极易被压垮，
这可能是代理反复死锁的根因。**建议把内存调到 6GB** 后再重建：

```bash
docker compose up -d --build app
bash scripts/acceptance-admin.sh   # 预期 18 步 73 条断言全过
```
