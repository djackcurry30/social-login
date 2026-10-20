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
3. **H 组（审计查询）仍未实现**：数据在写，但没有查询入口。

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
