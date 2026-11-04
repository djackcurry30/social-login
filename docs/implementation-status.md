# 实现状态对照 · 设计规划 vs 当前代码

> 基线：`docs/architecture-design.md`（§5.3 业务端 API、§13 分期路线、§15.4 管理端 API）
> 代码：main + §23/§24（未提交）
> 核对时间：2026-10-29（第四期第 1 组交付后复核）
> 核对方式：逐条比对路由注册、包结构、表结构与依赖，不依据注释宣称

---

## 0. 一页结论

| 维度 | 规划 | 已实现 | 完成度 |
| --- | --- | --- | --- |
| 业务端 API（§5.3） | 14 | 15（含 `/.well-known/openid-configuration`） | **100%** |
| 渠道适配器（§4） | 4 平台 / 9 场景 | 4 平台 / 10 场景 | **100%**（代码；实渠道未联调） |
| 管理端 API（§15.4） | 53 端点 / 11 组 | 59 端点 / 11 组 | **100%**（多出 6 个辅助端点） |
| 管理端前端 | 11 组界面 | 11 组 / 14 页 | **100%** |
| 第一期 · 骨架与最小闭环 | 10 项 | 10 项 | **100%** |
| 第二期 · 真实渠道 | 7 项 | 7 项 | **100%**（代码） |
| 第三期 · 绑定与合并 | 12 项 | 7 项 + 3 项部分 + 2 项未做 | **约 71%**（按工作量 85%） |
| 第四期 · 生产化 | 21 项 | 8 项 | **约 38%**（按工作量 35%） |
| **合计** | **50 项** | **32 完成 / 3 部分 / 15 未做** | **约 64%**（部分项按半计 67%） |

**一句话**：前三期的**功能面**基本闭环（业务端 14 个接口、管理端 11 组 53 个端点、
11 组前端页面全部到位），剩下的缺口集中在**第四期生产化**——KMS、配置热更新、
账号注销合规、双人复核、管理员开户、两档限流、tracing 与告警规则、压测演练。
另有三处第三期「能配不生效」的遗留，见 §25。

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
| 账号注销与数据删除 | §10.2 | ✅ | `POST /v1/account/close`（§34） |
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
3. ~~**J 组**（claim 一致性与 mismatch 排查）~~：已于 §22 交付（`claim_mismatches` 表 + 3 个端点 + 前端页面）。
4. ~~**HTTPAccountProvider**~~：已于 §23 交付（`account.provider=http` 可用，
   契约见 `infrastructure/account/http.go` 文件头；实机联调待用户中心就绪）。
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

- ~~J 组页面（claim 一致性）与 G 组事件死信的**前端**~~：均已交付（G 组见 §19，J 组见 §22）
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
- ~~⚠️ **容器未重建**~~：已于 2026-10-23 重建镜像并实机验证（详见 §22.11），
  `acceptance-admin.sh` 17 步全过。当时 Docker daemon 未运行（`npipe:////./pipe/docker_engine`
  连接失败），所以本节改动在交付时只过了单测。

管理端前端至此覆盖 A/B/C/D/E/F/G/H/I/K —— 十组页面齐全（J 组随后在 §22 补齐，
现为十一组齐全）。

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

---

## 21. 三期遗留：login 链路的 claim 归并（R2 的 claim_verified）

### 21.1 之前是什么状态

`merge.on_login` 有三个取值，文档写得完整：

| 取值 | 本该的行为 |
| --- | --- |
| `off` | 只按 open_id 匹配已有绑定 |
| `detect_only` | 检测到同手机号已有账号时返回 `hint`，不动数据 |
| `claim_verified` | 按已验证凭证找既有账号，命中就归并过去 |

但代码里只有前两个：`detect_only` 设了个 hint，`claim_verified` **完全没有分支**。
配置成 `claim_verified` 的应用，行为与 `off` 一模一样，而且不会报任何错。

这是最坏的一类缺失：配置显示功能已开启，实际什么都没发生。用户抱怨
"同一个手机号怎么进了新账号"，从配置上根本看不出问题。

### 21.2 两轮结构：先解析，再执行

```
第一轮  逐条凭证只读解析：
         本地 claim → 归属身份 → 该身份的活跃绑定 → 回源用户中心核对
         收集"每条凭证指向哪个账号"
第二轮  全部指向同一账号 → 建绑定 + 审计 + 签发 auth_code
        指向不同账号     → 直接拒绝
```

**为什么不能"命中第一条就归并"**：用户一次授权可能同时带来手机号和邮箱。
如果手机号指向账号 A、邮箱指向账号 B，先遍历到哪条就替用户选哪个账号——
这是随机的。数据侧不一致只能交给人工，所以第一轮发现分歧就返回
`ACCOUNT.MULTIPLE_MATCH`（409）。

### 21.3 六道关卡，顺序有讲究

```go
1. FindVerified(hash)           // 只认 verified=true 且未撤销
2. claim.IdentityID == 当前身份  → 跳过（第二次登录，本来就该走主路径）
3. Identities.FindByID          // claim 指向的身份可能已被清理
4. 跨平台检查                     // R4 红线 3
5. Bindings.FindActiveByIdentity // 没有绑定就不是"已有账号"
6. Accounts.GetByClaim           // P0-6 回源核对
7. acc.Status == active          // 冻结/注销的账号不能当目标
```

前四步都是本地判断、零外部调用，把它们放在回源之前：用户中心是外部依赖，
能用本地条件否掉就不该白调一次。

**第 6 步是整个功能的安全核心**。`identity_claims` 记录的是"某次授权中平台
证明过这个值"，不是"账号现在仍然持有它"。用户换号、注销、或 claim 已漂移
时，只看本地表就会把新身份挂到错误的账号上。所以必须问用户中心：
"这个手机号现在属于谁？" 答案与本地绑定不一致就跳过并打 warn（那不是故障，
是需要人工排查的数据状态）。

### 21.4 归并的本质是建绑定，不是合并

这一点容易搞混，但实现上完全不同：

| | 账号合并（merge） | 登录期归并（claim_verified） |
| --- | --- | --- |
| 前提 | 两个身份**各自都已绑定**到不同账号 | 新身份**没有任何绑定** |
| 动作 | 改挂绑定 + 撤销令牌 + 迁移远端数据 | 建一条绑定 |
| 需要补偿吗 | 需要（跨服务、三次事务） | 不需要（单事务、幂等） |
| `bind_source` | `merge` | `merge`（同为自动归并，便于检索） |

因为只建一条绑定，这里不需要 `merge_operations`、不需要补偿器、也不动既有
账号的任何数据。`uk_bindings_active` 唯一索引兜底并发：`Activate` 返回
`alreadyExists=true` 时读回来看绑到了谁，一致才继续。

### 21.5 配置校验补了一道

`mode=auto` 分支此前只校验 `verification != none`，不校验 `on_login` 取值。
也就是说 `"on_login": "claim_verify"`（少一个字母）能保存成功，然后静默不生效。

现在加了白名单校验，错误响应里带 `valid` 列表。前端策略页也补了三个最容易
配错字段的说明——那段 JSON 编辑器没有任何提示，靠猜字段名不现实。

### 21.6 测试

`application/authflow/claimmerge_test.go`：11 例

| 用例 | 守住什么 |
| --- | --- |
| 主路径 | 建成绑定、`bind_source=merge`、签发 auth_code |
| 回源不一致 | 用户中心说手机号属于别人 → 不归并 |
| 账号不存在 | claim 还在、账号已注销 → 跳过 |
| 命中多个账号 | `ACCOUNT.MULTIPLE_MATCH`，不择一 |
| 跨平台默认关 | 微信 → 支付宝不归并（红线 3） |
| 跨平台显式开 | 打开开关后才归并 |
| Apple 中继邮箱 | 即使开了跨平台也必须拒绝 |
| 账号冻结 | 不能作为归并目标 |
| 凭证属于自己 | 第二次登录不产生归并 |
| 双凭证冲突 | 手机号与邮箱指向不同账号 → 拒绝且不写任何绑定 |

`domain/tenant` +2 例：`claim_verified` 可配、拼错被拒。

验收脚本新增 9.1（3 条断言）：`auto + claim_verified` 能保存、拼错的取值
返回 400、测完恢复基线配置。

### 21.7 仍未交付

1. **`existing_binding` 验证方式**：confirm 模式下用"source 账号上另一个
   已绑定渠道再授权一次"来证明控制权。需要给 `/v1/authorize` 增加验证用途的
   模式，会侵入核心授权链路，单独排期。
2. **J 组**（凭证一致性与 mismatch 排查）：`claim_mismatch` 记录的读写、
   人工撤销 claim。本节里"回源不一致"只打了 warn，运维没有查询入口。
3. **端到端集成测试**：本节的验证靠单测覆盖分支。真实回调链路需要 stub 渠道
   能返回指定 openid + 手机号，当前 stub 是固定值，造不出"新渠道同手机号"的
   场景。补这个要先扩展 stub。

---

## 22. J 组 · 凭证一致性运维（第三期收尾）

J 组是第三期最后一块，也是"合并功能上线前的兜底"（§15.6：合并是高风险操作，
没有管理端兜底就不能上线）。它解决的问题在前面的实现里其实已经埋下了伏笔：
21.3 的回源核对会在数据不一致时**拒绝归并**，但那时的处理只是打一行 warn。
用户侧看到的是"我明明同一个手机号，怎么又注册了一个号"，运维侧什么都没有。

### 22.1 交付清单

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/claims` | 凭证查询（app_id / claim_type / identity_id / status） | `identity:read` |
| GET | `/admin/v1/claims/mismatches` | 漂移记录，含 `open_total` 全量未闭环数 | `identity:read` |
| POST | `/admin/v1/claims/{id}/revoke` | 人工失效凭证（需 `reason`），顺带闭环漂移 | `identity:write` |

前端新增「账号运营 → 凭证一致性」页（`ClaimsPage.tsx`），两个视图：
默认「漂移待处理」（要干活的）、另一个「全部凭证」（要查证的）。
导航至此覆盖 A/B/C/D/E/F/G/H/I/J/K —— **十一组齐全**。

### 22.2 为什么要有 `claim_mismatches` 这张表

架构 §8.5 写的是"记录 `identity.claim_mismatch` 事件"，实现上做了扩展，
理由值得写下来：

**事件表回答不了"还剩几条"**。outbox 是外发队列，投递成功就出队；
而 J 组的核心动作是"看还有多少条待处理、逐条判断后闭环"。这要求记录有
**可变更的状态**，只有事实表能做。所以这里是"事实表 + open/resolved 状态机"，
事件（如果需要外发）只是从这张表派生的同一件事。

表结构的关键字段：

| 字段 | 作用 |
| --- | --- |
| `kind` | 四类漂移：`account_not_found` / `account_mismatch` / `multiple_accounts` / `identity_missing`，有 CHECK 约束 |
| `expected_user_id` | 本地绑定认为该凭证属于谁 |
| `actual_user_id` | 用户中心说它属于谁（可为空） |
| `occurrences` | 重复命中次数 |
| `status` | `open` / `resolved` + 处理人、理由、时间 |

### 22.3 去重：漂移是状态，不是事件

这是本节最重要的设计决定。

用户换了手机号之后，**每次登录**都会命中同一处不一致。如果每次都插一行，
一周就能把表写爆；更糟的是"待处理条数"会随登录量上下浮动，那个数字就失去意义。

所以 `(app_id, claim_id, kind)` 在 `status='open'` 时**部分唯一索引唯一**，
重复命中只累加 `occurrences`、刷新 `last_seen_at`：

```sql
CREATE UNIQUE INDEX uk_claim_mismatch_open
    ON claim_mismatches (app_id, claim_id, kind)
    WHERE status = 'open';
```

写入用 `INSERT ... ON CONFLICT (app_id, claim_id, kind) WHERE status='open'
DO UPDATE`。谓词必须再写一遍 PostgreSQL 才做索引推断——这也是这里没用
GORM `clause.OnConflict` 的原因（它表达不了部分索引的条件，写成全集会在
"已闭环记录存在"时误报冲突，而那种情况本应允许新增一行）。

注意 `first_seen_at` **不被** DO UPDATE 覆盖：首次出现时间是判断"这处漂移
存在多久"的依据。

### 22.4 撤销与闭环必须绑定

`POST /claims/{id}/revoke` 做两件事：撤销 claim、把该 claim 名下 open 的漂移
标为 resolved。两者缺一不可：

- **只撤销不闭环**：`claim_mismatch` 计数永远降不下来。一个只涨不落的指标，
  第二次就没人看了。
- **只闭环不撤销**：下一次登录还会命中同一条 claim，再记一条新的漂移——
  那是假的修复。

撤销的入参有两道硬约束：`app_id` 必填（凭证按应用隔离，id 属于哪个应用
必须显式声明）、`reason` ≥ 4 字符（进 `admin_audit_logs.reason`）。
审计同时写 `before_state` / `after_state`——撤销之后原记录只剩 `revoked_at`，
事后想知道"当时它是否已验证、来源是什么"只能靠 before 快照。

重复撤销返回 200 但带 `already_revoked: true`，而不是静默成功：运维要能分清
"是我撤的"还是"别人已经在另一个工单处理过"。

### 22.5 登录链路的写入是旁路

`claimmerge.resolveClaim` 的三个失败分支现在各写一条漂移：

| 分支 | kind | expected / actual |
| --- | --- | --- |
| `identity.ErrNotFound` | `identity_missing` | 空 / 空 |
| `account.ErrNotFound` | `account_not_found` | 本地绑定账号 / 空 |
| `account.ErrMultipleAccounts` | `multiple_accounts` | 本地绑定账号 / 空 |
| `acc.UserID != b.ExternalUserID` | `account_mismatch` | 本地绑定账号 / 用户中心账号 |

三个实现选择：

1. **best-effort**：写失败只打 Error，绝不让登录失败。漂移记录是旁路证据，
   主流程是"拒绝归并"，两者不该互相牵连。
2. **`context.WithoutCancel`**：证据不该随请求取消而丢失。用户断网、前端超时
   都会取消入站 ctx，但"这里发生过一次不一致"是运维必须知道的事实。
3. **3 秒超时**：WithoutCancel 之后没有任何取消了，必须自己兜住，
   否则一次数据库抖动会让登录请求挂住。

### 22.6 权限与数据可见性

- `identity:write` 是新权限，只给 `operator`。撤销一条 claim 会改变"下一次登录
  被归并到哪个账号"，属于账号运营动作；`config_admin` 管的是接入配置，不该有。
- 凭证值仍然只回哈希前缀（8 位）。完整哈希可用于"拿一批疑似手机号离线反查
  库中是否匹配"，而管理端账号被盗的代价不该包括一整批手机号。
- `claims` / `claim_mismatches` 两张表的查询都带 `app_id`；`claim_mismatches`
  已加入 `scopedTables`，业务侧误用会直接 panic（与 `identity_claims` 同口径）。

### 22.7 前端：概念先讲清楚

参照 G 组「事件死信」的教训（术语直接摆上来没人看得懂），这一页开头就把
两套数据的关系写清楚：

> `identity_claims` 记的是"某次授权中平台证明过这个号属于他"，平台不会主动撤销；
> 用户中心说的是"这个号现在属于谁"。两者会漂移。
> **漂移 = 有人本该被归并进来，但因为数据不一致被拦住了。**

顶部常驻一条横幅显示 `open_total`：非 0 时用警示色，并说明"这些用户本该被
自动归并、但被拦住了，逐条确认后撤销对应凭证即可释放号码"；为 0 时也补一句
"长期为 0 而业务侧一直反馈同手机号没合并，要先确认应用是否开了
`on_login = claim_verified`，否则核对根本不会发生"——避免把"没配"误读成"没问题"。

四类漂移各有一句 `hint`（悬浮展示）：说清"两边怎么对不上"和"该怎么办"。

### 22.8 测试与验收

`application/adminidentity/claims_test.go`：9 例

| 用例 | 守住什么 |
| --- | --- |
| 非法 status / kind | `REQUEST.INVALID`，不落到仓储 |
| 已撤销筛选 | 换号排查必须能看已撤销的记录 |
| 哈希截断 + 状态计算 | 只回 8 位；撤销只置 `revoked_at` 不改 `verified`，status 不能推错 |
| `open_total` 全量 | 不受筛选影响（翻页时不能误以为处理完了） |
| revoke 缺 app_id / reason | 分别 `REQUEST.INVALID` / `ADMIN.REASON_REQUIRED` |
| revoke 不存在 | **404**（不是被 errs.From 归一化的 500） |
| revoke 正常 | 撤销 + 闭环 + 出参带撤销时间与闭环条数 |
| revoke 幂等 | `already_revoked=true` 且不重复调用仓储 |

`application/authflow/claimmerge_test.go` 新增断言：三个失败分支各写了正确的
`kind` 与两侧账号（含"多账号命中会返回错误、漂移记录仍须在返回前落库"）。

`scripts/acceptance-claims.sh`：15 步实机验收。造数走 SQL（身份只能由真实授权
产生，没有 API 可直接建），清理走 trap：

```
1-6   登录 / 列表结构 / 非法 status / 非法 kind / open_total / 401
7-8   缺 reason → 400；不存在的凭证 → 404
9     造数：应用 + 身份 + 已验手机号 + 一条 account_not_found 漂移
10-11 能查到凭证（且不泄露完整哈希）、能查到漂移（open_total=1）
12-13 撤销 → 闭环 1 条 → 凭证转 revoked、漂移转 resolved、open_total=0
14    重复撤销幂等
15    审计留痕 claim.revoke（target_id = claim id）
```

### 22.9 仍未交付

1. **`existing_binding` 验证方式**（21.7 遗留）：需要给 `/v1/authorize` 加
   验证用途模式，侵入核心链路，单独排期。
2. **漂移的自动发现**：当前只有"回源核对失败"这一路会写漂移。定期全表扫描
   （对照用户中心批量核对）没做——那是离线任务，量级与限流都要单独设计。
3. **`claim.invalidated` 反向通知**（§8.5 第 2 条，仅建议）：用户中心主动推送
   换号事件 → 本服务自动撤销 claim。有了它，多数漂移根本不会产生；当前靠
   人工撤销兜底。
4. **漂移的趋势与告警**：`/health/overview` 现在有 `claim_mismatch_open`
   这个瞬时值（见 22.10），但没有时间序列，也没有"新增速率"告警。
   阈值告警要接监控系统，不在本服务内做。

### 22.10 顺手补上：漂移数进总览

§15.4 I 组要求的摘要里本来就有"claim 不一致数"，一直没接（当时没有数据源）。
现在数据具备了，补上：

- `GET /admin/v1/health/overview` 增加 `claim_mismatch_open`（全平台未闭环数）
- 读取失败只打 warn，该字段保持 0——单个指标取不到不该让整个看板 500，
  运维这时更需要的是渠道健康状态
- 观测看板增加第 5 张卡片，非 0 时用警示色，点击直达「凭证一致性」页

为什么要在总览里放：漂移数只躺在 J 组页面里，运维不会主动点进去。
放在每天都会扫一眼的看板上，才有可能被处理。

### 22.11 实机验证（2026-10-23）

镜像重建后 `docker compose up -d --build`，`migrate` 一次性容器输出：

```
OK   00006_claim_mismatch.sql (77.96ms)
goose: successfully migrated database to version: 6
```

`\d claim_mismatches` 核对：18 列、4 个索引（含 `uk_claim_mismatch_open` 部分唯一索引）、
2 个 CHECK 约束，与迁移文件一致。

| 验证项 | 结果 |
| --- | --- |
| `scripts/acceptance-claims.sh` | **15 步全过**（含 404 不被归一化成 500、哈希前缀、闭环、幂等、审计留痕） |
| `scripts/acceptance-admin.sh`（回归） | **17 步全过** —— 上一轮的 G 组 404 修复与 claim 归并没有破坏既有链路 |
| 去重语义 | 同一 `(claim, kind)` 连续命中 3 次 → `rows=1 occurrences=3` |
| 闭环后复发 | 标记 resolved 后再命中 → `rows=2 open=1 resolved=1`（新增一行，不复用） |
| `claim_mismatch_open` | 无漂移时 0，插一条后 1，清理后 0 |
| 前端 | `/admin/` 200 且加载新 bundle；`/admin/claims` SPA fallback 200；bundle 内含页面文案 |

**踩到的坑**（已修进脚本）：`psql -tA` 执行 `INSERT ... RETURNING id` 会额外打印一行
命令标签 `INSERT 0 1`。把它一起塞进 shell 变量后，后续 SQL 的 VALUES 列表变成
`VALUES (1\nINSERT 0 1, 'phone', ...)`，报 `syntax error at or near "INSERT"`——
错误位置指在第 4 行，跟真正的出错原因（变量内容）完全不像。改成
`WITH t AS (INSERT ... RETURNING id) SELECT id FROM t` 后只输出纯值。

---

## 23. HTTPAccountProvider（接入真实用户中心）

第三期一直挂着的最后一块：`account.provider=http` 此前是显式报错，
账号只能存在进程内存里（`StubProvider`），生产不可用。

> ⚠️ 本节描述的是契约 v1（无应用维度）。**已于 §27 升级到 v1.1**：
> 路径加 `/v1/apps/{app_key}` 前缀、补错误信封与换绑端点。下面的路径表仅作历史记录。

### 23.1 契约由本服务定义，不去适配对方现状

用户中心是外部系统，它现在可能没有、或者有几个形态各异的内部接口。
本服务需要的四件事各有硬性语义要求（强一致读、幂等键、命中多账号必须报错），
这些语义没法从"对方恰好有这么一个接口"里推出来。所以这里的路径与报文
就是**对用户中心的接口要求**，写进联调文档，而不是做成一个可配置的万能适配器。

| 方法 | 路径 | 语义 |
| --- | --- | --- |
| GET | `/accounts/{user_id}` | 200 账号 / 404 不存在 |
| GET | `/accounts/by-claim?type=&value=` | 200 / 404 / **409 命中多个账号** |
| POST | `/accounts` | 需 `Idempotency-Key`；404/405/501 表示不提供该能力；409 表示凭证被占用 |
| POST | `/accounts/merge` | 需 `Idempotency-Key`；404 target/source 不存在；409 拒绝合并 |

账号报文：`{"user_id","status":"active|frozen|closed","claims":[{"type","value","source"}],"extra":{}}`。
合并报文：`{"merged":bool,"already_merged":bool,"remote_ref":{}}`。

`GetByClaim` 的 409 不是"请求冲突"，而是"这个凭证在用户中心对应多个账号"
——说明唯一性已经坏了，必须让调用方走人工排查，而不是随手挑一个。

### 23.2 三条实现纪律

1. **不重试**（§5.5 / C6）。httpx 本身不带重试，这里也不加。登录链路的
   失败单位是"整次授权"，由接入方重新发起；Merge 的重试走
   `merge_operations` 的幂等键，不是 HTTP 层重试。
2. **错误码翻译**。httpx 是给三方渠道写的，传输层错误用 `PROVIDER.*` 表达。
   但本接口的调用对象是用户中心——对外出现 `PROVIDER.TIMEOUT` 会让排障的人
   去翻渠道日志。所以统一翻成 `ACCOUNT.UNAVAILABLE`，并保留 `retryable`。
3. **响应校验**。对端返回缺 `user_id`、或 `status` 不在枚举内时直接拒绝。
   否则垃圾值会以"账号状态非 active，跳过归并"的形式出现在业务层——
   看起来像数据问题，实际是契约不符，排障方向完全错。

### 23.3 配置与启动自检

```yaml
account:
  provider: "http"
  http:
    base_url: "https://uc.internal"
    token: ""        # 生产走 SOCIAL_LOGIN_ACCOUNT_HTTP_TOKEN
    timeout: "3s"
```

- `base_url` 为空 / 缺 scheme / 非 http(s) → 启动失败（`CONFIG.INVALID`），
  不带着空地址跑。空地址不会"启动就崩"，而是每次登录拼出相对 URL 再失败，
  日志里看不出是配置问题。
- **超时默认 3s**（httpx 默认 5s）：用户中心是登录链路的同步依赖，
  整条链路预算 8s，Exchange+UserInfo 已占 5s。慢到 3s 没回就让本次登录失败，
  比拖死整个请求好。
- `token` 为空只打 Warn 不报错——内网无鉴权联调环境确实存在，
  但生产缺 token 的现象是"所有登录都 ACCOUNT.UNAVAILABLE"，很难联想到鉴权，
  所以必须喊出来。
- `provider` 保持默认 `stub`（本地/演示可跑）；生产模式下 stub 会被启动自检拒绝。

### 23.4 测试

`infrastructure/account/http_test.go`：19 例，用 `httptest` 起假用户中心
（跳过 HTTP 层就等于没测协议映射）。

| 用例组 | 守住什么 |
| --- | --- |
| 配置校验 ×3 + 尾斜杠 | 空地址/错 scheme 启动即失败；`//accounts` 不会出现 |
| Get | 解析、404→ErrNotFound、缺 user_id 拒绝、未知 status 拒绝 |
| GetByClaim | 查询参数正确、**409→ErrMultipleAccounts** |
| Create | **必须带 Idempotency-Key**、缺键不发请求、404/405/501→NOT_SUPPORTED、409→BIND.IDENTITY_TAKEN |
| Merge | 幂等键必传、`already_merged` 解析、请求体字段 |
| 错误归一化 | 5xx→ACCOUNT.UNAVAILABLE(可重试)、超时→ACCOUNT.UNAVAILABLE(可重试)、4xx 不可重试且保留对端错误片段 |

### 23.5 仍未做

- **实机联调**：对端尚未开始建设。已用假对端（`internal/testsupport/mockusercenter`
  + `test/acceptance/account_http_test.go`）把协议映射、幂等键、降级行为跑通；
  真实对端的强一致读、幂等实现、容量与延迟仍需联调。**完整状态标记与联调步骤见
  `docs/user-center-integration.md`，见 §26。**
- **契约版本化**：路径与报文目前是 v1，对端演进时需要有版本协商（`/v1/accounts`）。
- **批量核对**：`identity_claims` 与用户中心的全量对账仍是离线任务（见 §22.9）。

---

## 24. 指标导出（`/metrics`）

§11 要求的观测能力此前完全缺失：没有 `/metrics`，所有指标只存在于日志里，
上线等于盲飞。

### 24.1 为什么手写而不引 Prometheus SDK

1. 需要的类型只有 counter 与 gauge。直方图用 `<name>_sum` / `<name>_count`
   两个 counter 就能算平均与总量；分位数不是当前需求（要看 P99 时再加 histogram）。
2. 引 SDK 会带来依赖树、全局注册表和一套初始化约定，而指标总量是两位数以内。
3. 手写输出可以在测试里**逐字节断言**，行为完全可预期。

`internal/pkg/metrics`：`Registry` / `Counter`（带标签）/ `GaugeFunc`（采集时求值）
/ `Handler()`，输出 Prometheus 文本格式 0.0.4。

### 24.2 导出的指标

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| `social_login_http_requests_total{method,route,status}` | counter | 全部端点的请求数 |
| `social_login_http_request_duration_seconds_sum/_count{method,route}` | counter | 平均耗时（rate 后相除） |
| `social_login_claim_mismatch_open` | gauge | 未闭环凭证漂移数（J 组数据） |
| `social_login_outbox_dead` | gauge | 死信数（必须人工处理） |
| `social_login_outbox_pending` | gauge | 待投递数（持续升高说明投递跟不上） |
| `social_login_merge_compensation_lag_seconds` | gauge | 最久未推进的合并已等待秒数（§11 明确要求） |
| `social_login_uc_sync_failed` | gauge | 未同步到用户中心的应用数（非 0 表示这些应用登录会失败，§32） |
| `social_login_apps_total` | gauge | 应用总数，作为上一行的分母（区分单租户与全链路故障） |

**登录成功率不单独建指标**：`/v1/oauth/callback` 的 2xx 比例就是它，
HTTP 指标里能算。为它再维护一套埋点只多一个会漂移的口径。

gauge 用 `GaugeFunc` 在采集时查库（带 2s 超时），不是让业务代码每次 Push：
业务代码不需要知道指标存在，采集频率也由 Prometheus 决定。查库失败只 Warn
并返回 0——一个指标取不到不该让整个 `/metrics` 挂掉。

### 24.3 两条必须守住的实现细节

**标签基数**：`route` 标签取 gin 的路由模板（`c.FullPath()`），**不是原始路径**。
用原始路径会让 `/apps/1`、`/apps/2`… 每个 id 变成一条时间序列，几百个应用就能
把 Prometheus 打爆——这是"指标比业务先挂"的典型原因。未命中路由统一归为
`unmatched`，否则扫描器的随机路径会无限建序列。

**中间件顺序**：`Metrics` 必须挂在 `Recovery` 的**外层**。洋葱模型下，
handler panic 会先被内层 Recovery 捕获并写成 500，Metrics 的 defer 随后执行
才能读到 500；反过来会把它记成 200——监控上看一切正常，实际在 500。

### 24.4 部署要求（不是建议）

`/metrics` **不做鉴权**：Prometheus 抓取端通常只支持简单鉴权，而指标内容不含凭据。
安全边界靠网络——部署时必须确保该路径只对监控网段开放（网关/安全组），
**不要暴露到公网**。

### 24.5 测试

- `pkg/metrics`：8 例。逐字节格式比对、gauge 采集时求值、标签转义
  （引号/换行/反斜杠——不转义会让整个抓取被解析器拒绝）、同名异类型 panic、
  标签数量不符 panic、100×100 并发累加不丢、Content-Type。
- `middleware`：4 例。**路由模板合并**（3 个 id → 1 条序列）、
  unmatched 折叠、**panic 记 500**（中间件顺序回归）、耗时 sum/count。

### 24.6 仍未做

- **实机抓取验证**：容器未重建（Docker daemon 不可用），`/metrics` 尚未在
  真实进程上抓取过。启动后 `curl :8080/metrics | grep social_login` 验证。
- **Tracing**：只有 trace_id 串日志，没有 OpenTelemetry 上报。
- **直方图分位数**：要看 P99 需要加 histogram bucket，当前只有平均值。
- **告警规则**：指标有了，但没有配套的告警表达式（`outbox_dead > 0`、
  `merge_compensation_lag_seconds > 300`、`claim_mismatch_open > 0`）。

---

## 25. 整体完成度对照（2026-11-02 复核）

本节回答一个问题：**离 `§13 分期落地路线` 的原始规划还差什么。**
核对方式是读代码与迁移文件，不看注释里的承诺——历史上出现过三次
「注释说做了、代码没有」的情况（`claim_verified`、`/metrics`、`summary` 指标）。

> 上一版是 10-29，那时用户中心还不存在。本次复核把随后交付的
> 用户中心（§29）、服务边界护栏（§30）、容器化双服务部署（§31）
> 与本轮补的三项（绑定路径回源核对、`rl:identity`、告警规则）一并计入。
> 表格里 ⚠️ 的含义是「能力在，但有明确的缺口」，❌ 是「没有」。

### 25.1 四期逐项

| 期 | 规划项 | 状态 | 说明 |
| --- | --- | --- | --- |
| 一 | 五张核心表 | ✅ | `00001_init.sql` |
| 一 | IdentitySource 抽象 + Provider SPI | ✅ | `domain/identitysource/`、`provider.Register` |
| 一 | AccountProvider + Stub | ✅ | Stub 保留，HTTP 见 §23 |
| 一 | 通用 OAuth2 适配器 | ✅ | `adapters/generic_oauth2` + `cmd/mockoauth2` |
| 一 | 授权 / 回调 / 换令牌 + NEED_REGISTER | ✅ | `test/acceptance/flow_test.go` |
| 一 | Ticket + bind_ticket + JWT | ✅ | |
| 一 | JWKS + 密钥骨架 | ✅ | |
| 一 | 凭据 AES-GCM 加密 | ✅ | 本地主密钥，KMS 见四期 |
| 一 | outbox 表 + 投递骨架 | ✅ | |
| 一 | 管理端 A/B/I 组 | ✅ | |
| 二 | 微信 4 场景 | ✅ | app / mini_program / official_account / pc_qr |
| 二 | 支付宝 3 场景 | ✅ | app / mini_program / web |
| 二 | Apple 2 场景（client_secret 签发 / nonce / 首次 name-email / notify） | ✅ | |
| 二 | 小程序 session_key 生命周期 | ✅ | §10.6 |
| 二 | 熔断 + 四类阈值 + 三段超时 + WithoutCancel | ✅ | `pkg/guards/breaker`、`middleware.Timeout` |
| 二 | 管理端 G/H 组 | ✅ | |
| 三 | 绑定三件套 | ✅ | |
| 三 | 合并行为配置化（3 mode × 3 on_login）+ 校验器 | ✅ | |
| 三 | R4 红线（白名单 / 跨平台默认关） | ✅ | |
| 三 | 三次独立事务 + 幂等键 + 补偿 | ✅ | |
| 三 | 合并前回源核对（P0-6） | ✅ | |
| 三 | 验证手段：sms | ✅ | |
| 三 | 验证手段：existing_binding | ❌ | 只有 hint 常量，无验证路径 |
| 三 | 验证手段：待合并账号手机号/邮箱验证 | ⚠️ | 走 sms 通道，独立入口未做 |
| 三 | `source_disposal` 生效 | ❌ | 字段可存可解析，合并时无分支读它；`notify_source_account` 仍硬编码 true |
| 三 | 补偿滞后**告警** | ⚠️ | 指标与规则都有（`deploy/prometheus/alerts.yaml`），通知通道未接 |
| 三 | HTTPAccountProvider | ✅ | 契约 v1.1 + 真实用户中心联调，见 §27/§31 |
| 三 | 管理端 C/D/J 组 + 前端 | ✅ | |
| 四 | jti 撤销黑名单（P0-5） | ✅ | §14 |
| 四 | 密钥四步轮换 + F 组 | ✅ | §16 |
| 四 | 会话/令牌 + E 组 | ✅ | §14 |
| 四 | 管理员授权 K 组 | ✅ | §17 |
| 四 | 审计导出 | ✅ | §12 |
| 四 | 限流：notify + app×IP | ✅ | §15 |
| 四 | 限流：`rl:identity`（防撞库） | ✅ | 2026-11-02 补，`pkg/ratelimit` + `infrastructure/ratelimit`；挂在授权流程内部（中间件拿不到身份） |
| 四 | 限流：`rl:platform:day`（渠道日配额） | ✅ | 2026-11-02 补，`AllowDaily` 自然日窗口；超限 `PROVIDER.QUOTA_EXCEEDED` 快速失败 |
| 四 | Webhook 事件体系（签名/重试/去重/死信） | ✅ | 提前到二期交付，见 §11 |
| 四 | 可观测性：`/metrics` | ✅ | §24，已含 `uc_sync_failed` / `apps_total` |
| 四 | 可观测性：告警规则 | ✅ | `deploy/prometheus/alerts.yaml`（6 条），接收端待运维接入 |
| 四 | 可观测性：tracing | ❌ | 只有 trace_id 串日志 |
| 四 | KMS 信封加密 | ✅ | 2026-11-04 补：真信封（每行 DEK）+ KEK 端口 + KMS/本地两种实现 + 迁移工具，见 §35 |
| 四 | 配置热更新 | ❌ | 改配置需重启 |
| 四 | 账号注销与数据合规 | ✅ | 2026-11-04 补，`POST /v1/account/close`：关对端 → 级联解绑 → 撤令牌 → 删凭证密文；见 §34 |
| 四 | `Unbind` 不支持的降级提示 | ❌ | `Revoke` 仍无调用点；**卡在"不保存平台 refresh_token"**，见 §33.3 |
| 四 | 双人复核（`admin_approvals`） | ❌ | 表未建、流程未做 |
| 四 | 管理员账号管理（创建/停用/改密） | ✅ | 2026-11-02 补，`adminuser` 用例 + `/admin/v1/admins`；含自锁保护、末位超管保护、改密撤会话、审计 |
| 四 | `ScopeAppID` 按应用鉴权 | ❌ | 字段存了，鉴权层明确忽略 |
| 四 | 压测与故障演练 | ❌ | 无记录 |
| 四 | 与用户中心联调压测（降级验证） | ⚠️ | 联调与降级验证完成（§31：对端停机 → `ACCOUNT.UNAVAILABLE` + `retryable=true`），压测未做 |

### 25.2 统计

| 期 | 项数 | 完成 | 部分 | 未做 |
| --- | --- | --- | --- | --- |
| 一 | 10 | 10 | 0 | 0 |
| 二 | 7 | 7 | 0 | 0 |
| 三 | 12 | 8 | 2 | 2 |
| 四 | 21 | 14 | 1 | 6 |
| **合计** | **50** | **39** | **3** | **8** |

**按项数看：规划 50 项，完成 39 项、部分 3 项、未做 8 项 → 约 78%**

比 10-29 那版（32/3/15，64%）多了 6 项完成。三轮的推进方式不同：
第一轮是"等对端"的项终于有对端（联调、部署验证）；第二轮把"知道该做、
但一直排在后面"的三项补上（状态闸门/换绑、两档限流、告警）；
第三轮清掉上线阻塞项（日配额、管理员开户）并补上注销编排。

### 25.3 本轮（2026-11-02）实际变化

| 项 | 之前 | 现在 |
| --- | --- | --- |
| 真实用户中心联调 | ❌ 只有假对端 | ✅ 契约 18 项 + 真实登录链路（§29/§31） |
| 已绑定用户登录的账号状态校验 | ❌ 命中本地绑定就直接签发 | ✅ `accountgate.go`：非 active 一律拒绝 |
| 平台侧凭证变更识别 | ❌ `ClaimReplacer` 无调用方 | ✅ 登录时比对并调用换绑，冲突不阻断登录 |
| `rl:identity` | ❌ | ✅ 30 次/分钟/身份，作用在授权流程内部 |
| 告警规则 | ❌ 只有指标 | ✅ 6 条规则（死信/积压/合并滞后/漂移/同步失败×2） |
| `uc_sync_failed` 指标 | ❌ | ✅ + `apps_total` 做分母（区分单租户与全链路） |
| `rl:platform:day` 渠道日配额 | ❌ | ✅ 自然日窗口，超限 `PROVIDER.QUOTA_EXCEEDED`（不排队） |
| 管理员账号管理 | ❌ 只能改库 | ✅ `/admin/v1/admins` 增查改 + 改密；自锁保护、末位超管保护、撤会话、审计 |

三件事共同的判断标准是**"会不会静默出事"**：状态不校验 = 封禁不生效且没人知道；
同步失败 = 单应用登录全挂但报"应用不存在"；告警缺失 = 指标躺着没人看。

### 25.4 剩下 10 项，按上线必要性排序

**A. 上线阻塞（0 项）**

原 A 组 3 项已全部清空：真实用户中心联调（§29/§31）、`rl:identity`（§32）、
`rl:platform:day`（§33）。**这是首次出现"没有上线阻塞项"的状态**——
但下面的 B 组仍是灰度前的门禁，不等于可以上生产。

**B. 灰度前（2 项）**

1. `Unbind` 平台侧解绑——**卡在凭据**：平台撤销需要渠道的 refresh_token，
   而本服务从不持久化它（见 §33.3 的取舍）。降级提示已在注销里给出
   （`unbind_manual_required`），真实撤销要等平台令牌存储的安全评审。
2. tracing——链路横跨用户中心 → 本服务 → 渠道，只能靠 trace_id 手工串日志。

**C. 可延后（6 项）**

3. `existing_binding` 验证方式（侵入 `/v1/authorize`，且已有 sms 兜底）
4. `source_disposal` 生效 + `notify_source_account` 去硬编码（方向安全，只是配置关不掉）
5. 双人复核（`admin_approvals` 表 + 审批流）
6. 配置热更新
7. `ScopeAppID` 按应用鉴权（多应用管理员目前能看到全部应用）
8. 压测与故障演练（含"远端 Merge 成功、本地提交失败"的补偿自愈演练）

> 另有 1 项**非代码**阻塞：回调域名备案 + Apple Service ID / `.p8`。周期最长，应最早启动。

**管理端通用约定（§15.5）未落地的 5 条**：`Idempotency-Key` 全局未实现；
`page_token` 恒空；`dry_run` 只有 `policy:validate`；C 组解绑/transfer 只有 after 快照；
前端只有审计页有翻页。

### 25.5 用户中心侧

用户中心 P0 已完整交付，缺口按 `docs/user-center-mvp-design.md` §10 分期：

- **P0.5**：审计日志、慢查询日志、`uc_sync_failed` 在**对端**侧的指标（登录侧已有）。
- **P1**：`claim.invalidated` 推送、注销的完整链路、管理端账号只读视图、
  换绑 24h 回滚窗口、`discarded_claims` 通知用户。其中"停用状态在登录链路生效"
  本轮已由登录侧的 `accountgate.go` 补上（对端不需要改）。
- **P2**：分区/RLS、批量对账、`claim_types` 注册表、KMS。

### 25.6 结论

- **功能面**：业务端 14 接口、管理端 11 组 53 端点、11 组前端，加上用户中心
  五端点，链路已闭环，且有契约脚本 + 真实联调 + 容器部署三层验证。
- **生产化面**：剩 12 项，其中 6 项属于"上生产前必须有"（A 组 1 + B 组 5）。
- **三处「能配不生效」仍是当前最该修的质量问题**——它们不会报错，只会让运维
  以为自己配好了：`source_disposal`、`page_token`、`ScopeAppID`。

## 26. 用户中心未就绪：状态标记与联调准备

> ⚠️ 历史章节（2026-11-02 之前的状态）。对端已于 2026-11-02 交付并通过真实联调，
> 本节的「未就绪」结论已过期，保留它是为了记录「对端不存在时我们标记了什么、
> 怎么准备联调」这一过程。当前状态见 §29 与 §25。

用户中心是独立服务，目前**尚未开始设计与开发**。本服务的账号体系是 remote 模式
（约束 C4，没有 `accounts` 表），因此它的 absence 会让一批功能处于"代码完成、
语义未验证"的悬空状态。这一节做三件事：把状态标出来、把现在能验的验掉、
把对端就绪后要做的事写成可执行清单。

### 26.1 三个层次的标记

| 层次 | 手段 | 谁看 |
| --- | --- | --- |
| 运行期 | `/admin/v1/health/overview` 返回 `account_center{provider, base_url, production_ready, note}`；观测看板顶部常驻标记条，stub 时警示色 | 运维、值班 |
| 启动期 | `release` 模式禁止 `provider=stub`（已有）；`provider=http` 缺 base_url 启动即失败（已有） | 发布流程 |
| 文档 | `docs/user-center-integration.md`：契约 v1 + 16 项进度标记 + 联调步骤 + 切换清单 | 对端团队、我方开发 |

运行期标记的必要性：stub 与 http 在**外部表现上几乎一样**——都能登录成功、
都能签发令牌、`/v1/userinfo` 都正常。差别只在账号存在哪里。没有标记的话，
一个演示环境看起来和生产没有任何区别。

### 26.2 把"等对端"变成"现在能验"

| 交付物 | 作用 |
| --- | --- |
| `internal/testsupport/mockusercenter` | 契约的可执行版本：4 个端点 + 幂等键 + 多账号 409 + 故障注入（500/429/timeout/slow/multi）+ 调用记录（含幂等键） |
| `cmd/mockusercenter` | 独立进程形态，给手工联调/演示用；`-seed` 预置账号，`-no-create` 模拟对端不提供建号 |
| `test/acceptance/account_http_test.go` | 4 个端到端用例：真实登录流程 + `provider=http` |
| `scripts/check-usercenter-contract.sh` | 对端交付时的契约体检（默认只读，`--write` 才创建数据） |

端到端用例跑的是**真实链路**（authorize → 三方回调 → auto_create → 签发 auth_code →
换令牌），不是直接调适配层，因此能验到"用户中心返回的 `user_id` 有没有真的
被写进绑定与令牌 `sub`"——这一点在单测里根本看不见。

### 26.3 实测结果（2026-10-29）

```
$ go test ./test/acceptance/ -run TestHTTPAccountProvider -v
--- PASS: TestHTTPAccountProviderAutoCreate
--- PASS: TestHTTPAccountProviderCreateUnsupported
--- PASS: TestHTTPAccountProviderUnavailableFailsFast
--- PASS: TestHTTPAccountProviderRateLimited
ok  github.com/djackcurry30/social-login/test/acceptance  2.1s
```

| 用例 | 守住的语义 |
| --- | --- |
| AutoCreate | Create 恰好一次、带幂等键；令牌 `sub` = 对端 `user_id`（不是 open_id）；二次登录不再建号 |
| CreateUnsupported | 对端 404 → `AUTH.INVALID_CONFIG`，文案提示改 `need_register`；不产生账号 |
| UnavailableFailsFast | 5xx → 回跳 `ACCOUNT.UNAVAILABLE&retryable=true`；故障恢复后一次登录成功（无半截绑定） |
| RateLimited | 429 → `RATE.LIMITED`（不与可用性故障混同） |

```
$ scripts/check-usercenter-contract.sh http://127.0.0.1:19091 "" --write --claim phone:19900000001
  ok   连通性正常，未知账号返回 404
  ok   by-claim 对不存在的凭证返回 404
  ok   缺少 Idempotency-Key 时被拒绝（400）
  ok   创建成功，user_id=uc-0001
  ok   幂等键重放返回同一账号（uc-0001）
  ok   写后立刻按凭证反查命中同一账号（强一致读成立）
  ok   target==source 被拒绝（409）
  ok   source 不存在返回 404
==> 结果：通过 8 项，不符 0 项
```

### 26.4 写这个假对端时踩到的语义坑

**`merge` 幂等重放不能原样返回首次结果。** 第一版在命中幂等键时
`return prev`，于是重放返回 `merged=true, already_merged=false`——
补偿任务会据此认为"又合并了一次"，进而重复推进本地收敛。
正确语义是 `merged=false, already_merged=true`：**这次调用没有执行合并**。
这个 bug 是被 `TestMergeMovesClaimsAndIsIdempotent` 的第二段断言抓出来的，
而它在真实对端上会表现为"补偿重试把数据搬了两遍"，极难归因。

### 26.5 仍然悬空的 5 项（全部依赖对端先给接口形态）

1. `by-claim` 的**强一致读**——mock 天然强一致，证明不了对端
2. `merge` 的**真幂等**——mock 是 20 行 map，证明不了对端事务边界
3. `claim.invalidated` 反向通知（对端推换号事件，本侧自动失效 claim）——本侧接收端也没写
4. 账号注销（本侧发起、对端执行）——契约未定义
5. 批量对账（`identity_claims` vs 对端全量）——离线任务，量级与限流需单独设计

### 26.6 切换时最容易踩的坑

`stub` 生成的 `user_id` 形如 `u_stub_12_ab3f`，已经写进
`oauth_bindings.external_user_id`。切到 http 后这些绑定与真实账号没有任何对应关系：
登录能用（走已有绑定），但 `sub` 是对端不存在的 id，一旦触发合并/回源核对就
`Get` 404 → 归并被跳过并记漂移。

切换前必须清理或重建（开发/演示环境直接 `down -v` 即可）。
SQL 与处理方式见 `docs/user-center-integration.md` §6.1。

### 26.7 顺手修的看板错误：`apps_count` 恒为 0

加账号体系标记时顺手看了同一条 overview，发现 `apps_count` 一直是 0——
而库里当时有 160 个应用。原因是 `adminobs.Deps.OverviewGetter` 这个口子
**从未接线**：`Service.Overview` 里有 `if s.deps.OverviewGetter != nil` 的分支，
bootstrap 里却没给它赋值。

修法：`AppRepository.Count(ctx)`（跨应用作用域 + `COUNT(*)`）+ bootstrap 接线。
没有复用 `ListIDs`：它上限 500，超过之后数字会永远停在 500，而且不会有人察觉。

**恒为 0 的指标比没有指标更糟**——它看起来像"还没有人接入"，而不是"统计坏了"。
这类"永远返回同一个值"的口子以后加字段时应该顺手打一次真实请求确认。

---

## 27. 契约 v1.1 落地：应用维度、错误信封、换绑

上一节（§25）列的"真实用户中心联调"是外部依赖，但**契约本身缺了应用维度**——这件事
不等对端，我方先改。这一节是 `docs/user-center-mvp-design.md` §2 的实现记录。

### 27.1 为什么必须先改

`http.go` 的四个方法此前都不带应用标识。照那个契约实现，用户中心只能有一个**全局
账号空间**：App1 里某人用手机号建过号，App2 同一号码首登会命中 App1 的账号，直接
登进另一个业务的主体。这不是"多应用不方便"，是数据越权。

同时 `Merge` 要求拒绝跨应用合并（R3），没有应用维度就没有判据。

改的时机也重要：对端一行代码没写，现在改成本为零；等对端按 v1 写完再改，要双方
改代码 + 重跑联调。

### 27.2 五处契约变更

| # | 变更 | 落点 |
| --- | --- | --- |
| 1 | 路径加应用前缀 `/v1/apps/{app_key}/accounts/...` | `Get` / `GetByClaim` / `Create` / `Merge` / `ReplaceClaim` |
| 2 | `app_key` 用 `app_code`，不用 `applications.id` | 调用点传 `app.AppCode` |
| 3 | 统一错误信封 `{code,message,retryable}`，按 code 翻译 | `classify()` |
| 4 | 补换绑端点 `PUT .../claims/{type}` | `ClaimReplacer` 可选端口 |
| 5 | 合并回传 `discarded_claims` | `MergeResult.DiscardedClaims` |

### 27.3 三个设计决定

**① 应用进路径，不进请求头。** 请求头漏了 = 未知租户，每个端点都得记得拦，日志和
网关限流都看不见；路径漏了 = 404，不可能静默串租户。代价是 URL 变长，可以接受。

**② 换绑做成可选端口 `ClaimReplacer`，不放进 `Provider`。** `Provider` 是登录链路的
最小必需集合；换绑目前没有调用方（P1 才接"平台侧手机号变了"的识别）。并进去会让
所有实现方（含测试替身）被迫实现一个当下无人调用的方法。调用方按需类型断言：

```go
if r, ok := provider.(account.ClaimReplacer); ok { ... }
```

**③ 裸 409 不再被猜成某一种具体原因。** 这是行为变化，值得单独说：

| 场景 | 改前 | 改后 |
| --- | --- | --- |
| Create 收到 409 + `ACCOUNT.CLAIM_TAKEN` | `BIND.IDENTITY_TAKEN` | 同（不变） |
| Create 收到 409 + `ACCOUNT.IDEMPOTENCY_IN_PROGRESS` | `BIND.IDENTITY_TAKEN`（**译错**） | `ACCOUNT.UNAVAILABLE` + 可重试 |
| Create 收到裸 409 | `BIND.IDENTITY_TAKEN` | `ACCOUNT.UNAVAILABLE`，不可重试 |

猜错比不猜更糟：把"同键正在处理"说成"该手机号已被占用"，会让调用方去做一件完全不
相关的事（走合并流程）。所以**没有 code 就只报"无法判定原因"**，把原始报文带在
details 里让人看。

代价是：对端如果实在不肯实现信封，`by-claim` 的多账号检测会退化成"409 但不知为何"，
`ErrMultipleAccounts` 不再被触发。契约 §3.3 已把这条写成硬要求，体检脚本会检查。

### 27.4 假对端同步升级（否则测不出应用维度）

`internal/testsupport/mockusercenter` 不是"顺手改一下"，它是**契约的可执行版本**：

- 账号按 `app_key` 分区（`claimOwner` 的 key 带应用前缀，`Get` 校验 `appOf` 一致）
- 跨应用 `Get` 返回 404、跨应用 `merge` 返回 404（R3）
- 合并按"类型目标优先"丢弃同类型凭证，并把 `discarded_claims` 回传
- 换绑端点：正常 / 幂等 no-op / 被占用 409
- `RequireRegisteredApp` 开关模拟 `APP.UNKNOWN`
- 调用记录带 `AppKey`，让测试能断言"租户前缀真的送到了"

### 27.5 测试

新增/改写的关键用例：

| 用例 | 守住什么 |
| --- | --- |
| `TestPathsCarryAppKey`（5 个子用例） | 每个端点的路径都带应用前缀 |
| `TestRequireAppKeyLocally` | 空 appKey 本地拦截——否则拼出 `/v1/apps//accounts`，对端 404 被译成"账号不存在" |
| `TestAppIsolation` | 同一手机号在两个应用建出两个账号；跨应用按 id 查 404 |
| `TestMergeCrossAppRejected` | R3：跨应用合并被拒 |
| `TestMergeDiscardsSameTypeClaim` | 合并丢弃同类型凭证，且**释放该号码**（否则用户拿它重新注册会一直撞"被占用"） |
| `TestIdempotencyInProgressIsRetryable` | 409 + IDEM_IN_PROGRESS 不被译成"凭证被占用" |
| `TestRaw409IsNotGuessed` | 无码 409 不猜原因 |
| `Test5xxBeatsEnvelopeCode` | 5xx 优先于信封（它决定"要不要重试"） |
| `TestCreate404WithCodeIsNotSupported` | 404 的双重含义靠"有没有 code"区分 |
| `TestErrorCodesMatchContract` | mock 与生产的错误码字面量逐条相等（两份独立定义，防漂移） |
| `TestReplaceClaim` | 换绑三条语义 + 失败时原凭证不动 |
| `TestUnregisteredApp` | APP.UNKNOWN 不可重试、文案指向注册 |
| `TestPathWithoutAppIs404` | 漏带前缀必须 404，不能落到默认租户 |
| e2e `TestHTTPAccountProviderAutoCreate` | 真实登录链路里 `Create` 带的是 `app_code`（不是空串、不是 id） |
| e2e `TestHTTPAccountProviderAppNotRegistered` | 应用未同步时用户看到什么 |

### 27.6 实机验证（2026-11-02）

```
go build ./...                     通过
go vet ./...                       干净
go test ./internal/...             38 个包全绿
test/acceptance（含 5 个用户中心 e2e）  全绿
scripts/acceptance-admin.sh        17 步全过（回归）
```

契约体检脚本对假对端跑满 16 项：

```
$ scripts/check-usercenter-contract.sh http://127.0.0.1:19093 "" \
    --app app_one --app2 app_two --write
  ok   连通性正常，未知账号返回 404
  ok   404 带错误信封（ACCOUNT.NOT_FOUND）
  ok   by-claim 对不存在的凭证返回 404
  ok   缺少 Idempotency-Key 时被拒绝（400）
  ok   400 带错误信封
  ok   创建成功，user_id=uc-0001
  ok   幂等键重放返回同一账号（uc-0001）
  ok   写后立刻按凭证反查命中同一账号（强一致读成立）
  ok   target==source 被拒绝（409）
  ok   拒绝合并带 ACCOUNT.MERGE_REJECTED 信封
  ok   source 不存在返回 404
  ok   同一凭证在 app_two 建出独立账号（uc-0002），应用隔离成立
  ok   APP2 反查只命中本应用账号
  ok   跨应用合并被拒绝（404）
  ok   换绑成功，账号已切换到 19900000009
  ok   换绑后旧凭证已释放（撤销即释放）
==> 结果：通过 16 项，不符 0 项，警告 0 项
```

未注册应用的分支也验过：`--app app_typo` 直接以 `APP.UNKNOWN` 中止并提示先做注册同步。

### 27.7 仍未做

1. **`ClaimReplacer` 没有调用方**。适配层和假对端都实现了，但登录链路还不会
   "发现平台侧手机号变了就换绑"——那是 P1，要改核心链路，风险大于收益。
2. ~~**应用注册同步没接**~~：已于 §28 交付（即时同步 + 5 分钟全量对账 + 状态落库）。
3. **真实对端联调**：仍是外部依赖。现在能验的到"协议映射 + 降级"为止，
   §26.5 列的五项（强一致读、真幂等、跨服务一致性、容量、鉴权）只有对端能给答案。

---

## 28. 应用注册同步（契约 v1.1 §2.6 落地）

§27 把契约升到 v1.1 时，"应用注册"只是纸面上的一行：对端要求 `POST /internal/v1/apps`，
本服务却没在任何地方调用它。按这份契约实现，对端上线当天所有应用的登录都会
400 `APP.UNKNOWN`——**这不是配置瑕疵，是登录直接不可用**。这一节把它补齐。

### 28.1 为什么它算"可用性组件"而不是配置项

契约把账号空间按 `app_key` 隔离，未注册的 `app_key` 一律 400。于是：

| 状态 | 用户侧表现 |
| --- | --- |
| 应用已注册 | 正常登录 |
| 应用未注册 | 该应用**所有**登录失败，错误 `ACCOUNT.UNAVAILABLE`（文案指向"未注册"） |
| 同步任务没跑 | 等价于"全部应用未注册" |

所以它必须满足两条相互矛盾的约束：**建应用不能依赖它**（用户中心挂了也要能改配置），
但**登录依赖它**（慢一分钟就有一分钟不可用）。下面两条路径就是这对矛盾的解法。

### 28.2 两条路径

| 路径 | 触发 | 延迟 | 作用 |
| --- | --- | --- | --- |
| 即时同步 | 建应用 / 启停应用后入队 | 毫秒级 | 运维刚建完就能登录 |
| 全量对账 | 启动即一次 + 每 5 分钟 | ≤ 5 分钟 | 自愈三类漂移 |

对账要自愈的三类问题，缺一条都不行：

1. 建应用时用户中心正好不可用（即时同步失败，只 warn）；
2. 用户中心上线前就存在的存量应用（从来没同步过）；
3. 对端数据被回滚 / 被手工清理（本地以为"已同步"，远端其实没了）。

### 28.3 五个实现决定

**① 入队是【非阻塞】的。** 队列满（256）时丢弃并打 warn，不阻塞调用方。
丢弃只意味着等下一轮对账（≤5 分钟）；阻塞会让"用户中心故障"升级成"建不了应用"，
而建应用恰恰是恢复期最需要的操作。这条很容易被"优化"掉——改成阻塞发送看起来
更严谨（不丢任务），实际是把两个独立链路焊死了。

**② 队列只带 `app_code`，不带应用快照。** 两个原因：

- 建完可能立刻被改（改名/停用），队列里那份就是过期的；
- 请求 ctx 在响应返回时取消，把结构体（或 ctx）带进后台会得到一个"永远失败
  但不报错"的任务。

回查只有一次主键查询的成本，换来的是"总是最新状态"。

**③ 接口定义在消费方（`adminapp.AppSyncNotifier`）。** A 组用例不该知道"用户中心"
这个概念的存在——它只说"我改了一个应用"。这样换同步实现、临时关掉同步，都不动
adminapp；A 组的单测也不必拉起一套 HTTP 客户端。

**④ 状态落库，成功后【清空】上次错误。** 只打日志等于没做：日志会滚掉，而
"这个应用到底注册上没有"是运维每天要回答的问题。失败保留 `uc_synced_at`
（"上次成功是 3 天前、此后一直失败"与"从未成功"是两种完全不同的判断），
成功则清空 `uc_sync_error`（否则管理端永久显示一个已经修好的旧错误）。

**⑤ 同步不动 `updated_at`。** 它是业务字段（配置最后修改时间），同步每 5 分钟一次；
一并刷新会让管理端列表里所有应用的"更新时间"自己往前跑。

> 这一条踩了两次坑：GORM 对带 `UpdatedAt` 字段的模型会自动补这一列，
> 不写进 map 拦不住；换 `UpdateColumns` 后**仍然**写了（靠"更新时间恰好等于
> 同步时间"才发现）。最后改成两条原生 `UPDATE`，只碰目标列，语义一眼可见。
> 教训：这类"我只改这两列"的期待，不要赌 ORM 的隐式行为。

### 28.4 数据与可见性

`00007_app_uc_sync.sql` 给 `applications` 加两列（含 COMMENT 说明归属）：

| 列 | 含义 |
| --- | --- |
| `uc_synced_at` | 最近一次成功注册的时间；NULL = 从未成功 |
| `uc_sync_error` | 最近一次失败原因（成功后清空），按 rune 截断 300 |

**刻意不加索引**：对账是全量重放（每 5 分钟 upsert 全部应用），不是"只查未同步的"。
只补未同步的话，"远端删了租户、本地状态仍是已同步"这一类永远修不回来；既然是全表
扫描，索引只会增加写入成本。

管理端三处可见：应用列表新增「用户中心」列（已同步 / 未同步 + 悬浮原因 / —）、
`GET /admin/v1/apps` 返回 `AccountSync{SyncedAt, LastError}`、启动日志按结果分级
（全成功 Info、部分失败 Warn、全失败 Error）。

### 28.5 失败语义与文案

注册调用复用 §27 的错误分类：5xx / 超时 → 可重试（下一轮对账会重试）；
400 → 不可重试（报文问题，重试一百次一样）。

顺手修了一处**会误导排障**的文案：`translateTransportError` 原先用
`errs.Wrap(..., err)`，把 httpx 的 "PROVIDER.UNAVAILABLE: 无法连接三方平台"
一起带了出来。登录链路里它只进日志还好；但同步失败原因会落进
`applications.uc_sync_error` 并显示在管理端——让运维在"用户中心同步失败"下面
读到"三方平台"，等于把方向带偏。现在改成新建干净错误
（`用户中心不可用（连接失败）`），原始原因只进 details。

### 28.6 测试

| 位置 | 例数 | 守住什么 |
| --- | --- | --- |
| `application/accountsync` | 11 | 停用应用也同步、单应用失败隔离、单次超时、**入队不阻塞**、回查最新状态、已删除应用跳过、无对端时 no-op、读列表失败报错、ctx 停止、状态映射（脏值按停用）、写状态失败不改变同步结论 |
| `application/adminapp` | 5 | 建应用通知一次、停用/改名也通知、无 notifier 时照常成功、写库失败不通知、视图带同步状态 |
| `infrastructure/account` | 7 | 报文形状（路径 / app_key / status / updated_at）、204 也算成功、空 app_key 与缺状态本地拦截、5xx 可重试、400 不可重试、**每次都真调用**（不本地记"已同步"） |
| `testsupport/mockusercenter` | 6 | 注册解锁登录、幂等 upsert（不新增租户）、非法报文拒绝、GET 405、停用状态只记录不拦截、故障注入可重试 |
| `test/acceptance` | 1 | 未注册 → 登录失败 → 对账 → 登录成功；`uc_synced_at` 写入；`updated_at` 不变 |

`TestRegisterAppReplaysEveryTime` 值得单独说：它断言"连调三次就是三次请求"。
如果哪天为了省流量加了"同步过就跳过"的本地缓存，这条会红——而那个优化的代价是
**远端漂移永远修不回来**，现象是"管理端显示已同步，登录却 APP.UNKNOWN"。

### 28.7 实机验证（2026-11-02）

容器内镜像重建，`00007` 迁移执行；`applications` 新增两列（`\d` 核对）。

真正验的是"两个进程 + 一个真实进程"的组合：本地起服务
（`SOCIAL_LOGIN_ACCOUNT_PROVIDER=http`、`base_url` 指向假对端、`sync.interval=10s`），
假对端以 `-require-apps` 启动（初始零应用）。

| 场景 | 结果 |
| --- | --- |
| 启动即对账 | **241 / 241** 个应用写入 `uc_synced_at` |
| 时间戳语义 | `updated_at ≠ uc_synced_at`（同步没动业务时间） |
| 断开对端一轮 | 241 个应用记 `ACCOUNT.UNAVAILABLE: 用户中心不可用（连接失败）`，**`uc_synced_at` 保留** |
| 恢复对端一轮 | **0 个失败**（成功后清空错误，无需人工干预） |
| 管理端接口 | `GET /admin/v1/apps` 返回 `AccountSync{SyncedAt, LastError}` |
| 契约脚本 | 对假对端 **18 项全过**（新增第 0 步：自动注册被测应用） |

`scripts/acceptance-admin.sh`（17 步）与 `scripts/acceptance-claims.sh`（15 步）
回归全过。

### 28.8 仍未做

1. **停用应用是否由对端拒绝**（§12.3）：现在只把 `status=disabled` 同步过去，
   对端记录但不用它拦截；拦截仍在本服务侧（`applications.status` 检查）。
2. **指标**：`/metrics` 还没有 `uc_sync_failed` 这类 gauge。数据在库里
   （`count(*) where uc_sync_error is not null`），接一个 GaugeFunc 即可。
3. **同步失败的告警**：目前只有日志级别（全失败 Error）与管理端展示，
   没有接监控告警通道——与 §24.6 的告警缺口是同一件事。
4. **批量补注册脚本**：不需要单独写——全量对账本身就是补注册机制，
   启动一次即覆盖存量应用。

---

## 29. 用户中心 MVP 实现（2026-11-02）

前 28 节里，用户中心始终是"契约 + 假对端"：`account.provider=http` 这条路径
只被 `internal/testsupport/mockusercenter` 验过，账号实际落在哪里从未有过第二种答案。
本节记录真正的对端交付——它让 §23/§26/§27/§28 的四条"等对端"结论全部落地。

方案依据：`docs/user-center-mvp-design.md`（§3 五张表、§4 五个端点、§5 并发语义）。

### 29.1 交付范围（P0）

| 项 | 位置 |
| --- | --- |
| 独立二进制 | `cmd/usercenter`（另一个服务，不是 social-login 的子命令） |
| 分层代码 | `internal/usercenter/{config,domain,cryptox,store/postgres,service,httpapi,observe,app}` |
| 迁移 | `migrations/usercenter/00001_init.sql`（独立 embed FS 与独立库 `user_center`） |
| 配置 | `configs/usercenter.yaml`（环境变量前缀 `UC_`） |
| 本地启动 | `scripts/dev-usercenter.sh`、`make uc-run`、compose 的 `usercenter` 服务 |
| 联调验收 | `test/acceptance/account_http_real_test.go`（`TEST_USER_CENTER_URL` 触发） |
| 集成测试 | `internal/usercenter/service/integration_test.go`（`TEST_USER_CENTER_DSN` 触发） |

五个对外端点 + 应用注册，全部按契约 v1.1：
`GET /accounts/{id}`、`GET /accounts/by-claim`、`POST /accounts`、
`POST /accounts/merge`、`PUT /accounts/{id}/claims/{type}`、`POST /internal/v1/apps`。

### 29.2 三处与设计文档的偏离

写在代码注释里也写在设计文档 §14.2，这里只列结论：

1. **Merge 的幂等键只落在 `merges` 表**，不再往 `idempotency_keys` 写一份。
   两处都记会出现"一处成功、一处失败"，而流水表本来就是幂等键的天然宿主。
2. **幂等快照只存 `{"user_id":"..."}`**，重放时按 id 重读当前状态。
   存完整账号报文会让幂等表变成第二份凭证明文/密文，而它恰恰是排障时被直接 query 的地方。
3. **`merges` 只记成功的合并**（取消 `status` 列）。被拒绝的合并没有副作用，
   重放时重新判定；写进去会让重放返回 `already_merged=true`，而那次调用什么都没合并。

### 29.3 验收数据

| 检查 | 结果 |
| --- | --- |
| `scripts/check-usercenter-contract.sh http://127.0.0.1:8099 <token> --app a --app2 b --write` | **18 项全过，0 警告** |
| `go test ./test/acceptance/`（含 `TEST_USER_CENTER_URL`） | 全过；其中真实 UC 两项：登录 302 且绑定写入 UC 的 ULID、未注册应用登录被拒 |
| `go test ./internal/usercenter/...`（含 `TEST_USER_CENTER_DSN`） | 13 个集成用例通过（连真 PG） |
| 并发：10 同键 Create | 1 个账号，其余返回同一 `user_id` |
| 并发：10 同凭证不同键 Create | 1 个 201，9 个 `CLAIM_TAKEN` |
| 并发：A→B 与 B→A 同时 Merge | 无死锁，恰好 1 个 `merged=true`，另一个 `already_merged` |
| 手工边界 | 无 token 401、未知应用 400 `APP.UNKNOWN`、停用应用 403 `APP.DISABLED`、非法类型 400 |

两个在测试里被真实抓到的缺陷（值得记下来，因为它们都不会在"顺利路径"里暴露）：

1. **哈希拼接歧义**：`("a","\x00b")` 与 `("a\x00","b")` 在 NUL 分隔方案下产生同一哈希。
   改成长度前缀布局后由 `TestHashRejectsSeparatorCollision` 守住。
2. **测试自身用 `ULID()[:6]` 做租户后缀**：ULID 前 48 位是时间戳，同进程内连续调用
   前缀几乎相同，导致多个用例共用一个应用、数据互相污染（表现为"刚建的号查不到凭证"）。
   改用完整 ULID。

### 29.4 由此解锁 / 仍需跟进

解锁：

- §23 遗留的"对端强一致读、幂等实现、跨应用隔离"三项，现在有真实实现可验。
- §28 的注册同步不再只是打到假对端：`appsync` 指向 `usercenter` 即可真跑（compose 里
  `ACCOUNT_PROVIDER=http` 就是这条链路）。

仍待跟进（与设计文档 §10 的分期一致）：

1. **P0.5**：审计日志、慢查询与连接池调优、`uc_sync_failed` gauge。
2. **P1**：`ClaimReplacer` 接登录链路（识别平台侧手机号变更）、UC 停用状态与
   social-login 的注销流程对齐顺序、换绑 24h 回滚窗口。
3. **运维**：`usercenter` 尚未接入告警；当前只有 `/metrics` 与 `/readyz`。
4. **数据清理**：契约脚本与联调会在 UC 侧留下测试租户（`app_contract_*`）
   与测试账号，契约本身没有 DELETE 接口，需要时直接按 app_key 清理。

---

## 30. 服务边界护栏（2026-11-02）

同仓库、同 module 的代价是"顺手 import 一下"几乎没有摩擦。规则一旦只写在
文档里，就会在某次赶进度时被破掉，而且破掉的那一刻没人知道——CI 只会说
"某处类型不匹配"。所以把它变成了可执行的检查。

**规则**：同一仓库、同一 `go.mod`、共用 `internal/pkg` 通用工具；两个服务的
业务代码零相互依赖。完整规则（含 `pkg` 下哪些不算通用）见
`docs/user-center-mvp-design.md` §15。

**落地**：`scripts/check-service-boundary.sh`（`make boundary`，已挂进 `make lint`）。
三层检查：传递依赖（`go list -deps`，抓间接引用）、直接 import（grep，含 `_test.go`）、
交叉点白名单。

**本次清理的一处违规**：`internal/usercenter/domain/errs_test.go` 曾 import
`internal/infrastructure/account` 与 `internal/testsupport/mockusercenter`
来断言三方错误码一致。已搬到 `test/contract/usercenter_codes_test.go`——
`test/` 不参与任何服务的构建，是唯一豁免区。原文件只保留本服务的
「错误码字面量锁定」与「状态码/可重试性不变量」。

**负向验证**（不做这一步的检查等于假护栏）：

| 注入的违规 | 退出码 | 是否抓到 |
| --- | --- | --- |
| 用户中心 import `infrastructure/account` | 1 | ✅ 传递依赖 + 直接 import 各报一处 |
| 登录中心 import `usercenter/domain` | 1 | ✅ 同上 |
| 用户中心 import `pkg/errs`（伪通用包） | 1 | ✅ |

清理后 `exit 0`，`go test ./test/contract/` 通过。

---

## 31. 本地容器化双服务部署验证（2026-11-02）

前面 §29 的验收都在"本机进程 + 容器里的 PG/Redis"下完成；§30 之后补做了一次
**两个服务都跑在容器里**的验证，因为部署形态本身也会出问题（网络、健康检查、
启动顺序），这些在单进程测试里永远不会暴露。

### 31.1 形态

```
pg(healthy) ─► uc-db(一次性) ─► usercenter(healthy) ─┐
             ├─► migrate ─► adminseed ──────────────┴─► app(healthy)
redis(healthy) ───────────────────────────────────────┘
```

```bash
ACCOUNT_PROVIDER=http docker compose up -d
```

| 服务 | 地址 | 账号数据 |
| --- | --- | --- |
| social-login | http://localhost:8080/admin | 无 `accounts` 表（remote 模式） |
| usercenter | http://localhost:8099 | `user_center` 库 |

### 31.2 验证结果

| 检查 | 结果 |
| --- | --- |
| 冷启动顺序 | `usercenter` 先 healthy，`app` 才启动 |
| 启动即对账 | `应用注册对账完成 {"total":292,"succeeded":292}` |
| 概览接口 | `apps_count=292`、`account_center{provider:"http",production_ready:true}` |
| 真实登录（容器内跨服务） | 授权 302 → 平台回调 → 302 带 `code=ac_…`；UC 建号、登录中心写绑定 |
| 绑定与账号一致 | `oauth_bindings.external_user_id` == `accounts.public_id`（ULID 逐位相同） |
| 重复登录 | 两次登录后 UC 账号数仍为 1、绑定数仍为 1 |
| 对端停机（新用户） | `ACCOUNT.UNAVAILABLE` + `retryable=true`（不是 500，也不静默建号） |
| 对端停机（老用户） | 仍可登录——绑定在登录中心，不依赖对端；**也意味着 UC 侧的停用不会拦住老用户**（§12.3 的已知空档） |
| 对端恢复 | 新用户登录立即成功，UC 建号 |
| 契约脚本（对容器内 UC） | 18 项全过，0 警告 |
| `go test ./test/...`（指向容器 UC） | 全过 |

### 31.3 本次修掉的一个部署陷阱

`app` 原先不依赖 `usercenter`。冷启动时若 `app` 先就绪，启动对账会失败，
要等 5 分钟一次的全量重放才自愈；这 5 分钟里所有登录都返回 `APP.UNKNOWN`，
而错误文案指向"应用不存在"——几乎没人会联想到"对端还没起来"。
现在 `app` 声明 `usercenter: condition: service_healthy`。

### 31.4 复现步骤（含 mock 平台）

```bash
# 1) 两个服务
ACCOUNT_PROVIDER=http docker compose up -d

# 2) 假的 OAuth2 平台（容器通过 host.docker.internal 访问它）
go run ./cmd/mockoauth2 -addr 0.0.0.0:9090

# 3) 写联调应用与渠道配置（注意连的是 compose 的 PG 与容器同一把主密钥）
SOCIAL_LOGIN_DATABASE_DSN='postgres://postgres:postgres@127.0.0.1:15432/social_login?sslmode=disable' \
SOCIAL_LOGIN_SECURITY_MASTER_KEY='+CCIh0DbO4eCpxQ0BB8wmuk0/bjR0XU8oOR/VvLNInc=' \
go run ./cmd/seed -config configs/config.yaml -app-code app_e2e_uc \
  -redirect-uri http://127.0.0.1:3000/callback \
  -oauth2-base-url http://127.0.0.1:9090 -on-unbound-login auto_create -merge-mode manual

# 4) token/userinfo 改成容器可达地址（authorize 留给浏览器/curl 用 127.0.0.1）
#    UPDATE app_provider_configs SET extra = jsonb_set(... 'host.docker.internal:9090' ...)

# 5) 让登录服务重新对账（把新应用推给 UC），然后走 /v1/authorize → 平台 → /v1/oauth/callback
```

两个注意点，都是踩过的：

- `cmd/seed` 用的主密钥必须与容器一致，否则渠道凭据解不开，回调报"解密失败"。
- 渠道配置里 `authorize_url` 走 127.0.0.1（浏览器侧），`token_url`/`userinfo_url`
  走 `host.docker.internal`（容器侧）。同一个 base_url 在两种视角下是不通的。

---

## 32. 三处"静默出事"的缺口补齐（2026-11-02）

§25 复核后挑了三件事，共同标准是**失败时不报错、只表现为用户登不进来或封禁不生效**：

1. 已绑定用户的登录路径完全不问用户中心（封禁不生效、换号不同步）；
2. 只有 app×IP 一档限流（分布式撞库拦不住）；
3. 指标躺在 `/metrics` 里，没有一条告警表达式。

### 32.1 绑定路径回源核对（`accountgate.go`）

主路径 `FindActiveByIdentity` 命中后，此前直接签令牌，一次都不问用户中心。
补上之后做两件事：

| 动作 | 失败时 |
| --- | --- |
| 按 `user_id` 查账号，状态非 `active` → 拒绝 | 返回 `AUTH.FORBIDDEN`（不可重试） |
| 平台本次返回的凭证与账号现值不同 → 调 `PUT .../claims/{type}` 换绑 | 不阻断登录，只 Warn |

三个判断写进了代码注释，也都是刻意选择：

- **"查不到账号"与"查不了"分开处理**。前者是确定答案（本地有绑定、对端没这个人），
  必须拒绝；后者是对端不可用，按配置决定。
- **对端不可用默认拒绝**（架构 §6.2）。这是本次唯一**降低可用性**的改动：
  对端故障时所有登录都会 `ACCOUNT.UNAVAILABLE`。想要可用性优先的部署，
  打开 `account.gate.allow_on_unavailable`，代价是对端故障窗口内已封禁账号也能登录。
- **换绑失败不阻断登录**。新号码在别人名下时，拒绝登录会让用户既进不去、
  又不知道号码在谁那里；让能登的人登进来、数据交给人工修更合适。

桩模式下整个闸门关闭（`Enabled: provider == "http"`）：桩的账号在进程内存里，
重启即空，开闸会把每个有绑定的老用户都判成 `ACCOUNT.NOT_FOUND`——那不是发现
了数据分叉，是桩模式本身的语义。

### 32.2 `rl:identity` 身份维度限流

位置不在中间件，而在授权流程内部（`Identities.Upsert` 之后）：中间件只能看到
app + IP，identityID 要等平台返回 open_id 才有。代价是平台调用已经发生，
收益是它拦在凭据入库、用户中心调用与签发令牌之前。

- 抽出 `internal/pkg/ratelimit`（固定窗口 + 窗口号进 key + fail-open），
  接入层的 `middleware/ratelimit.go` 与新的 `infrastructure/ratelimit` 共用它。
- 阈值 30 次/分钟/身份：正常用户不可能一分钟完成 30 次完整授权往返。
- 超限返回 `RATE.LIMITED` 而不是 `PROVIDER.REJECTED`——调用方要知道"等一会儿能成"。

### 32.3 指标与告警

新增两个 gauge（`social_login_uc_sync_failed` / `social_login_apps_total`）
与 `deploy/prometheus/alerts.yaml`（6 条规则）：死信、积压、合并滞后、漂移未闭环、
同步失败、全量同步失败。

`uc_sync_failed` 用**采集时查库**而不是失败时 `Inc`：需要的是"当前还坏着几个"，
而计数器只增不减，告警会因为历史失败一直 firing。`apps_total` 存在的唯一理由是
给前一行做分母——"挂了一个"和"全挂了"的处置完全不同。

### 32.4 验收（容器内实跑，`ACCOUNT_PROVIDER=http`）

| 场景 | 结果 |
| --- | --- |
| 老用户正常登录（闸门开启） | 302 带 `code=ac_…` |
| 同邮箱重复登录 | 无第二次换绑（换绑日志恒为 1 条） |
| 平台侧邮箱变更 | 换绑执行：日志 + 用户中心 `PUT .../claims/:type` 200 |
| 账号被置为 `frozen` | `AUTH.FORBIDDEN`「该账号已被停用或注销」 |
| 对端停机（默认 strict） | `ACCOUNT.UNAVAILABLE` + `retryable=true` |
| 对端停机（`allow_on_unavailable=true`） | 登录成功，Warn 记录"按配置放行" |
| 身份限流 2/分钟，连打 3 次 | 前 2 次成功，第 3 次 `RATE.LIMITED` |
| 注入一条 `uc_sync_error` | `social_login_uc_sync_failed` 0 → 1 → 清理后 0 |
| 单元测试 | `pkg/ratelimit` 5 项、`infrastructure/ratelimit` 5 项、`authflow` 闸门 10 项全过 |
| `go test ./internal/... ./test/contract/` + 边界检查 | 全过，`exit 0` |

### 32.5 仍未做（与 §25 一致）

`rl:platform:day`（A 组唯一剩余项）、注销的完整链路、`Unbind` 平台侧接线、
KMS、tracing、`ScopeAppID` 鉴权、双人复核、配置热更新。
告警规则已写，但 Alertmanager 的接收端（邮件/IM）属于部署侧，未接。

---

## 33. 清空上线阻塞项：渠道日配额与管理员账号管理（2026-11-02）

§32 之后剩下的上线阻塞项只有 `rl:platform:day`。这一轮把它做掉，并顺带补了
B 组里最"该有却没有"的一项——管理员账号管理。做完之后 A 组第一次归零。

### 33.1 `rl:platform:day`：渠道日配额

所有三方渠道都有日调用上限。不预拦时，超限表现为渠道直接报错，用户看到的是
"登录失败"——一个本可解释的状态（今天额度用完了）被翻译成了"这个应用坏了"，
而且超限期间每次请求还在继续打平台，白白消耗重试预算。

实现上有三个判断：

| 决定 | 理由 |
| --- | --- |
| 复用固定窗口，新增 `AllowDaily` | 日配额自己写一套 TTL，很容易在"跨零点"上与分钟窗口行为分叉，而那种 bug 一年只暴露两次 |
| 日期用**服务器本地时区** | "今天还剩多少额度"是运维按业务时区理解的；多实例必须时区一致，否则同一渠道的配额被拆成两段 |
| 超限返回 `PROVIDER.QUOTA_EXCEEDED` 且**不排队** | 排队会把请求堆在内存里，配额恢复瞬间形成尖峰；且它与 `RATE.LIMITED` 的处置完全不同（前者扩配额/换渠道，后者重试即可） |

拦截点在 `Callback` 的 Exchange **之前**：配额已经用尽时再打平台没有收益。
未配置的渠道取 `platform_daily_default`，0 表示不限（默认值），因此升级本身
不会改变任何现网行为。

### 33.2 管理员账号管理

在这之前加人只能 `cmd/adminseed` 或直接改库：没有校验、没有审计、没有护栏。

| 能力 | 端点 | 说明 |
| --- | --- | --- |
| 列表 | `GET /admin/v1/admins` | 不含 password_hash（列表会被导出、截图、贴进工单） |
| 创建 | `POST /admin/v1/admins` | 用户名 `[A-Za-z0-9_.-]{3,64}`、密码 ≥8、角色合法、reason 必填 |
| 修改 | `PATCH /admin/v1/admins/:id` | 显示名/角色/启用状态，同样 reason 必填 |
| 重置密码 | `POST /admin/v1/admins/:id/password` | 由超管执行；成功后**撤销该账号全部会话** |

三条护栏，都是"不写就会以事故形式被发现"的：

1. **不能改自己的角色、不能停用自己** —— 一次手滑就把自己锁在门外，恢复只能改库。
2. **不能移除最后一个启用中的 super_admin** —— 同上，且整个管理端会再无人能改配置。
3. **重置密码与停用必须撤销会话** —— 只改库不撤会话等于没改：对方手里的 token
   还能继续用满 8 小时，"已经止损"是错觉。

权限只给 super_admin：`admin:read` / `admin:write` 没有写进任何角色的权限表，
只有通配 `*` 覆盖它们。能给自己加账号的人，等于能给自己加权限。

`reason` 必填是沿用项目对高危写操作的既有约定（K 组撤权、I 组熔断复位）。
第一次实现时漏了它，表现为审计写入报 `REQUEST.INVALID: audit event.reason 不能为空`，
而这条错误被 `writeAudit` 的 warn 吞掉了——**审计静默失败**，正是这个功能最不该有的失败模式。

### 33.3 为什么这轮没做 `Unbind` 平台侧解绑

做之前先查了凭据：`providerSource.Revoke` → 各适配器的 `Unbind`，只有 Apple 有真实实现，
且它必须拿到渠道的 **refresh_token**（`req.Extra["refresh_token"]`）。而本服务
从来不持久化平台令牌——`exchange` 完就把 token 丢掉，库里只有我们自己的
`refresh_tokens`（发给业务方的），没有渠道令牌。

也就是说：**即使把调用接上，所有渠道都会返回 NotSupported**，因为参数根本不存在。
接一个"必然走降级分支"的调用只是把假动作包装成实现。

真实撤销需要一个前置决策：**是否持久化渠道 refresh_token**。那是把"渠道用户凭据"
落进本服务的数据库，属于安全评审级别的问题（加密、留存期、谁能读、泄漏影响面），
不该在补一个 P1 的过程中顺手决定。所以这轮只把它记清楚，留给下一轮单独讨论。

### 33.4 验收（容器内实跑）

| 场景 | 结果 |
| --- | --- |
| 渠道日配额=1，连打两次 | 第 1 次成功；第 2 次 `PROVIDER.QUOTA_EXCEEDED` + `retryable=true` |
| 创建管理员 | 201，响应不含 password_hash |
| 新管理员登录 → `/auth/me` | 200，权限列表为 viewer 的 9 项 |
| 停用该管理员 | 200；其旧 token 立即 401 `ADMIN.SESSION_REVOKED`；再登录 401（不区分原因，防枚举） |
| 停用自己 | 403 `AUTH.FORBIDDEN`，`details.rule=no_self_lockout` |
| 重置密码 → 启用 → 新密码登录 | 200 / 200 / 拿到 token |
| operator 访问 `/admins` | 403 `权限不足: admin:read` |
| 无 reason 的写操作 | 400 `reason 必填（管理端写操作需要审计原因）` |
| 审计落库 | `admin.create` / `admin.update` / `admin.reset_password`，含 reason 与 target_id |
| 单元测试 | `adminuser` 15 项、`pkg/ratelimit` 日窗口 2 项、`infrastructure/ratelimit` 配额 6 项全过 |
| `go test ./internal/... ./test/contract/` + 边界检查 | 全过，`exit 0` |

### 33.5 接口变更（对使用方）

- 新增 `/admin/v1/admins` 一族端点，仅 super_admin 可访问。
- `admin.UserRepository` / `admin.SessionRepository` 各新增方法（`List`、`UpdateProfile`、
  `CountEnabledSuperAdmins`、`RevokeAllByUser`）。**这是对接口的破坏性扩展**——
  所有测试替身都要补实现，本轮已补 4 处。

### 33.6 仍未做

B 组剩 4 项：账号注销编排、`Unbind` 平台侧（受阻于凭据决策）、KMS、tracing。
C 组 6 项与用户中心 P1/P2 见 §25。

---

## 34. 账号注销编排（2026-11-04）

§25 B 组的第一项。用户中心侧早就有一个原子动作（`accounts/{id}/close`），
缺的一直是登录侧编排——绑定、令牌、凭证密文都在这边。（§33.3 里 `Unbind` 那项
单独说，两者不是一回事。）

### 34.1 顺序：先关对端，再清本地

```
用户中心 close  →  级联解绑  →  撤销 refresh_token  →  写撤销水位  →  删除凭证密文
```

这个顺序不是风格问题。反过来的话，中途失败会留下"对端 active、本地已无绑定"，
用户下次用同一个微信登录会走未绑定分支、自动创建一个新账号——他以为自己注销了，
实际得到的是"旧数据还在、外加一个空账号"。

按现在的顺序，失败最坏是"对端已 closed、本地绑定还在"，此时登录会被状态闸门
拦下（§32.1），不会复活，重试即可补齐。

### 34.2 端点与调用方

`POST /v1/account/close`，挂在**用户端点组**（AppAuth + UserAuth），请求体
`{"confirm": true, "reason": "..."}`。

`confirm` 必填是刻意的：注销不可逆，而它最可能的误触发方式是"业务方把某个按钮
接错了接口"——那种调用不会带这个字段。成本几乎为零，却能把误调用与真实意愿分开。

架构 §10.2 写的是"由用户中心发起、本服务提供内部接口配合"。这轮**没有**按那个
方向做，原因：用户中心目前没有反向调用本服务的能力（它不持有我们的服务令牌），
做一个没有调用方的内部接口就是死代码。等对端具备回调能力时再补，见 §34.6。

### 34.3 把"三方撤销"降级成提示，而不是假装调用

架构要求"级联解绑时调用 `Provider.Unbind` 撤销三方授权"。没做，理由与 §33.3 同源：
本服务从不持久化渠道的 refresh_token，各适配器的 `Unbind` 必然返回 NotSupported。
调一次拿个已知的失败，再落到"请手动撤销"分支——结论与用户完全一致，只是多了一层
"我们尽力了"的假象。

所以响应里直接给可操作的提示（按平台给出具体菜单路径）：

```json
{"warnings":[{"code":"unbind_manual_required","platform":"wechat",
  "message":"请在微信「我 → 设置 → 隐私 → 授权管理」中取消对本应用的授权"}]}
```

### 34.4 实测抓到的两个缺陷

**① 注销走了错误的前缀，而 404 被当成"已注销"**

首版按业务契约拼成 `/v1/apps/{key}/accounts/{id}/close`，但对端把注销挂在
`/internal/v1/...` 下（内部接口，网关上只对内开放）。对端返回 404，适配层把
404 译成 `ErrNotFound`，而我在业务上又需要"账号本就不存在 ⇒ 视为已注销"的幂等
语义——两者一撞，结果是：**本地数据清干净了、响应 200、对端账号仍是 active**。

如果不是把两侧数据库都查了一遍，这个 bug 会一路走到生产：用户看到"已注销"，
数据其实还在用户中心。

修法是两条一起：
- 路径改用 `/internal/v1`，并与业务路径分成两个常量（`pathPrefix` /
  `pathPrefixInternal`），避免下次顺手用错；
- **裸 404 不再当成功**。只有带 `ACCOUNT.NOT_FOUND` 信封的 404 才算"本来就没有"；
  没有信封的 404 一律报 `ACCOUNT.UNAVAILABLE`「用户中心未提供注销接口」。
  回归用例：`TestCloseRejectsBareNotFound`。

**② 注销后再登录，被重新绑回那个已注销的账号**

`auto_create` 分支的幂等键是 `first_login:{app}:{identityID}`，固定可推导。
注销之后用户再登录，`Create` 按幂等键重放——返回的正是那个 closed 账号，
代码不看状态直接激活绑定。表现是：登录"成功"、拿到授权码，但账号是 closed，
后续凡是要用户中心参与的操作全被闸门拒绝，而且**每次登录都重复这一遍**
（幂等键不变 ⇒ 永远拿到同一个死账号）。

修法是按状态分流：

| 返回状态 | 处理 | 理由 |
| --- | --- | --- |
| `active` | 正常绑定 | — |
| `closed` | 换幂等键重建账号 | "注销后再注册"与"从未注册"在产品上是同一件事 |
| `frozen` 等 | 拒绝（`AUTH.FORBIDDEN`） | 冻结是管理动作，不能靠"再登录一次"绕过 |

新幂等键 = `first_login:{app}:{identity}:after:{closedUserID}`。不用时间戳
（并发同一次登录会算出不同键、建出两个账号），不用随机数（没有幂等可言），
用 closed 账号 id：同一轮重试恒定，每次注销后又会变。

回归用例：`TestAutoCreateRecreatesAfterClosed` / `TestAutoCreateRejectsFrozen`。

### 34.5 一个必须说清的残留窗口

注销后 **access_token 最长还能用 15 分钟**——只在本服务自己的用户端点与业务方
的本地验签上。

实测（容器内）：

| 请求 | 结果 |
| --- | --- |
| 注销后 `/v1/userinfo`（本地验签） | 200 |
| 注销后 `/v1/introspect`（`check_revocation` 缺省） | `active=true` |
| 注销后 `/v1/introspect?check_revocation=true` | `active=false` |

也就是说撤销水位是真的写进去了，只是**只有主动查水位的消费方会看到**。
没把检查塞进用户端点的原因是：那等于给每个用户请求加一次 Redis 往返，并让
Redis 故障直接变成"用户接口全 500"；而这段时间里令牌能做的事只有读自己那份
已被清空的绑定。要更严的做法（把水位检查做成默认）随时可加，但那是一次
可用性与安全性的交易，不该顺手做。

`refresh_token` 没有这个窗口——它在库里被撤销，换不出新令牌。

### 34.6 已知未做

- **UC 主动发起注销的反向链路**：若账号在用户中心侧被别的入口关闭，本地绑定
  会残留到下一次登录时才被状态闸门拦下。需要用户中心具备回调本服务的能力。
- **冷静期/可恢复窗口**：现在是立即且不可逆。合规要求"及时删除"，立即满足；
  冷静期是产品偏好，需要 tombstone 表 + 到期清理任务，另做。
- **`identity_claims` 之外的身份资料**：`oauth_identities.profile_snapshot`
  （昵称/头像）仍在。它不是联系方式，但属于个人信息，是否一并清理由产品定
  （清掉会让"同一个人再次登录"失去历史资料，也可能影响风控）。

### 34.7 验收（容器内实跑，`ACCOUNT_PROVIDER=http`）

| 场景 | 结果 |
| --- | --- |
| 未带 `confirm` 的注销 | 400 `REQUEST.INVALID`，`details.field=confirm` |
| 正常注销 | 200：`closed_bindings=1, revoked_tokens=1, purged_claims=1` + 一条 `unbind_manual_required` |
| 用户中心账号状态 | `active → closed`，其凭证全部撤销 |
| 本地绑定 | `active → unbound`（历史行保留） |
| 本地凭证密文 | 删除（该身份下 0 行） |
| refresh_token | 0 active / 1 total |
| 重复注销 | 200 幂等，各项计数为 0 |
| 注销后重登（修复后） | 建**新**账号并绑到新账号；旧账号仍 closed |
| 审计 | `account.close`，含 closed_bindings / revoked_tokens / purged_claims 与 reason |
| 契约脚本 | 加入注销两项（路径正确 + 幂等），**20 项全过** |
| 单元测试 | `accountclose` 8 项、`authflow` 注销后重建 4 项、适配层 4 项全过 |
| `go test ./internal/... ./test/contract/` + 边界检查 | 全过，`exit 0` |

### 34.8 接口变更（对使用方）

- 新增 `POST /v1/account/close`（用户端点组）。
- `account.Provider` 未变；新增**可选**端口 `account.AccountCloser`，
  由 HTTP 与桩实现各自实现。对端不支持时整体拒绝，不做"只清本地"。
- `identity.ClaimRepository` 新增 `PurgeByIdentities`（破坏性扩展，
  2 处测试替身已补）。

---

## 35. KMS 信封加密（2026-11-04）

§25 B 组的第二项，也是我此前标为"越晚做迁移面越大"的那一项。

### 35.1 之前那个不是信封

`KeyManager` 一直叫"信封加密"，但实现是**用主密钥直接加密数据**——没有 DEK。
注释里也写明了（"schema 里只有 secret_dek_id 一列，因此本实现用主密钥 + kid
表达密钥版本"），所以 `secret_dek_id` 存的是 KEK 的 id，不是数据密钥的 id。

后果不在安全性上（AES-GCM 本身没问题），而在**轮换**：换密钥 = 把所有密文解密
再加密一遍。数据越多越贵、越不敢动，而"不敢轮换"本身就是一种风险积累。

### 35.2 现在的分层

```
KEK（KMS 或本地主密钥） ──包装──► DEK（每行一把，随机）
DEK                    ──加密──► 凭据明文
```

密文格式（v2）：

```
"SLK2" | dekLen(uint16) | wrappedDEK | nonce(12) | ciphertext+tag
```

三个刻意的决定：

| 决定 | 理由 |
| --- | --- |
| 每行一把 DEK | 一条记录泄漏不牵连其它记录；轮换 KEK 只需重包 32 字节 |
| 数据 AAD 不含 keyID | 否则轮换 KEK 时数据密文必须重算，"只换包装"的收益归零 |
| 用 4 字节魔数区分 v1/v2 | 不需要加列、不需要停机；v1 首字节是随机 nonce，撞车概率 2⁻³²，且撞了还有回退兜底 |

### 35.3 两个实现，一个端口

`crypto.KEK` 只有三个方法（`KeyID` / `Wrap` / `Unwrap`）：

- `LocalKEK`：主密钥在配置里，AES-256-GCM 包装 DEK。开发与过渡形态。
- `RemoteKEK`：调 KMS 网关的两个动作。契约是一层薄 HTTP，不引任何厂商 SDK：

```
POST {base}/v1/wrap    {"key_id","plaintext"(b64)} → {"wrapped"(b64)}
POST {base}/v1/unwrap  {"key_id","wrapped"(b64)}   → {"plaintext"(b64)}
```

AWS KMS、阿里云 KMS、Vault Transit 都能一对一映射到这两个动作。引 SDK 会把某家
厂商的类型、重试策略、依赖树带进登录服务，而真正要验的只是这两个动作对不对。

`cmd/mockkms`（`internal/testsupport/mockkms`）是它的可执行版本，支持 `-master-key`
固定密钥——**假 KMS 每次重启换密钥是个陷阱**：那样"KMS 密钥丢失"这种最严重的
故障会被演示成日常操作，用它迁过的密文全部解不开。（这不是假设，本轮踩了一次。）

### 35.4 DEK 缓存：不是优化，是可用性

渠道凭据在**每次登录**都要解密。若每次都问 KMS（往返 5–20ms），等于把 KMS
变成登录链路上的同步依赖。

`Options.DEKCacheTTL` 缓存解包后的 DEK（默认 5 分钟、上限 512 条，按 wrappedDEK
的哈希作键）。实测效果（mockkms 的 `/stats`）：

| 操作 | unwrap 调用数 |
| --- | --- |
| 第一次登录 | 1 |
| 第二次登录（同一渠道配置） | 仍是 1 |

只缓存 DEK、不缓存明文：DEK 泄漏只影响一条记录，而缓存明文会把凭据的可读窗口从
"一次调用"拉长到"一个 TTL"。

本地 KEK 不启用缓存——解包只是一次 AES，缓存省不下什么，却让数据密钥在内存里
多存一个 TTL。

### 35.5 迁移工具：`cmd/keyrewrap`

没有它，"换 KEK 只重包 DEK"只是句好话。用法：

```bash
# 只统计：多少行仍是 v1、多少行已是 v2
go run ./cmd/keyrewrap -config configs/config.yaml -dry-run

# 本地 KEK 换版本 / v1→v2 升级
go run ./cmd/keyrewrap -config configs/config.yaml \
  -from-master-key "<旧主密钥>" -from-kek-id local-kek-v1

# 迁到 KMS：目标 KEK 取配置里的 security.kms
```

三条安全属性：

1. **先验证能解开再写回**。`rewrapOne` 先用源 KEK 解一次；解不开就跳过并报哪一行，
   绝不覆盖。本轮在一个有 396 行的库上实测：48 行成功、**348 行被拒绝**——那些行
   是历次验收测试用临时主密钥写入的残留，任何版本的服务都解不开。工具没有把它们
   覆盖成垃圾，这是"批量工具"最该守住的一条。
2. **幂等**。已是 v2 且源/目标 KEK 相同的行直接跳过，可以反复执行（运维最常做的
   就是"再跑一遍确认干净"）。实测第二遍：`已是 v2 48，迁移 0`。
3. **只读密文列**。唯一写操作是 UPDATE 密文两列 + dek_id；v1 升级路径才需要读出
   明文，用完即弃。

### 35.6 真机演练：本地 KEK → KMS → 回到本地

按"生产会怎么切"完整走了一遍（容器内，`ACCOUNT_PROVIDER=http`）：

| 步骤 | 结果 |
| --- | --- |
| 新版本 + 现有 v1 密文 | 登录正常（v1 兼容路径生效） |
| `keyrewrap -dry-run` | 48 行 v1、348 行解不开（历史测试残留） |
| `keyrewrap`（本地 KEK，v1→v2） | 48 行迁成 v2，密文头 `534c4b32`（"SLK2"） |
| v2 之后登录 | 正常 |
| `keyrewrap` 再跑一遍 | `已是 v2 48，迁移 0`（幂等） |
| `keyrewrap` 迁到 KMS（`-from-master-key`） | 48 行 rewrap，数据密文未变 |
| 服务以 KMS 模式启动（`KMS_ENABLED=true`） | 启动日志 `渠道凭据使用 KMS 托管密钥` |
| KMS 模式下登录 | 正常；`unwrap` 0→1，第二次登录仍是 1（缓存生效） |
| KMS 停机 + 清缓存后登录 | `INTERNAL.ERROR`「调用 KMS 失败（检查网络与地址）」+ `retryable=true`，`details.kms_path=/v1/unwrap` |
| KMS 恢复 | 登录立即正常 |
| 切回本地 KEK（重写渠道凭据） | 登录正常，`secret_dek_id=local-kek-v1` |

KMS 停机的错误文案刻意不写成"凭据解密失败"：那会让运维去查凭据内容，而真相是
依赖不可用。

### 35.7 顺带修掉的一处不一致

`cmd/seed` 原来自己构造 `LocalKEK`，与服务的装配逻辑各写一份。启用 KMS 后这会变成
"seed 用本地密钥写、服务用 KMS 读"——当场卡死且不好排查的错配。

现在三处（服务、seed、迁移工具）共用 `bootstrap.BuildKEK`。同时 `cmd/seed` 的
"必须配置 master_key"前置检查在 KMS 模式下不再误报。

### 35.8 仍未做

- **KMS 密钥轮换自动化**：工具能换，但没有定时任务与"旧 KEK 何时可下线"的判定。
  真实轮换还需要 KMS 侧的双版本并存期。
- **KMS 不可用时的降级**：现在是快速失败（登录 500）。备选是"缓存更久"或"双 KEK
  并行解密"，都属于可用性与安全的交易，不在本轮。
- **用户中心侧的信封**：`internal/usercenter/cryptox` 有自己的 AES-GCM 实现，
  主密钥来自 `UC_SECURITY_MASTER_KEY`。它是独立服务、独立库，本轮没有动它——
  两边共享的只是"信封"这个概念，不是代码（服务边界规则 §15）。
- **`secret_dek_id` 列名**：语义已从"主密钥版本"变成"包装 DEK 的 KEK"，列名没改。
  改列名要动两边服务与迁移，收益只是命名一致，留到下次表结构变更时一起做。
