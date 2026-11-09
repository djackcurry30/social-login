# 用户中心联调手册

> 适用代码：`internal/infrastructure/account/http.go`（客户端）、
> `internal/testsupport/mockusercenter`（契约的假实现）、
> `test/acceptance/account_http_test.go`（端到端验收）
> 最后更新：2026-11-02
> 结论先行：**契约 v1.1 已落地；对端（用户中心 P0）已于 2026-11-02 交付并通过真实联调。**

> ✅ **对端已交付（2026-11-02）**
> `cmd/usercenter` + `internal/usercenter/**` + `migrations/usercenter/00001_init.sql`。
> 契约检查 18 项全过；`test/acceptance/account_http_real_test.go` 已验证
> "登录 → 绑定写入对端 ULID → 按 id 回查对端" 全链路。
> 本文 §3 的接口要求现在有了参考实现；对端细节见
> `docs/user-center-mvp-design.md` §14 与 `docs/implementation-status.md` §29。
> 切到对端的方式：`account.provider=http` + `account.http.base_url`，
> 并确认应用已通过注册同步推到对端（未注册的应用一律 400 `APP.UNKNOWN`）。

> ✅ **契约已修订到 v1.1 并落地（2026-11-02）**
> v1 缺少应用维度，按它实现只能有一个全局账号空间，与 C1（账号按应用隔离）冲突。
> 现已全部改完：路径前缀 `/v1/apps/{app_key}/...`、统一错误信封、幂等进行中语义、
> 换绑端点、合并回传 `discarded_claims`。
> 改动落在 `internal/infrastructure/account/`（http + stub）、5 处调用点、
> `internal/testsupport/mockusercenter`（假对端同步升级）、
> `scripts/check-usercenter-contract.sh`（16 项体检）。
> **对端照 §3 实现即可，不要再按 v1 做。**

---

## 1. 一句话现状

本服务是 `remote` 账号模式（约束 C4）——**没有 `accounts` 表**，账号全在用户中心。
对端 P0 已交付，当前可选的运行形态：

| 配置 | 现状 | 后果 |
| --- | --- | --- |
| `account.provider: stub`（默认） | 账号存在**进程内存** | 重启即丢；与真实账号无任何关系；仅可演示 |
| `account.provider: http` | 已接真实用户中心并验收通过 | 生产形态；本地用 `ACCOUNT_PROVIDER=http docker compose up` |
| `server.mode: release` + `provider: stub` | **启动即失败** | 生产模式禁止桩实现（`bootstrap/config.go` 自检） |

管理端「观测看板」顶部现在有一条常驻标记，直接显示当前用的是哪种实现
（`/admin/v1/health/overview` 的 `account_center` 字段）——避免把内存桩
误读成"已经接上了"。

---

## 2. 进度标记

三档口径：

- ✅ **已完成并自测**：代码 + 自动化用例，可重复验证，不依赖对端
- 🟡 **已实现，待对端联调**：我方代码就绪，语义正确性取决于对端实现
- ⛔ **依赖对端设计**：对端连接口形态都还没定，现在无法开工

### 2.1 依赖对端能力的部分

> 2026-11-02 起对端已交付：下表"🟡 待联调"列的是**当初的**验证依赖，
> 现在均已在真实用户中心上跑通（证据见 §14 与 implementation-status §29）。
> 保留这张表是因为它记录了"每项能力依赖对端哪个接口"，后续改契约时仍要照它核对。

| # | 能力 | 用到的对端接口 | 状态 | 验证方式 |
| --- | --- | --- | --- | --- |
| 1 | 首次登录建号（`on_unbound_login=auto_create`） | `POST /accounts` | ✅ 自测通过 / 🟡 待联调 | `TestHTTPAccountProviderAutoCreate` |
| 2 | 建号幂等（重复首次登录不产生两个账号） | `POST /accounts` + `Idempotency-Key` | ✅ 我方必带 / 🟡 对端是否真去重 | `TestCreateIsIdempotent` + 契约脚本第 4 步 |
| 3 | 对端不提供建号时的降级 | 404 / 405 / 501 | ✅ 自测通过 | `TestHTTPAccountProviderCreateUnsupported` |
| 4 | 按凭证反查（回源核对 P0-6） | `GET /accounts/by-claim` | ✅ 协议映射 / ⛔ 强一致读实现 | 契约脚本第 5 步（写后立刻反查） |
| 5 | 命中多账号必须拒绝归并 | `by-claim` → 409 | ✅ 自测通过 | `TestGetByClaimOutcomes`、`TestMultiAccountFault` |
| 6 | 合并调用 | `POST /accounts/merge` | ✅ 协议映射 / 🟡 对端幂等 | `TestMergeMovesClaimsAndIsIdempotent` |
| 7 | 补偿重试（P0-3：远端成功、本地失败） | `merge` 同键重放 → `already_merged` | ✅ 假对端已验 / 🟡 真对端 | 同上第 2 段断言 |
| 8 | 合并目标账号校验（`verification`） | `GET /accounts/{id}` | ✅ | `merge/verification.go` 单测 |
| 9 | 对端不可用的降级（快速失败） | 5xx / 超时 | ✅ 自测通过 | `TestHTTPAccountProviderUnavailableFailsFast` |
| 10 | 对端限流 | 429 | ✅ 自测通过 | `TestHTTPAccountProviderRateLimited` |
| 11 | 服务间鉴权 | `Authorization: Bearer` | ✅ 客户端 / 🟡 对端是否要求 mTLS | `TestTokenRequired` |
| 11b | 应用注册（建号/登录的前置条件） | `POST /internal/v1/apps` | ✅ 我方同步已接通（即时 + 5 分钟对账）/ 🟡 对端幂等 | `accountsync` 11 例、`TestAppRegistrationReconcileUnlocksLogin`、契约脚本第 0 步 |
| 12 | 手机号变更主动失效 claim（`claim.invalidated`） | — | ⛔ 依赖对端设计 | 本侧接收端也未实现（见 §9） |
| 13 | 订阅 `account.merged` 做数据迁移 | — | ⛔ 依赖对端设计 | 本侧只发事件，不管对端怎么消费 |
| 14 | 账号注销（本侧发起、对端执行） | 契约未定义 | ⛔ 未设计 | 见 §9 |
| 15 | 账号标识不可枚举（ULID/UUID） | `user_id` 形态 | ⛔ 依赖对端 | 若用自增 id，事后迁移成本极高 |
| 16 | `identity_claims` 与对端全量对账 | 批量接口未定义 | ⛔ 未设计 | 属离线任务，量级与限流需单独设计 |

**统计**：17 项中 ✅ 12 项（含若干标了"待联调"的语义确认）、⛔ 5 项。
⛔ 的 5 项全部不是"我方写点代码就能完成"，都需要对端先给出接口形态。

### 2.2 不依赖对端、已闭环的部分（不在联调范围内）

| 内容 | 位置 |
| --- | --- |
| HTTP 客户端与错误码翻译（`PROVIDER.*` → `ACCOUNT.*`） | `infrastructure/account/http.go` |
| 超时默认 3s（登录链路预算 8s） | 同上 |
| 配置自检：空地址 / 错 scheme / 缺主机 启动即失败 | `NewHTTPProvider` |
| 生产模式禁止 stub | `bootstrap/config.go` §自检 |
| 账号体系状态标记（未落地时不伪装成正常） | `bootstrap/build.go: describeAccountCenter` |
| 契约的假实现（含故障注入） | `internal/testsupport/mockusercenter` |
| 端到端验收 4 例 | `test/acceptance/account_http_test.go` |
| 契约符合性检查脚本 | `scripts/check-usercenter-contract.sh` |

---

## 3. 契约 v1.1（对端需要实现的东西）

**这份契约由本服务定义**，不是去迁就对端现有接口。原因：本服务对这几个接口有硬性语义
要求（强一致读、幂等键、多账号必须报错、应用隔离），这些没法从"对方恰好有这么一个接口"推出来。

### 3.1 端点

所有业务路径都带应用前缀。`{app_key}` 取本服务的 `applications.app_code`。

| 方法 | 路径 | 成功 | 失败语义 |
| --- | --- | --- | --- |
| POST | `/internal/v1/apps` | 200/201/204 | 400 报文不合法；**幂等 upsert** |
| GET | `/v1/apps/{app_key}/accounts/{user_id}` | 200 账号 | 404 不存在 |
| GET | `/v1/apps/{app_key}/accounts/by-claim?type=&value=` | 200 账号 | 404 无账号持有；**409 `ACCOUNT.MULTIPLE`** |
| POST | `/v1/apps/{app_key}/accounts` | 200/201 账号 | 404/405/501（无码）不提供该能力；409 `ACCOUNT.CLAIM_TAKEN` |
| POST | `/v1/apps/{app_key}/accounts/merge` | 200 合并结果 | 404 任一端不存在；409 `ACCOUNT.MERGE_REJECTED` |
| PUT | `/v1/apps/{app_key}/accounts/{user_id}/claims/{claim_type}` | 200 账号 | 404 账号不存在；409 `ACCOUNT.CLAIM_TAKEN` |
| POST | `/internal/v1/apps/{app_key}/accounts/{user_id}/close` | 200 `{"user_id","status":"closed"}` | 404 + `ACCOUNT.NOT_FOUND` 账号不存在；**已 closed 重复调用必须仍 200** |

写操作（Create / Merge）**必须**带 `Idempotency-Key` 请求头。

**注销在 `/internal/v1` 下，不在 `/v1` 下**（它是内部接口，网关上只对内开放）。
这一条要单独强调，因为写错前缀的表现极具迷惑性：对端返回 404，而 404 与
"账号不存在"同码。本服务的适配层只把**带 `ACCOUNT.NOT_FOUND` 信封**的 404
当作"已注销"；没有信封的裸 404 一律报"对端未提供注销接口"。
（真实踩过：错用 `/v1` 时本地数据清空了、对端账号仍是 active、接口返回 200。
详见 implementation-status §34.4。）

**`/internal/v1/apps` 是服务间接口**：它不在应用前缀下（它本身就是"声明一个应用
存在"），由本服务的注册同步任务调用（建应用时立即一次 + 每 5 分钟全量重放）。
它必须幂等——对账会反复重放同一个 `app_key`；不幂等的实现会造出重复租户，
而重复租户在账号侧的表现是"用户被随机分到其中一份，另一半数据永远查不到"。

```json
POST /internal/v1/apps
{"app_key":"app_xxx","name":"应用一","status":"active","updated_at":"2026-11-02T10:00:00Z"}
```

`status` 只有 `active` / `disabled`。缺 status 时**必须拒绝**：默认成 active 会让
一个已停用的应用在对端被重新启用，而"停用"通常是安全或合规原因。

**为什么应用进路径而不是请求头**：请求头漏了 = 未知租户，每个端点都得记得拦，
日志与网关限流都看不见；路径漏了 = 404，不可能静默串租户。

**为什么 `app_key` 用 `app_code` 而不是本服务的 `applications.id`**：后者是本地自增
主键，换环境会重号，拿它当跨服务租户标识迟早出现"测试环境的 app 2 对应生产环境的
另一个业务"。

三套凭据不要混：

| 凭据 | 谁签发 | 给谁用 |
| --- | --- | --- |
| `app_code` | 登录中心管理端（不可变） | 业务方标识应用；**同时就是 UC 的 `app_key`** |
| `app_secret` | 登录中心管理端（仅创建返回一次） | 业务方调 `/v1/token`、`/v1/introspect` |
| 服务 token | 部署配置 | 本服务调 UC 的服务间鉴权（服务级） |

**UC 不签发任何凭据**，只认 `app_code` + 服务 token。

### 3.2 报文

```json
// 账号
{"user_id":"01H...","status":"active","claims":[{"type":"phone","value":"138...","source":"wechat_phone"}],"extra":{}}

// 合并结果
{"merged":true,"already_merged":false,
 "discarded_claims":[{"type":"phone","value":"138...","source":"alipay_phone"}],
 "remote_ref":{}}
```

- `status` ∈ `active` | `frozen` | `closed`，其他值我方直接拒绝（不会当成"非 active 跳过"）。
- `discarded_claims` 是合并时因"一个账号每类凭证只能有一条活跃"而被撤销的凭证。
  **不回传的话，用户对"我另一个手机号去哪了"完全无感知，客服也查不出来。**

### 3.3 错误信封与映射

失败响应统一带信封（成功响应不带）：

```json
{"code":"ACCOUNT.CLAIM_TAKEN","message":"该手机号已被占用","retryable":false}
```

适配层**优先按 `code` 翻译，状态码只作兜底**。原先只看状态码时，Create 上任何 409
都被译成"凭证已被占用"——一旦对端用 409 表达别的冲突（如幂等处理中），业务方看到的
原因就是错的。

| 对端返回 | 我方错误码 | retryable | 业务含义 |
| --- | --- | --- | --- |
| 200/201 | — | — | 正常 |
| 404 + `ACCOUNT.NOT_FOUND` | `ErrNotFound` | — | 账号/凭证不存在 |
| 409 + `ACCOUNT.MULTIPLE` | `ErrMultipleAccounts` | false | 数据唯一性已坏，**拒绝归并** |
| 409 + `ACCOUNT.CLAIM_TAKEN` | `BIND.IDENTITY_TAKEN` | false | 凭证被别的账号占用 |
| 409 + `ACCOUNT.MERGE_REJECTED` | `REQUEST.INVALID` | false | 合并被拒（如 target==source） |
| 409 + `ACCOUNT.IDEMPOTENCY_IN_PROGRESS` | `ACCOUNT.UNAVAILABLE` | **true** | 同键并发，稍后重试 |
| 404/405/501（**无 code**，仅 Create） | `ACCOUNT.NOT_SUPPORTED` | false | 对端不提供建号 |
| 400 + `APP.UNKNOWN` | `ACCOUNT.UNAVAILABLE` | false | **应用未注册**（不是"凭证被占用"） |
| 400 + `APP.DISABLED` | `ACCOUNT.UNAVAILABLE` | false | 应用已停用 |
| 429 | `RATE.LIMITED` | true | 我们超配额，不是对端故障 |
| 5xx / 超时 | `ACCOUNT.UNAVAILABLE` | true | 上游故障，本次登录失败 |
| 裸 409 / 裸 4xx（无 code） | `ACCOUNT.UNAVAILABLE` | false | 无法判定原因，**不猜** |

三条容易做错的：

1. **`APP.UNKNOWN` 必须用 400 不能用 409**——409 会被翻译成"该凭证已被占用"，
   运维会去查手机号，而真正的问题是应用没注册。
2. **Create 的 404 有双重含义**：路由不存在（= 不提供该能力）vs 资源不存在。
   判据是"有没有 `code`"：带码说明对端认识这个请求。
3. **5xx 时不要带业务 code**：适配层会让 5xx 优先于信封（它决定"要不要重试"），
   但带一个 `CLAIM_TAKEN` 会让排障的人看到互相矛盾的信息。

### 3.4 七条硬性要求

1. **`by-claim` 必须强一致读**（不能用延迟从库）。它是归并前最后一道防线（P0-6），
   读到旧数据等于防线失效。
2. **账号空间按 `app_key` 隔离**。同一个手机号在两个应用里必须是两个账号；
   跨应用 `Get` 必须 404，跨应用 `merge` 必须拒绝（R3）。
3. **`merge` 必须真正使用 `Idempotency-Key` 去重**。补偿任务会重试；
   不幂等的合并会重复迁移订单/资产，不可逆。
4. **`merge` 重放要返回 `already_merged=true`、`merged=false`**，而不是原样返回首次结果。
   原样返回会让补偿任务以为"又合并了一次"。
5. **`by-claim` 命中多个必须 409 + `ACCOUNT.MULTIPLE`**，不能"挑一个返回"。
6. **一个账号每类凭证最多一条活跃**（`uk_claim_one_per_type`）。换号必须换绑，
   不能并存——否则 `by-claim` 返回哪个都是"看起来对、实际错"。
7. **`user_id` 不可枚举**（ULID/UUID），且**不做懒注册**（未注册的 `app_key` 一律 400）。

> 追踪头（2026-11-04 起）：调用会带 `traceparent`（W3C）与 `X-Trace-Id`。
> 对端**不接也没关系**（未知头会被忽略，接口行为不变）；接了就能在一条 trace 里
> 看到 `social-login → usercenter` 的完整链路。反过来，对端若回写
> `X-Trace-Id`/`X-Request-Id`，本服务会原样沿用，见 implementation-status §36。

### 3.5 反向：用户中心 → 本服务（`claim.invalidated`）

这是**唯一一个由对端调用本服务的接口**，2026-11-09 起可用（本侧已实现，
对端可按需接入；不接也不影响任何现有契约）。

```
POST /internal/v1/usercenter/claim-invalidated
X-Service-Token: <internal.service_token>
Content-Type: application/json

{
  "event_id":   "17",
  "event_type": "claim.invalidated",
  "payload": {
    "app_key":     "app-xxxxxxxx",
    "user_id":     "01M6ZK...",
    "claim_type":  "phone",        // 空串 = 全部类型
    "reason":      "replaced",     // replaced | closed | merged_source
    "occurred_at": "2026-11-09T07:38:05Z"
  }
}
```

响应：

| 状态 | 含义 | 对端应如何处理 |
| --- | --- | --- |
| 200 `{"identities":1,"revoked":2}` | 已处理（`revoked=0` 表示重复投递） | 标记事件已投递 |
| 400 | 报文/`claim_type` 不认识 | **永久失败**，不要重试 |
| 401 | 令牌不一致 | 永久失败（改配置） |
| 404 | `app_key` 未在本服务登记 | 永久失败（应由应用对账修复） |
| 5xx | 本服务暂时不可用 | 重试（指数退避） |

四条约定：

1. **不要带新旧号码**。本服务按 `user_id` 反查绑定，拿到凭证值会多一份明文，
   却不多一分能力。
2. **至少一次投递 + 本侧幂等**：重复投递是安全的，不需要对端做「恰好一次」。
3. **`claim_type` 为空表示全部类型**（换绑用具体类型，注销/合并用空）。
4. **令牌独立于 `Authorization`**：`X-Service-Token` 只用于内部接口，
   与业务方的 `app_secret`、用户的 access_token 都不共用。

---

## 4. 对端就绪后怎么买账：联调步骤

### 第 0 步（现在就能做）：用假对端把链路跑通

```bash
go run ./cmd/mockusercenter -addr 127.0.0.1:9091
# 另一个终端：让它成为"用户中心"
SOCIAL_LOGIN_ACCOUNT_PROVIDER=http \
SOCIAL_LOGIN_ACCOUNT_HTTP_BASE_URL=http://127.0.0.1:9091 \
go run ./cmd/server
```

容器内跑时把 `127.0.0.1` 换成 `host.docker.internal`（macOS/Windows）。

### 第 1 步：对端交付时，先跑契约体检

```bash
# 只读（安全，可在任何环境跑）：连通性 + 应用已注册 + 404/信封
scripts/check-usercenter-contract.sh https://uc-test.internal "$UC_TOKEN" --app app_web

# 含写（会创建测试账号；契约没有删除接口，需对端侧清理）
scripts/check-usercenter-contract.sh https://uc-test.internal "$UC_TOKEN" \
  --app app_web --write --claim phone:19900000001

# 再加一个应用做隔离对照（v1.1 核心项，强烈建议跑）
scripts/check-usercenter-contract.sh https://uc-test.internal "$UC_TOKEN" \
  --app app_web --app2 app_mini --write
```

`--app` 必填。脚本的**第 0 步会自动注册**被测应用（`POST /internal/v1/apps`，
幂等 upsert）——顺序刻意放在最前：应用未注册时后面每一项都是 400 `APP.UNKNOWN`，
会把人引向"账号逻辑有问题"，而真正原因是"应用没同步过去"。
对端若没实现这个接口，第 0 步直接 FAIL，这是必须知道的事。

18 项检查的每一项失败都对应一个已知风险，输出里写了原因。
**这一步不通过就不要往下走**——否则后面所有失败都会混在一起，分不清是协议不符还是逻辑不符。

第 7 项（跨应用隔离）值得单独说：脚本用同一个手机号在 `--app2` 建号，
断言拿到的 `user_id` 与 `--app` 的不同；再做一次跨应用合并，断言被拒绝。
这一条做不到，App2 的用户会登进 App1 的账号——那是数据越权，不是"多应用不方便"。

### 第 2 步：切换配置并回归

```yaml
account:
  provider: "http"
  http:
    base_url: "https://uc-test.internal"
    token: ""            # 生产走 SOCIAL_LOGIN_ACCOUNT_HTTP_TOKEN
    timeout: "3s"
```

```bash
bash scripts/acceptance-admin.sh      # 管理端回归（17 步）
go test ./test/acceptance/ -count=1   # 登录链路回归（假对端，用于确认我方未回归）
```

### 第 3 步：跑真实场景矩阵

| 场景 | 触发方式 | 期望 |
| --- | --- | --- |
| 首次登录建号 | 应用配 `on_unbound_login=auto_create`，用新身份登录 | 200 建号 + 本地绑定 `external_user_id` = 对端 `user_id` |
| 重复首次登录 | 同一身份再登录一次 | 对端账号数不增加 |
| 对端不提供建号 | 应用配 `auto_create`，对端返回 404 | `AUTH.INVALID_CONFIG`，文案提示改 `need_register` |
| 对端 5xx | 对端返回 500 | 302 回跳业务方，`error=ACCOUNT.UNAVAILABLE&retryable=true` |
| 对端超时 | 对端睡眠 > 3s | 同上（503 语义） |
| 对端 429 | 对端返回 429 | `error=RATE.LIMITED&retryable=true` |
| 同手机号已属别人 | 对端 `by-claim` 返回另一账号 | 走绑定冲突三选一，**不得静默归并** |
| 对端命中多账号 | `by-claim` 返回 409 | `ACCOUNT.MULTIPLE`，拒绝归并，记入 J 组漂移 |
| 合并成功 | `/v1/bind` 触发合并 | 对端 `merged=true`，本地 `merge_operations=done` |
| 补偿重试 | 手工把 `merge_operations` 置 `failed` 后跑补偿 | 同键重放返回 `already_merged=true`，不重复迁移 |

失败形态说明：业务级失败是 **302 回跳业务方 + `error` / `error_description` / `retryable`**，
不是 5xx 页面（`handler/oauth.go`）——用户看到的是业务方统一提示。断言时不要只看状态码。

---

## 5. 假对端做不到的 5 件事

这一节是给"联调通过 = 上线"这个念头踩刹车的。

| # | 事项 | 为什么 mock 证明不了 | 风险 |
| --- | --- | --- | --- |
| 1 | **强一致读** | mock 是单进程内存，天然强一致 | 对端若读写分离，`by-claim` 读到旧数据 → P0-6 防线失效 |
| 2 | **Merge 真幂等** | mock 的幂等是 20 行 map 查找 | 对端若"记录幂等键但仍执行迁移"，订单资产会被搬两次 |
| 3 | **跨服务一致性** | mock 不会"成功一半" | 远端成功、本地事务失败时，靠补偿自愈；真实对端可能有自己的事务边界 |
| 4 | **容量与延迟分布** | mock 在环回地址上响应 <1ms | 真实延迟尾部决定 3s 超时是否够；P99 超时会被记成 `ACCOUNT.UNAVAILABLE` |
| 5 | **鉴权方式** | mock 只做 Bearer 明文比较 | 对端若要 mTLS/签名，客户端要改 `httpx` 的 transport |

因此上线前的验收结论应写成："协议与降级行为已验证；**强一致读、幂等实现、容量
需由对端提供证据或在对端测试环境复验**。"

---

## 6. 切换清单（stub → http）

### 6.1 ⚠️ 最容易踩的坑：历史绑定里的 id 是桩生成的

`stub` 生成的 `user_id` 形如 `u_stub_12_ab3f`。这些绑定写进了
`oauth_bindings.external_user_id`。切到 http 后，它们与真实用户中心的账号
**没有任何对应关系**：

- 用户再次登录时能用（走已有绑定的快速路径），但 `sub` 是一个对端不存在的 id；
- 一旦触发合并/回源核对，`Get(u_stub_…)` 返回 404 → 归并被跳过并记漂移；
- 管理端按 `external_user_id` 查账号会查不到。

切换前必须确认这些数据怎么处理：

```sql
-- 找出桩时代留下的绑定（切换前跑）
SELECT app_id, external_user_id, count(*)
FROM oauth_bindings
WHERE external_user_id LIKE 'u_stub_%'
GROUP BY 1,2 ORDER BY 3 DESC;
```

处理方式（按环境选一种，**不要带到生产**）：

| 环境 | 建议 |
| --- | --- |
| 开发/演示 | `docker compose down -v` 重建库，从干净状态开始 |
| 预发 | 清空 `oauth_bindings` / `oauth_identities` / `identity_claims` 中由桩产生的数据 |
| 生产 | 不适用——生产禁止 stub，本来就进不去 |

### 6.2 切换检查表

- [ ] `server.mode=release` 下启动不报 `account.provider=stub`
- [ ] `account.http.base_url` 为 https 且域名与网络策略一致
- [ ] `SOCIAL_LOGIN_ACCOUNT_HTTP_TOKEN` 由密钥管理系统注入（不入库、不进镜像）
- [ ] 管理端看板 `account_center.provider = http`、`production_ready = true`
- [ ] `/metrics` 能抓到 `social_login_http_requests_total{route="/v1/oauth/callback/:platform"}`
- [ ] 桩时代绑定已按 §6.1 处理
- [ ] 契约体检脚本 8 项全过（§4 第 1 步）
- [ ] 场景矩阵（§4 第 3 步）在测试环境全过

---

## 7. 与 J 组（凭证一致性）的关系

`claim_mismatches` 的三个写入点全部来自对端返回：`account_not_found`、
`multiple_accounts`、`account_mismatch`。也就是说：

- 对端没接上时，这三类漂移**不会产生**（stub 永远查得到、也不会多账号）；
  看板上 `claim_mismatch_open` 长期为 0 是"没核对"，不是"没问题"。
- 对端接上后，这个数字才会真实反映数据质量。
- 长期为 0 且业务侧一直反馈"同手机号没合并"时，先查
  `applications.policy.merge.on_login` 是否配了 `claim_verified`。

---

## 8. 变更记录

| 日期 | 变更 |
| --- | --- |
| 2026-10-29 | 首版：契约 v1、进度标记 16 项、假对端与契约脚本、切换清单 |
| 2026-11-02 | 补应用注册同步（§2.6 落地）：`POST /internal/v1/apps` 纳入契约，本服务侧即时同步 + 5 分钟全量对账，状态落 `applications.uc_synced_at / uc_sync_error`，管理端应用列表展示「已同步 / 未同步」；契约脚本扩到 18 项（第 0 步自动注册被测应用） |
| 2026-11-09 | 新增反向推送契约（§3.5）：`POST /internal/v1/usercenter/claim-invalidated` + `X-Service-Token`。用户中心换绑/注销/合并后主动失效本侧 claim；事件不含号码，重复投递幂等；400/401/404 为永久失败、5xx 可重试 |
| 2026-11-05 | 审计与慢查询落地（对端侧，不影响契约）：① 写入 `account_audit_logs`（与业务同事务），`actor` 取本服务发的 `X-Actor: social-login`，真人靠 `trace_id` 与我校验；② 新增只读查询 `GET /internal/v1/apps/{app_key}/audit`（仅内部，业务方不接触）；③ 慢查询日志只记 SQL 模板与参数个数，不记值 |
| 2026-11-02 | 契约升到 v1.1 并在代码中落地：① 全部路径加 `/v1/apps/{app_key}`（应用隔离）；② 统一错误信封，适配层按 `code` 翻译、状态码只兜底；③ 补换绑端点 `PUT .../claims/{type}`；④ 合并回传 `discarded_claims`。同步改：5 处调用点、stub 按应用分区、假对端加应用维度与信封、契约脚本扩到 16 项（含跨应用隔离）。v1 的"待修订"警示已移除 |
