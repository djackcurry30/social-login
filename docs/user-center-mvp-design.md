# 用户中心 MVP 技术方案

> 目标读者：用户中心开发、统一登录接入服务（social-login）维护者、运维
> 输入依据：`docs/architecture-design.md`（C1/C4/C5、§7.3 合并、§8.1 标识、§13 并行事项）、
> `docs/user-center-integration.md`（契约 v1）、`internal/infrastructure/account/http.go`（现有适配层）
> 状态：**P0 已实现（2026-11-02）**。实现记录与三处有意偏离见 §14；
> §2 的契约修订与 §3 的 DDL 均已落地，验收结果见 §10。

---

## 1. 定位：用户中心只做"账号主数据"

先把边界钉死，MVP 才能小。社会上有一种常见误解是"用户中心 = 登录中心"，
在本项目里不成立：**登录、授权、令牌、绑定全在 social-login**，用户中心被 C4 明确
定位为**账号主数据的持有者**。

| 能力 | social-login | 用户中心 | 说明 |
| --- | --- | --- | --- |
| 三方授权 / 换 token / 验签 | ✅ | — | 渠道细节不该泄漏到账号层 |
| 三方身份（open_id）+ 绑定关系 | ✅ | — | `oauth_identities` / `oauth_bindings` |
| 账号主数据（存在、状态） | — | ✅ | 本服务**没有 accounts 表**（C4） |
| 凭证唯一性（一个手机号只能属于一个账号） | 本地镜像 | ✅ **权威** | 本地 `identity_claims` 只是"某次证明过"的记录，会漂移（J 组兜底） |
| 合并的执行（迁移数据） | 编排 + 本地收敛 | ✅ 执行 | 三次独立事务的编排在 social-login，UC 只负责它自己那一笔 |
| 短信验证码 | ✅ | — | 发码是登录侧的事，UC 不碰 |
| 登录态 / 会话 / 令牌 | ✅ | — | **UC 不做 IdP** |
| 对外事件通知 | ✅ | P1 | 交给 social-login 统一外发，避免业务方接两套 webhook |

**一句话**：UC 是"账号的数据库 + 几条严格语义的写接口"，不是身份提供方。

由此得到 MVP 的三个减法，这是本方案最重要的部分：

1. **没有登录接口** → 不需要会话、不需要 Redis、不需要密码/验证码。
   整个服务是**无状态**的，只依赖 PostgreSQL。
2. **没有权限模型** → 不存角色、不存菜单。业务方的权限在自己的系统里。
3. **没有资料编辑** → MVP 只提供读 + 建 + 合并。昵称/头像只在 Create 时写入。

---

## 2. 必须先修的契约缺口：应用维度

这是动手前必须解决的第一件事，也是本次设计里唯一的"破坏性变更"。

### 2.1 问题

`internal/infrastructure/account/http.go` 的四个方法（`Get` / `GetByClaim` /
`Create` / `Merge`）**都不携带应用标识**。而 C1 要求：

> 账号空间边界 = 业务应用。App1 与 App2 里，同一个自然人是**两个互不相干的账号**。

按现有契约实现，用户中心只能有一个全局账号空间——同一个手机号在 App1 建过号，
在 App2 首次登录时 `by-claim` 会命中 App1 的账号，于是 App2 的用户直接"登录成了
别人在另一个业务的账号"。这是数据越权，不是小 bug。

同时 `Merge` 还要求拒绝跨应用合并（需求 R3）：没有应用维度就无法判定是否跨应用。

### 2.2 决策：应用进路径，不进请求头

```
GET  /v1/apps/{app_key}/accounts/{public_id}
GET  /v1/apps/{app_key}/accounts/by-claim?type=phone&value=...
POST /v1/apps/{app_key}/accounts
POST /v1/apps/{app_key}/accounts/merge
```

**为什么用路径而不是 `X-App-Key` 头**：

| 方案 | 优点 | 致命问题 |
| --- | --- | --- |
| 路径前缀（采用） | 显式；日志/网关/限流一眼可见；漏了就是 404，不会静默串租户 | URL 稍长 |
| 请求头 | 客户端改动小 | **忘记带头 = 未知租户**，必须每个端点都记得拦；日志里看不到；网关无法按应用限流 |
| 每应用一套凭据 | 最安全 | 应用数量增长后凭据管理成本高，MVP 过重 |

第三种可作为演进方向（见 §9 扩展点 E6），MVP 用"一个服务 token + 路径隔离"。

### 2.3 `app_key` 用 `app_code`，不用 `applications.id`

social-login 的 `applications.id` 是**本地自增主键**：换环境、重建库都会重号，
把它当跨服务租户标识，迟早出现"测试环境的 app 2 对应生产环境的另一个业务"。

用 `app_code`（业务唯一键，管理端建应用时生成且不可变）。
UC 侧存 `app_key text UNIQUE`，内部再用 `bigserial` 做主键与索引。

**三套凭据别混为一谈**（这是最容易产生的误解）：

| 凭据 | 谁签发 | 给谁用 | 用途 |
| --- | --- | --- | --- |
| `app_code` | 登录中心管理端（建应用时生成，不可变） | 业务方 App | 标识"哪个业务应用"，**同时就是 UC 的 `app_key`** |
| `app_secret` | 登录中心管理端（仅创建时明文返回一次，库里只存哈希） | 业务方 App | 调 `/v1/token`、`/v1/introspect` 的业务方鉴权 |
| 服务 token | 部署配置 / 密钥管理 | social-login 服务 | 调 UC 的服务间鉴权（服务级，不区分应用） |

**UC 不签发任何凭据**：不复用 `app_secret`（那是给业务方的，不该扩散到内部服务），
也不另发一套（两套凭据必然漂移）。它只认 `app_code` 这个租户键 + 一个服务级 token。

### 2.4 适配层要改的地方（social-login 侧，工作量集中在这里）

> ✅ **已于 2026-11-02 完成**（见 `docs/implementation-status.md` §27）。
> 下表保留作为改动清单与影响面记录。

| 文件 | 改动 |
| --- | --- |
| `internal/domain/account/provider.go` | `Get(ctx, appKey, userID)`、`GetByClaim(ctx, appKey, claim)`；`CreateRequest` / `MergeRequest` 加 `AppKey string`；新增 `ClaimReplacer` 可选端口 |
| `internal/infrastructure/account/http.go` | 拼路径时加 `/apps/{app_key}` 前缀；四个方法签名跟随；错误信封解析（见 §2.5） |
| `internal/infrastructure/account/stub.go` | 内部 map 按 `appKey` 分区，否则测试里两个应用会串号 |
| `application/authflow/branches.go` | `autoCreateAndBind` 传 `app.AppCode` |
| `application/authflow/claimmerge.go` | 传 `app.AppCode` |
| `application/merge/service.go`、`merge/verification.go` | 同上（`Merge` 有两处调用：正常链路与补偿重试） |
| `test/acceptance/account_http_test.go`、`http_test.go` | 路径断言与用例签名 |

改动面：4 个方法签名、5 处调用点（`merge/service.go` 的 `Merge` 两处）、2 个实现（http + stub）、
约 20 个用例。**都是编译期就能发现的问题，不会出现"改漏了但能跑"的情况**——这也是
为什么值得现在改：靠编译器兜底的重构，成本远低于靠联调发现。

**为什么必须现在改**：UC 一行代码还没写，改契约成本是零；等对端按 v1 写完再改，
要双方改代码 + 重跑联调。这是"尽早付最小代价"的典型场景。

### 2.5 顺带补上：统一错误信封

现有适配层是**只看状态码**的（`Create` 里任何 409 都译成 `BIND.IDENTITY_TAKEN`）。
一旦 UC 在 Create 上返回别的 409（例如幂等键正在处理中），业务方看到的是
"该凭证已被其他账号占用"——错得很有误导性。

所以契约补一层机器可读的错误信封，适配层优先按 `code` 翻译，状态码只作兜底：

```json
{"code":"ACCOUNT.CLAIM_TAKEN","message":"该手机号已被占用","retryable":false}
```

| UC 返回 | 适配层映射 | 备注 |
| --- | --- | --- |
| 200/201 | — | 正常 |
| 404 + `ACCOUNT.NOT_FOUND` | `ErrNotFound` | 账号/凭证不存在 |
| 409 + `ACCOUNT.CLAIM_TAKEN` | `BIND.IDENTITY_TAKEN` | 仅 Create |
| 409 + `ACCOUNT.MULTIPLE` | `ErrMultipleAccounts` | 仅 by-claim |
| 409 + `ACCOUNT.MERGE_REJECTED` | `INVALID_REQUEST` | 仅 merge（如 target==source） |
| 409 + `ACCOUNT.IDEMPOTENCY_IN_PROGRESS` | 可重试错误 | 同键并发，稍后重试 |
| 400 + `APP.UNKNOWN` | `ACCOUNT.UNAVAILABLE`（不可重试） | **不能用 409**，否则被误译成"凭证被占用" |
| 429 | `RATE.LIMITED`（可重试） | 配额 |
| 5xx | `ACCOUNT.UNAVAILABLE`（可重试） | 上游故障 |

这张表是**双向约束**：UC 选状态码时要考虑"消费方会怎么翻译"。写完接口先拿
`scripts/check-usercenter-contract.sh` 过一遍，它已经覆盖了其中 8 条。

### 2.6 应用注册：唯一入口在登录中心，UC 侧做幂等同步

> ✅ **已实现（2026-11-02）**：`POST /internal/v1/apps` + 即时同步 + 5 分钟全量对账，
> 状态落 `applications.uc_synced_at / uc_sync_error`。见 `docs/implementation-status.md` §28。

应用的**创建入口只有一个**：登录中心管理台 `POST /admin/v1/apps`，它生成
`app_code` 与 `app_secret`（明文只返回一次，库里存哈希）。UC 不重复这套流程，
它只需要知道"这个 `app_code` 存在"。

同步方式三步，每步都幂等：

1. **建应用时同步**：管理端建应用成功后异步调用 `POST /internal/v1/apps`。
   **失败只打 warn，不阻塞建应用**——建应用与登录是两条独立链路，
   UC 故障不该让运维连应用都建不了。
2. **后台对账**：每 5 分钟把全部启用应用 upsert 一遍。解决两类问题：
   建应用时 UC 正好不可用；以及历史应用是在 UC 上线前就建好的。
3. **失败可见**：登录侧遇到未注册应用返回 `APP.UNKNOWN`（400）；
   管理端应用详情显示"用户中心未同步"（P1，需记录 `uc_synced_at`）。

**为什么不允许 UC 懒注册**（首次调用自动建租户）：配置里一个字母写错
（`app_web_porta1`）就会静默造出一个空租户——该应用所有用户都变成"新用户"
并触发 `auto_create` 建号。这种错误不报错，只表现成"用户数据全丢了"。

**为什么不让 UC 直接读 social-login 的库**：跨服务读库会把两边 schema 焊死，
任一方改表都要同时改另一方。契约 + 同步是更松的耦合。

---

## 3. 数据模型

五张表，全部以 `app_id` 为第一维度。DDL 为示意（正式实现用 goose 迁移，
与 social-login 同一套迁移工具，不用 AutoMigrate——迁移要可审计、可回滚）。

```sql
-- ① 租户：一个业务应用一行
CREATE TABLE apps (
    id         bigserial PRIMARY KEY,
    app_key    text        NOT NULL UNIQUE,      -- social-login 的 app_code
    name       text        NOT NULL DEFAULT '',
    status     smallint    NOT NULL DEFAULT 1,   -- 1 启用 / 0 停用
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ② 账号
CREATE TABLE accounts (
    id          bigserial PRIMARY KEY,
    app_id      bigint      NOT NULL REFERENCES apps(id),
    public_id   text        NOT NULL,            -- ULID，对外唯一标识（§8.1 不可枚举）
    status      text        NOT NULL DEFAULT 'active',  -- active|frozen|closed
    nickname    text        NOT NULL DEFAULT '',
    avatar_url  text        NOT NULL DEFAULT '',
    merged_into bigint      NULL REFERENCES accounts(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_status CHECK (status IN ('active','frozen','closed')),
    UNIQUE (app_id, public_id)
);

-- ③ 凭证：hash 查询 + 密文留存
CREATE TABLE account_claims (
    id           bigserial   PRIMARY KEY,
    app_id       bigint      NOT NULL,
    account_id   bigint      NOT NULL REFERENCES accounts(id),
    claim_type   text        NOT NULL,            -- phone | email
    value_hash   bytea       NOT NULL,            -- HMAC-SHA256(归一化值)
    hash_version smallint    NOT NULL DEFAULT 1,  -- 换盐/换算法时用
    value_cipher bytea       NOT NULL,            -- AES-GCM，用于展示与审计
    dek_id       text        NOT NULL,            -- 信封加密的 KEK 版本
    source       text        NOT NULL,            -- wechat_phone | apple_email | manual
    verified_at   timestamptz NOT NULL,
    revoked_at    timestamptz NULL,
    revoke_reason text        NULL,   -- replaced | merged_source | closed | admin
    CONSTRAINT ck_claim_type CHECK (claim_type IN ('phone','email'))
);

-- ① 一个凭证值只能属于一个账号（跨账号唯一）
--    只约束【活跃】凭证：撤销后释放号码（与 social-login 同口径）
CREATE UNIQUE INDEX uk_claim_value
    ON account_claims (app_id, claim_type, value_hash)
    WHERE revoked_at IS NULL;

-- ② 一个账号每类凭证最多一条活跃：换号必须换绑，不能并存
CREATE UNIQUE INDEX uk_claim_one_per_type
    ON account_claims (app_id, account_id, claim_type)
    WHERE revoked_at IS NULL;

-- ④ 幂等键：写操作的结果快照
CREATE TABLE idempotency_keys (
    app_id       bigint      NOT NULL,
    scope        text        NOT NULL,       -- create_account | merge
    key          text        NOT NULL,
    request_hash bytea       NOT NULL,       -- 同键不同体必须拒绝
    status_code  int         NOT NULL,
    response     jsonb       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, scope, key)
);

-- ⑤ 合并流水：审计 + 幂等 + 可重放
CREATE TABLE merges (
    id         bigserial   PRIMARY KEY,
    app_id     bigint      NOT NULL,
    idem_key   text        NOT NULL,
    target_id  bigint      NOT NULL,
    source_id  bigint      NOT NULL,
    status     text        NOT NULL,         -- merged | rejected
    reason     text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, idem_key)
);
```

### 3.1 四个值得解释的地方

**`value_hash` + `value_cipher` 双列。** 只存密文无法按值查询（AES 是随机 IV，
同值不同密文）；只存 hash 又没法展示与审计。所以：查询走 hash，展示走密文。
hash 用 HMAC-SHA256（带盐，防彩虹表），`hash_version` 让"换盐"成为一次可灰度
的迁移而不是一次停机。

**`app_id` 在 `account_claims` 上冗余。** 逻辑上可以从 `accounts` join 出来，
但唯一索引必须在 `(app_id, claim_type, value_hash)` 上，冗余存储换掉一次 join，
也顺便让"跨应用查同一凭证"不可能因为写错 SQL 而成立。

**两个唯一索引，约束的是两件事。** `uk_claim_value` 管"一个号码只能属于一个账号"；
`uk_claim_one_per_type` 管"一个账号每类凭证最多一条"（一个账号只有一个手机号、
一个邮箱）。两者都只作用于 `revoked_at IS NULL` 的行——撤销即释放，
历史记录仍完整保留，否则没法解释"这个号码以前是谁的"。

第二条索引是产品规则的直接落地：**换手机号必须换绑，不能并存**。
少了它，就会出现"一个账号挂着两个手机号"，而那时 `by-claim` 无论返回哪个都是
"看起来对、实际错"的数据。同理，合并时两个账号的手机号不能都留下（见 §5.2）。

**`merged_into`。** 合并后 source 账号不删除，只置 `closed` + 指向 target。
理由：`public_id` 已经发给业务方（写进了对方的用户表），删掉会让历史数据指向空气；
置 closed 后 `Get` 返回 404 语义由调用方决定，也能回答"这个 id 去哪了"。

---

## 4. 接口

### 4.1 对外（social-login 调用）

| 方法 | 路径 | 语义要点 |
| --- | --- | --- |
| GET | `/v1/apps/{app_key}/accounts/{public_id}` | 200 / 404；跨应用一律 404（不泄漏存在性） |
| GET | `/v1/apps/{app_key}/accounts/by-claim?type&value` | **强一致读**；0 → 404，1 → 200，多 → 409 |
| POST | `/v1/apps/{app_key}/accounts` | 必带 `Idempotency-Key`；凭证冲突 → 409 |
| POST | `/v1/apps/{app_key}/accounts/merge` | 必带 `Idempotency-Key`；重复 → `already_merged` |
| PUT | `/v1/apps/{app_key}/accounts/{public_id}/claims/{claim_type}` | 换绑：原子替换该类型凭证；新值被他人占用 → 409 |
| GET | `/healthz` `/readyz` `/metrics` | 运维 |

请求示例（Create）：

```json
POST /v1/apps/app_web_portal/accounts
Idempotency-Key: first_login:app_web_portal:42

{
  "claims": [{"type":"phone","value":"13800000000","source":"wechat_phone"}],
  "nickname": "微信昵称",
  "avatar_url": "https://..."
}
```

响应：

```json
{"user_id":"01J8XK3M9P4Q7R2S5T8V0W1X2Y","status":"active",
 "claims":[{"type":"phone","value":"13800000000","source":"wechat_phone"}]}
```

> 注意：`user_id` 字段名沿用契约 v1（social-login 的 DTO 就叫这个），
> 值即 `accounts.public_id`。不要为了"更规范"改成 `public_id`——那会让适配层
> 与已有 17 个用例一起改，收益为零。

### 4.2 内部（运维 / 对账，不对公网）

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/internal/v1/apps` | 注册/更新应用（幂等 upsert）。建应用时同步调用 + 每 5 分钟对账（§2.6） |
| GET | `/internal/v1/apps/{app_key}/accounts/{public_id}` | 带凭证明文的调试视图（需独立鉴权，P1） |
| POST | `/internal/v1/accounts/{public_id}/close` | 注销（P1，见 §9） |

**未注册的 app_key 一律 400**（`APP.UNKNOWN`），不做隐式创建。理由见 §2.6。

注册接口由 social-login 侧调用，不是给运维手工敲的；运维脚本只在两种场景用：
UC 首次上线时为存量应用批量补注册、以及灾备重建。

### 4.3 明确不做（MVP）

- 登录、注册、密码、短信、验证码（登录侧的事）
- 令牌、会话、登出、单点登录
- 角色、权限、菜单
- 资料编辑、头像上传（`nickname/avatar_url` 只在 Create 时写入）
- 跨应用 SSO（C1 明确不做）
- 账号列表/搜索的管理端界面（P2 再议，先用只读 SQL）

---

## 5. 关键流程与并发语义

### 5.1 首次登录建号（social-login → UC）

```
social-login                          UC
  │  POST /apps/{k}/accounts           │
  │  Idempotency-Key: first_login:...  │
  ├───────────────────────────────────>│
  │                                    │ ① 幂等表 INSERT（唯一键冲突即重放）
  │                                    │ ② claims 唯一索引校验
  │                                    │ ③ INSERT accounts + claims（同事务）
  │  201 {user_id, status, claims}     │ ④ 写幂等快照
  │<───────────────────────────────────┤
  │ 用 user_id 写 oauth_bindings        │
  │ 签发令牌 sub = user_id              │
```

失败分支（social-login 已有对应处理，UC 只需返回正确语义）：

| UC 情况 | 返回 | social-login 行为 |
| --- | --- | --- |
| 凭证已被其他账号持有 | 409 `ACCOUNT.CLAIM_TAKEN` | 走绑定冲突/合并流程 |
| 应用未注册 | 400 `APP.UNKNOWN` | 登录失败，提示配置问题（不重试） |
| 同键正在处理中 | 409 `ACCOUNT.IDEMPOTENCY_IN_PROGRESS` | 可重试错误 |
| 不提供建号能力 | 404/405/501 | `AUTH.INVALID_CONFIG`，提示改 `need_register` |

### 5.2 合并（最需要小心的事务）

```sql
BEGIN;
  -- ① 幂等占位：INSERT ... ON CONFLICT DO NOTHING
  --    未插入 → 读已有行，返回 {merged:false, already_merged:true}
  INSERT INTO merges (app_id, idem_key, target_id, source_id, status, reason) ...;

  -- ② 按 id 升序加锁（防 A→B 与 B→A 并发死锁）
  SELECT id, status FROM accounts
   WHERE app_id = $1 AND id IN ($target, $source)
   ORDER BY id FOR UPDATE;

  -- ③ 校验：都存在、同属一个应用、target != source、source 未 closed

  -- ④ 凭证按【类型】目标优先：
  --    目标同类没有 → 迁移过去
  --    目标同类已有（哪怕号不同）→ source 的这条撤销，不迁移
  --    原因：一个账号每类只能有一条活跃凭证（§3.1 的第二条唯一索引）
  UPDATE account_claims SET account_id = $target
   WHERE account_id = $source AND revoked_at IS NULL
     AND NOT EXISTS (SELECT 1 FROM account_claims t
                      WHERE t.app_id = $app AND t.account_id = $target
                        AND t.claim_type = account_claims.claim_type
                        AND t.revoked_at IS NULL);

  UPDATE account_claims SET revoked_at = now(), revoke_reason = 'merged_source'
   WHERE account_id = $source AND revoked_at IS NULL;

  -- ⑤ source 关账并指向 target
  UPDATE accounts SET status = 'closed', merged_into = $target, updated_at = now()
   WHERE id = $source;

  -- ⑥ 回填幂等快照
COMMIT;
```

三条硬要求：

1. **`already_merged` 不能"原样返回首次结果"**。正确语义是
   `{merged:false, already_merged:true}`——"这次调用没有执行合并"。
   补偿任务据此判断是否还要推进本地收敛；返回 `merged:true` 会让它以为又合并了一次，
   进而重复迁移。这个坑我们在写假对端时已经踩过一次（见 implementation-status §26.4）。
2. **跨应用合并必须 404**，不能 409。返回"不存在"比返回"不允许"更不泄漏信息，
   也符合 R3 的"明确拒绝"（对外表现为查不到，业务侧无从试探）。
3. **整个合并是一笔本地事务**。UC 不做跨服务事务；"远端成功本地失败"的补偿在
   social-login 的 `merge_operations` 里，UC 只需保证自己这一笔要么全成要么全回滚。
4. **source 的手机号会被"丢掉"**（撤销而非迁移）。这是"一个账号一个手机号"的必然结果，
   必须在契约里写清、并在管理端可查（`revoke_reason='merged_source'` + 合并流水）。
   否则会出现"用户的旧号明明验证过，合并后却用不了，客服查不出原因"。

### 5.3 并发场景期望

| 场景 | 期望结果 |
| --- | --- |
| 同 key 并发 Create ×10 | 只建 1 个账号；其余返回同一 `user_id` 或 `IDEMPOTENCY_IN_PROGRESS` |
| 不同 key 并发 Create，同 claim | 1 个 201，其余 409 `CLAIM_TAKEN` |
| A→B 与 B→A 并发合并 | 按 id 升序加锁：1 个成功，另 1 个 `MERGE_REJECTED`（target 已 closed） |
| 合并中进程崩溃 | 事务回滚，无"迁移了一半"的账号 |
| 同 key 重放合并 | `already_merged=true`，凭证未再迁移 |
| 两个 replace 并发（同账号同类型） | 只有一条生效，另一条 409 `ACCOUNT.CONFLICT` |
| replace 到已被他人占用的号码 | 409 `CLAIM_TAKEN`，本账号原凭证不变（事务未提交） |

---

### 5.4 换绑（替换某类型凭证）

```
PUT /v1/apps/{app_key}/accounts/{public_id}/claims/phone
{"value":"13900000000","source":"wechat_phone"}
```

处理顺序：

1. 归一化 → hash。
2. 该 hash 已属于本账号同类且活跃 → **200 no-op**（幂等，重复调用不报错）。
3. 该 hash 被**其他**账号持有 → 409 `ACCOUNT.CLAIM_TAKEN`，调用方走合并或人工处理。
4. 否则在一个事务里：撤销本账号该类活跃凭证（`revoke_reason='replaced'`）→ 插入新凭证。

**为什么 MVP 必须有这个接口**：唯一索引只定义了"不能并存"，没定义"怎么换"。
没有它，纠正一个手机号只能靠合并——而合并会把整个 source 账号关掉，
为了改个号码牺牲一个账号，显然不对。

**谁调用它**：P0 只把接口做出来并自测；真正由 social-login 在登录链路里发现
"平台侧手机号变了"时调用，属 P1（需要改登录链路，风险大于收益，不塞进这一批）。

**并发**：两个 replace 同时来，唯一索引保证最多一条活跃，后者插入冲突 → 409
`ACCOUNT.CONFLICT`（可重试）。不做乐观锁版本号：这一类冲突概率极低，
用唯一索引兜住比维护 version 列更省事。

## 6. 多应用隔离怎么落地（不只是"加个 where"）

三层防线，缺一层都会在某次"新加一个查询"时破防：

1. **表设计**：所有唯一键以 `app_id` 开头；`account_claims` 冗余 `app_id`。
2. **仓储层强制**：仓储方法第一个参数就是 `appID`，拼 SQL 时统一由构造器注入
   `app_id = ?`；参照 social-login 的 `scopedTables` 做法——漏了 `app_id` 直接
   panic 而不是返回全表数据。宁可测试期崩，不要生产期串租户。
3. **测试**：每个读写接口都有"跨应用访问必须 404"的用例（App A 的 `public_id`
   拿到 App B 的路径下必须查不到）。

P2 可再加 PostgreSQL RLS 作为纵深防御（`SET LOCAL app.current_app`），
但**不要用它替代第 2 层**：RLS 只在数据库层生效，业务逻辑里的越权判断仍然需要。

---

## 7. 凭证归一化：必须与 social-login 完全一致

这条不写清楚，联调时会出现"同一个号码，本地查得到、UC 查不到"的诡异现象。

social-login 现有规则（`domain/identity/claim.go`）：

| 类型 | 归一化 |
| --- | --- |
| `phone` | 只保留数字；13 位且以 `86` 开头时去掉前缀 |
| `email` | 去空白 + 转小写 |
| 其他 | 去空白 |

UC **必须逐字实现同一套规则**，且放在一个单独的函数里、单测覆盖边界
（`+86 138-0000-0000` / `8613800000000` / `138 0000 0000` 必须得到同一个 hash）。

长期看这套规则应该由契约定义（写进 `docs/user-center-integration.md` §3.
的一致化章节），双方各自实现 + 用同一批用例校验；更彻底的做法是
social-login 在调用前就归一化并只传归一化后的值，UC 不再做二次加工——
**这一步列为 P1**，因为改它会动 social-login 的 claim 写入链路，风险大于收益。

---

## 8. 非功能

| 维度 | 措施 |
| --- | --- |
| 一致性 | 所有读写走主库；MVP **不接只读从库**（`by-claim` 是 P0-6 的最后一道防线，读到旧数据等于防线失效） |
| 延迟预算 | p99 < 50ms（单条 SQL 级操作，索引覆盖）；social-login 侧超时 3s，留足余量 |
| 容量 | 5 应用 × 10 万账号 × 2.2 凭证 ≈ 110 万行，索引 < 300MB，单 PG 足够 |
| 扩展 | 服务无状态，可水平扩到 N 副本；DB 垂直扩 + 按 `app_id` 分片（所有唯一键已以此开头） |
| 可观测 | `/metrics`（请求量/延迟/`accounts_created_total`/`merge_total`/`claim_conflict_total`）、结构化日志带 `app_key` 与 `public_id`、透传 `traceparent` |
| 安全 | 传输走 TLS（内网可 mTLS）；`value_cipher` 信封加密，KEK 由密钥管理系统下发；日志**不得**打印凭证明文 |
| 迁移 | goose（与 social-login 同工具）；每次迁移可回滚；生产禁止自动迁移 |
| 部署 | 单二进制 + PG；开发用 docker-compose（pg + migrate + api），生产 2 副本 + 主库 |

**MVP 不需要 Redis**。这是"不做登录态"带来的直接收益：没有会话、没有限流计数器
（限流交给网关）、没有分布式锁（幂等靠唯一键）。少一个组件就少一类故障。

---

## 9. 保留扩展能力：八个明确的缝

"保留扩展"不能靠"以后再说"，得先留好接缝。以下六处是**现在就要按扩展形态设计，
但 MVP 不实现**的地方：

| # | 扩展点 | 现在的做法 | 将来怎么长 |
| --- | --- | --- | --- |
| E1 | 凭证类型 | `CHECK (claim_type IN ('phone','email'))` + 一个 `normalize()` 函数 | 新增类型 = 一条迁移 + 一个 switch case；若类型多到需要动态配置，再引入 `claim_types` 注册表（届时把校验从 CHECK 挪到应用层） |
| E2 | 账号属性 | **MVP 不设 `attrs` 列**（决策见 §12）。只保留 `nickname` / `avatar_url` 两个显式列 | 需要时新增 `attrs jsonb` + 白名单校验；不预留空列，避免"随手往里塞字段" |
| E3 | 事件外发 | MVP 只写 `merges` 表（够审计） | 加 `outbox` 表 + worker，推 `account.merged` / `claim.invalidated` / `account.closed` |
| E4 | 接口版本 | 路径带 `/v1` | 新增端点用 `/v1` 内扩展；不兼容变更才开 `/v2`，并在一段时间内双写 |
| E5 | 分片 | 所有唯一键以 `app_id` 开头 | 按 `app_id` 分库/分区；路由层已有 app_key，天然是分片键 |
| E6 | 服务间鉴权 | 单一 Bearer token | 演进到每应用凭据或 mTLS（`social-login` 侧只需换 `httpx` 的 transport） |
| E7 | 敏感数据 | `value_cipher` 信封加密 + `dek_id` | 接 KMS；按应用配置"是否留存明文"（有的业务要求不留） |
| E8 | 批量对账 | 只提供单条读 | `POST /internal/v1/claims/reconcile`（批量比对，供 social-login 的离线任务用） |

其中 **E3（事件）** 是最值得早点想清楚的：一旦业务方需要"账号合并后同步订单"，
没有事件就只能靠轮询。但 MVP 不实现它，因为 social-login 自己已经在发
`account.merged` 的 webhook（§11），业务方的需求已经被满足。

---

## 10. 分期与验收

### P0 · MVP（能替代 Stub，跑通全部登录链路）

- 五张表 + 两个唯一索引（见 §3）
- 5 个对外端点：Get / by-claim / Create / Merge / **换绑**（含 app 维度、幂等）
- 应用注册接口（`POST /internal/v1/apps`）
- 归一化函数 + hash/加密
- `/healthz` `/readyz` `/metrics`

**完成的判据不是"接口通了"，而是这三条同时成立**：

1. `scripts/check-usercenter-contract.sh <base> <token> --write` 8 项全过
2. social-login 把 `account.provider` 指向 UC 后，`go test ./test/acceptance/`
   4 个 HTTP provider 用例全过（可把测试里的假对端地址换成真实地址跑一遍）
3. 并发用例：10 并发同 key Create → 1 个账号；A→B 与 B→A 并发合并 → 无死锁、1 成功

### P0.5 · 可运维（上线前必须有）— 已全部交付

- 建应用后同步注册 UC + 每 5 分钟对账（§2.6）；存量应用的补注册脚本
- 停用应用的拒绝逻辑（`APP.DISABLED`）
- 注销（`close`）：置 closed + 撤销全部凭证 + 事件占位
- **审计日志**（2026-11-05）：迁移 `00002_account_audit_logs`，
  `account.created` / `claim.bound` / `claim.replaced` / `account.merged` /
  `account.closed` 五类动作**与业务同事务写入**；detail 不含凭证明文；
  `actor` 取调用方声明的 `X-Actor`，真实的人通过 `trace_id` 与 social-login
  的审计关联。只读查询 `GET /internal/v1/apps/{app_key}/audit`（游标翻页）。
- **慢查询**（2026-11-05）：pgx `QueryTracer` 挂在连接上，阈值
  `database.slow_query_threshold`（默认 200ms，只记录不中断）；
  日志只有 SQL 模板与**参数个数**，不记参数值；与 `statement_timeout` 的分工
  是"先看见"与"最终杀掉"。连接池参数见 `configs/usercenter.yaml`。

### P1 · 补齐契约语义

- `claim.invalidated` 推送（对端换号 → social-login 自动失效 claim，J 组漂移会大幅减少）
- 注销的完整链路（与 social-login 的注销流程对齐顺序）
- 错误信封在适配层的解析（§2.5）与归一化下沉（§7）
- 登录链路识别"平台侧手机号已变"并调用换绑接口（§5.4）
- 管理端应用详情显示"用户中心已同步/未同步"（需 `uc_synced_at`）
- 账号列表/详情的管理端只读接口

### P2 · 规模与治理

- 分片 / 分区；RLS 纵深防御
- 批量对账接口（E8）
- `claim_types` 注册表（E1）
- KMS 接入（E7）

---

## 11. 风险与取舍

| # | 风险 | 影响 | 处理 |
| --- | --- | --- | --- |
| 1 | 契约改 app 维度时，social-login 与 UC **同时**在改 | 联调窗口内两边都对不上 | 先改 social-login 适配层 + 假对端（现在就能做），UC 按新契约实现；假对端可当"参考实现" |
| 2 | 归一化规则两边不一致 | 同一号码在两边 hash 不同，归并失效 | §7：同一批边界用例，两边各跑一遍；P1 下沉到单侧 |
| 3 | 强一致读被"优化"成读从库 | P0-6 防线失效，把错误账号并进来 | 代码层不提供从库连接；文档与注释写死原因 |
| 4 | 合并死锁 | 高峰期合并卡住，连接池耗尽 | 统一按 id 升序加锁；用例覆盖双向并发 |
| 5 | 凭证明文外泄 | 手机号批量泄漏 | 传输 TLS + 存储信封加密 + 日志脱敏 + 运维视图单独鉴权 |
| 6 | 应用未注册导致全量登录失败 | 一个配置错误 = 一个应用不可用 | 400 + 明确文案；上线检查表里加"应用已注册"一项 |
| 7 | 把 UC 做成 IdP（范围蔓延） | MVP 无限膨胀 | §1 的职责表作为验收边界；任何"要不要加登录"的讨论都回到 C4 |

### 关于"要不要现在做账号注销"的取舍

合规上必须有，但它牵动 social-login 的整条数据链路（绑定、令牌、事件），
MVP 里做半套反而更危险（用户以为注销了，其实另一侧还有数据）。
所以 P0 只做"UC 侧关闭账号 + 撤销凭证"这一个原子动作，
完整流程（通知业务方、清理 social-login 数据、可恢复窗口）放 P1 与 social-login 一起设计。

---

## 12. 决策记录与仍待确认

### 12.1 已确定（2026-11-02）

| # | 问题 | 结论 | 落在哪 |
| --- | --- | --- | --- |
| 1 | 应用注册由谁触发 | **唯一入口是登录中心管理端**（现有 `POST /admin/v1/apps`，分配 `app_code` + `app_secret`）。UC 侧不重发凭据，只做幂等同步 + 每 5 分钟对账；未注册 → 400 | §2.3、§2.6、§4.2 |
| 2 | 一个账号能否有多个同类型凭证 | **不能**。一个 app 下一个账号只挂一个手机号、一个邮箱；换号必须换绑，不能并存 | §3（`uk_claim_one_per_type`）、§5.2、§5.4 |
| 3 | `attrs` 是否放渠道原生字段 | **不放**，MVP 不设 `attrs` 列 | §9 E2 |

### 12.2 由此带来的三个必须注意的后果

决策 2 落地后，有三处会顺带改变行为，写在这里避免上线后被当成 bug：

1. **合并会丢手机号**。target 与 source 各有一个手机号时，保留 target 的，
   source 的撤销（`revoke_reason='merged_source'`）。用户可能会问"我另一个号呢"——
   客服需要能查到，所以撤销行必须保留、不能物理删除。
2. **纠正手机号需要换绑接口**。没有 `PUT .../claims/{type}` 就只能靠合并来改号，
   代价是关掉一个账号。这也是为什么它进了 P0（接口），而"谁来调"进 P1。
3. **注册态与登录态解耦**。建应用不依赖 UC 可用，但**登录依赖**：应用没同步到 UC 时，
   该应用所有登录都会 400 `APP.UNKNOWN`。所以对账任务不是锦上添花，是可用性组件。

### 12.3 仍待确认

1. **停用应用后 UC 是否也拒绝**：social-login 已经会拒（本地 `status` 检查），
   UC 侧再拒一层是纵深防御，但会让"同步停用状态"成为新的耦合点。倾向 P1 再说。
2. **换绑是否要留可撤销窗口**：用户误操作换号后，原号立即释放、可能被他人抢绑。
   是否需要 24 小时内可回滚？这会引入软删除与延迟释放，MVP 不做，但值得记一笔。
3. **合并时 source 的其他类型凭证**：按同一规则（目标优先）处理，是否需要在合并
   结果里回传"哪些凭证被丢弃"，让 social-login 记进事件、通知用户？倾向需要
   （否则用户侧无感知），但要看事件定义怎么落。

---

## 13. 变更记录

| 日期 | 变更 |
| --- | --- |
| 2026-10-30 | 首版 |
| 2026-11-02 | 按评审意见定三件事：① 应用注册入口统一在登录中心，UC 只做幂等同步（§2.6）；② 一个账号每类凭证只能有一条活跃，新增 `uk_claim_one_per_type` 与换绑接口（§3、§5.4）；③ 不设 `attrs` 列。合并的凭证规则随之改为按类型目标优先，source 同类型凭证撤销而非迁移（§5.2） |
| 2026-11-02 | **§2.6 应用注册同步落地**：`internal/application/accountsync`（非阻塞队列 + 全量对账 + 状态记录）、`POST /internal/v1/apps` 适配、迁移 00007、管理端展示；`-require-apps` 让假对端能验"未注册 → 不可登录" |
| 2026-11-02 | **契约 v1.1 已在 social-login 侧落地**：4 个方法签名 + 5 处调用点 + stub 分区 + 假对端 + 契约脚本（16 项）。新增 `ClaimReplacer` 可选端口承载换绑；`MergeResult` 增加 `DiscardedClaims`。见 `docs/implementation-status.md` §27 |
| 2026-11-02 | **P0 已实现**：`cmd/usercenter` + `internal/usercenter/**` + `migrations/usercenter/00001_init.sql`；契约 18 项全过、真实用户中心联调通过。见 §14 |

---

## 14. 实现记录（2026-11-02）

### 14.1 代码位置与运行形态

| 项 | 值 | 说明 |
| --- | --- | --- |
| 入口 | `cmd/usercenter` | 独立二进制，与 social-login 分开部署 |
| 代码 | `internal/usercenter/{config,domain,cryptox,store/postgres,service,httpapi,observe,app}` | 完整分层，见下 |
| 迁移 | `migrations/usercenter/00001_init.sql`（独立 embed FS） | 与 social-login 的 `migrations` 分开：两个服务两个库，共用一个目录会让"某服务没部署"在库里看不出来 |
| 数据库 | PostgreSQL，独立库 `user_center` | 不跨库 join、不跨库读表 |
| 配置文件 | `configs/usercenter.yaml`，环境变量前缀 `UC_` | 无 Redis、无 JWT、无渠道配置 |
| 本地启动 | `scripts/dev-usercenter.sh`（建库→迁移→启动）或 `docker compose up usercenter` | |
| Store | pgx v5 + 手写 SQL | 理由：部分唯一索引的 `ON CONFLICT ... WHERE` 推断、`ORDER BY id FOR UPDATE`、约束名区分——ORM 在这三处都会丢语义 |

分层与依赖方向（严格单向）：

```
domain   归一化 / 错误码 / 状态枚举      不依赖任何包
cryptox  HMAC-SHA256 派生 + AES-256-GCM  只依赖 domain
store    SQL 与事务                     只依赖 domain + pgx
service  排序、校验、组装、指标         依赖上面三者
httpapi  路由、鉴权、错误信封           依赖 service
app      装配与优雅关闭
```

### 14.2 与本文的三处有意偏离

| # | 本文原写法 | 实际实现 | 理由 |
| --- | --- | --- | --- |
| 1 | `idempotency_keys.scope` 含 `create_account \| merge`，Create 与 Merge 都写这张表 | Create 写 `idempotency_keys`；Merge 的幂等键只落在 `merges.idem_key` | 两处都记会出现"一处写成功、另一处没写"的不一致。Merge 本来就有流水表，幂等键挂在流水上即可；Create 没有流水表，才需要单独的键表 |
| 2 | `idempotency_keys.response` 存"结果快照"（完整账号报文） | 只存 `{"user_id":"..."}`，重放时按 id 重读当前状态 | 完整报文含凭证明文/密文，幂等表是排障时会被直接 query 的地方，不该成为第二份敏感数据。重读还能如实反映"账号后来被合并/关闭" |
| 3 | `merges.status`（merged \| rejected） | 只记成功合并，取消 `status` 列（保留 `reason`） | 被拒绝的合并没有副作用，重放时重新判定即可。写进去会让同键重放返回 `already_merged=true`，而那次调用并没有合并任何东西——这是对补偿任务撒谎（与 §5.2 第 1 条同源） |

另外两处**加强**（不在原文但成本为零）：

- `accounts` 增加 `UNIQUE (app_id, id)`，`account_claims` 用**复合外键** `(app_id, account_id) → accounts(app_id, id)`。这样"凭证的 app_id 与账号的 app_id 不一致"在数据库层面就无法提交（§6 第 1 层的加强）。
- 停用应用的拒绝在 P0 就做了（原文 §12.3 倾向 P1）。理由：`apps.status` 本来就在表里、查一次库顺带判断，而"停用"通常意味着安全或合规原因，多拒一层不是浪费。

### 14.3 几个实现层面的关键决定

1. **幂等与建号在同一个事务里**。分两段提交会引入两种新故障：进程在两步之间崩溃会留下永远"处理中"的键（该用户首次登录从此一直 409）；占位先提交而业务回滚，键又会被错误地当成"已完成"。放一个事务里，并发同键请求在唯一索引上排队，后来者读到的必然是完整结果。这也让 `ACCOUNT.IDEMPOTENCY_IN_PROGRESS` 在正常情况下不可达——保留它只为兼容将来改成两段式。
2. **换绑用乐观并发，不加 `FOR UPDATE`**。两个换绑同时来，各自读到同一个旧凭证 id，都执行 `UPDATE ... WHERE id=$old AND revoked_at IS NULL`；PostgreSQL 行锁让后到者等待，提交后重检谓词得到 0 行 → `ACCOUNT.CONFLICT`。若加了 `FOR UPDATE`，后到者会看到新凭证、把它撤销、再插自己的，两个都返回 200——用户以为换成了 A，实际生效的是 B。
3. **哈希用长度前缀而非 NUL 分隔**。`("a","\x00b")` 与 `("a\x00","b")` 在分隔符方案下会拼出同一条消息（单测抓到的真实碰撞）。布局：`appID(8) ‖ len(type) ‖ type ‖ len(value) ‖ value`。
4. **`by-claim` 不校验凭证格式**。传 `__nobody_123` 时正确答案是 404「没有账号持有」，而不是 400「参数不合法」。校验只发生在建号与换绑（垃圾值入库会占住唯一索引，表现为"某个真实号码注册时提示已被占用"，占用者是空字符串）。
5. **应用解析不缓存**。唯一索引单行查询，p99 亚毫秒；缓存会引入"停用后仍能登录若干秒"的窗口和一套一致性代码。本服务没有的东西（会话、分布式锁）都是刻意的减法，这里同样不为省一次查询加复杂度。
6. **单条凭证解密失败只跳过、不毁整个账号**。密钥配置出错会一次影响一批账号；让它们完全不可读（登录 500）比"少返回一条凭证"（漂移检测多报一条）危害大得多。

### 14.4 验收结果

| 判据（§10 P0） | 结果 |
| --- | --- |
| `scripts/check-usercenter-contract.sh <base> <token> --write --app a --app2 b` | **18 项全过**（含应用注册、404 信封、幂等重放、强一致读、跨应用隔离、跨应用合并拒绝、换绑与旧值释放） |
| social-login 指向真实 UC 后跑 HTTP provider 用例 | `test/acceptance/account_http_real_test.go` 两项通过：登录 302 → 绑定里记的是 UC 的 ULID → 用适配层按 id 回查 UC 得到 active 账号；未注册应用登录失败 |
| 并发用例 | 10 并发同键 → 1 个账号；10 并发同凭证（不同键）→ 1 成功 9 个 `CLAIM_TAKEN`；A→B 与 B→A 并发 → 无死锁且恰好 1 个真正合并 |
| 集成测试 | `internal/usercenter/service/integration_test.go` 13 个用例连真 PG 通过（含合并丢弃凭证、注销释放、停用应用拒绝） |

### 14.5 尚未做（与 §10 的分期一致）

- **P0.5**：审计日志（谁在什么时候对哪个账号做了什么）、慢查询与连接池调优、`uc_sync_failed` 类 gauge。
- **P1**：`claim.invalidated` 推送、注销的完整链路、`ClaimReplacer` 接登录链路、管理端账号只读视图。
- **P2**：分区/RLS、批量对账、`claim_types` 注册表、KMS。

一个需要说明的运维缺口：**应用注册同步的"停用"目前只影响新请求**。库里已有账号不受影响，本服务也不会因为应用停用而拒绝返回它们的凭证——停用的语义是"不许再用这个应用登录"，不是"删数据"。

---

## 15. 代码边界规则（2026-11-02 确认）

### 15.1 规则

一句话：**同一仓库、同一 Go module、共用通用工具包，但两个服务的业务代码零相互依赖。**

| 项 | 允许 | 说明 |
| --- | --- | --- |
| 同一 git 仓库 / 同一 `go.mod` | ✅ | 一次 `go build` 就能发现契约改动漏改的地方，这是现阶段最大的收益 |
| 共用 `internal/pkg/**` | ✅（有例外） | 见 §15.2，`pkg` 下并非都是通用工具 |
| 登录中心引用用户中心的任何包 | ⛔ | 需要账号数据就调 HTTP 契约（`infrastructure/account`） |
| 用户中心引用登录中心的任何业务包 | ⛔ | 需要"应用是否存在"就查自己的 `apps` 表 |
| 任何一方引用对方的迁移 / 配置 / 装配 | ⛔ | 迁移各用各的 embed FS，配置各读各的文件 |
| `test/contract` 同时引用两边 | ✅（唯一例外） | 见 §15.3 |

### 15.2 「放在 pkg 目录下」不等于「通用」

判断标准只有一条：**包里的标识符换到另一个服务里是否仍然成立**。

| 包 | 是否可共用 | 判断 |
| --- | --- | --- |
| `pkg/ids` | ✅ | ULID 生成，与业务无关 |
| `pkg/metrics` | ✅ | Prometheus 文本导出，不含任何业务指标名 |
| `pkg/httpx`、`pkg/guards`、`pkg/reqmeta`、`pkg/jwtkit` | ✅ | 通用 HTTP / 熔断 / 请求元数据 / JWT 工具 |
| `pkg/errs` | ⛔ | 里面有 `AUTH.*`、`BIND.*`、`PROVIDER.*`——**登录侧的业务错误码**，用户中心用它就是引用了登录中心的业务语义 |
| `pkg/adminx` | ⛔ | 管理端会话与权限，只有登录中心有管理端 |

脚本里把这两个列成显式例外（`PKG_BIZ`）。将来往 `pkg` 加东西时，按上面那条标准自查一次；拿不准就单独建包，不要塞进 pkg 假装通用。

用户中心当前的依赖是干净的：生产代码只用了 `pkg/ids` 与 `pkg/metrics`。

### 15.3 唯一的跨服务交叉点：`test/contract`

"两边的错误码必须一致"这件事天然需要同时看到两边。它不能放在任一服务内部（那就是相互依赖），所以单独放在 `test/contract/`：

```
test/contract/
  doc.go                    说明这个目录为什么存在、边界由谁强制
  usercenter_codes_test.go  三方错误码 + 幂等键头的一致性断言
```

`test/` 不参与任何服务的构建，也不属于任何一方，因此它是唯一豁免区。**新增跨服务断言请放这里，不要放回服务内部。**

顺带说明：`test/acceptance/` 是登录中心的端到端验收，它可以引用登录中心自己的包，但**不得**引用用户中心的类型——对端只能通过 HTTP 访问（`account_http_real_test.go` 就是这么做的）。

### 15.4 强制方式

```bash
bash scripts/check-service-boundary.sh   # 或 make boundary / make lint
```

三层检查：

1. **传递依赖**（`go list -deps`）：能抓到 `A → B → usercenter` 这种间接引用，只看直接 import 会漏。
2. **直接 import**（grep，含 `_test.go`）：`go list -deps` 不含测试依赖，而测试恰恰是最容易"就一行断言，放这儿吧"的地方。
3. **白名单**：确认只有 `test/contract` 跨了服务，且该目录里没有混入业务逻辑。

已做负向验证：在用户中心里 import `infrastructure/account`、在登录中心 import `usercenter/domain`、让用户中心引用 `pkg/errs`，三种情况都返回退出码 1。**一个永远绿灯的检查等于没有检查**，所以这个脚本本身需要能证明它会红。

### 15.5 违规时怎么改（三种修法）

| 场景 | 错误做法 | 正确做法 |
| --- | --- | --- |
| 想复用对方的领域类型 | `import internal/usercenter/domain` | 在自己的 domain 里定义同名概念；跨服务只传 JSON |
| 想复用对方的错误码常量 | 引用对方的 `Code*` | 各写一份字面量，由 `test/contract` 断言相等（这样漂移才测得出） |
| 想复用对方的工具函数 | 从业务包 import | 若确实通用，提到 `internal/pkg/`；若不通用，各写一份 |

### 15.6 与"将来拆成两个仓库"的关系

这条规则不是为了永远同仓库，而是让"拆"随时可做、成本可估：只要业务代码零交叉，拆库就只剩两件事——把 `pkg/ids`、`pkg/metrics` 提成公共 module（或各复制一份），以及把 `test/contract` 的两边断言换成契约文件比对。

现在不拆，只是因为同仓库改契约更省事（v1.1 那次改了 4 个方法签名 + 5 处调用点，一次编译就全找到了）。边界护栏的存在，让"现在不拆"成为一个可逆的决定。
