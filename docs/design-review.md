# 三方登录统一接入服务 · 设计审查报告

> 审查对象：`docs/architecture-design.md` v0.7
> 审查日期：2026-10-13
> 审查范围：全文一致性、设计正确性、安全性、扩展性
>
> ---
> **修复状态（2026-10-14）**：本报告的 A1～A16、P0-1～P0-6、P1-1～P1-8、P2-1～P2-4 及扩展留口 E1 / E3 / E4 / E5 / E6 / E7 / E8 / E10 **已在 `architecture-design.md` v0.8 中全部修复**，映射明细见该文档 **§14.2 审查修复记录**。
> 遗留待实现：**E9**（`ClaimValidator` SPI）、**E2 的完整 OIDC 兼容**（v0.8 仅提供 JWKS 与 discovery 骨架）。
> 本报告保留原样作为**问题台账**，编号可在两份文档间双向检索。

---

## 0. 结论摘要

| 维度 | 结论 | 严重度 |
| --- | --- | --- |
| **核心架构** | 站得住。D1（平台 × 接入场景二维路由）、D7（编译期注册）、C4（`remote` 账号模式）三个决策没有发现结构性错误 | — |
| **文档一致性** | **较差**。16 处"同一事实在不同章节说法不一致"，集中在 v0.4～v0.7 快速迭代时未回改的旧段落 | 中 |
| **安全性** | **2 处 P0**：`identity_claims` 唯一索引把未验证凭证也算进去（导致归并判定失真）；缺 JWKS 端点（业务方根本无法验签） | **高** |
| **正确性** | **1 处 P0**：两段式合并存在永久孤儿窗口 | **高** |
| **扩展性** | 整体良好，但有 **3 处会"撞墙"的硬限制**（配置唯一键、缺 JWKS/OIDC、无上游 IdP 扩展位） | 中高 |

**总体判断**：设计方向正确，不需要推倒重来。但**当前状态不能直接进入编码**——P0 问题会导致线上数据错误或功能不可用，文档冲突会让开发者按错误的理解实现。

**统计**：16 处文档冲突 · 6 项 P0 · 8 项 P1 · 4 项 P2 · 10 项扩展性缺口。

---

## 1. 文档内冲突清单

这些不是"设计有争议"，而是**文档里两处说法不一致，照着哪一处实现都可能错**。

### A 组 · 关键概念冲突（会造成实现错误）

| # | 冲突内容 | 位置 | 修正建议 |
| --- | --- | --- | --- |
| **A1** | **`sub` 的定义自相矛盾**。§8.1 明确决定 `sub` = 业务方 `external_user_id`，并专门论证了"再生成别名纯属多余"；但 §10.1 的"用户枚举"一行仍写"对外 `sub` 使用随机别名" | §8.1 vs §10.1 | 改 §10.1：`sub` 的可枚举风险已转嫁到用户中心（要求不可枚举 ID），本服务不做别名 |
| **A2** | **Identity 唯一索引不一致**。D4 写 `(provider, provider_app_id, open_id)`；§6.2 DDL 是 `(app_id, platform, provider_app_id, open_id)` | `D4` vs `§6.2` | 按 DDL 修正 D4——D4 是 C1 生效前的残留，**缺 `app_id` 会直接破坏应用隔离** |
| **A3** | **冲突策略清单已过时**。D4 把 `reject`/`verify_then_merge`/`auto_merge`/`transfer` 列为"可配置项"；§7.2/§7.5 已改为由 `merge.mode`（`auto`/`confirm`/`manual`）驱动，且 `transfer` 明确不开放配置 | `D4` vs `§7.2 §7.5` | 重写 D4 该条，只保留"冲突策略由 `policy.merge.mode` 驱动"的引用 |
| **A4** | **D2 节内部自相矛盾**。先写"绑定/登录时按优先级自上而下匹配；全部未命中才创建新账号"（即自动归并），后文又写"默认策略是只匹配不归并" | `D2` 内部 | 前半句加限定：**该行为仅在 `merge.on_login = claim_verified` 时启用** |
| **A5** | **§5.1 时序图未反映 C4 分支**。图中 ⑩ 直接"落库 identity+binding"、⑪ 302 回业务方；但 C4 下默认 `need_register`，回调时**不应该建 binding**，而是返回 `AUTH.NEED_REGISTER` | `§5.1` vs `§5.2` | 时序图增加分支：无活跃绑定 → 返回 NEED_REGISTER（不落 binding） |
| **A6** | **`identity_claims.source` 枚举不一致**。§6.2 DDL 注释：`wechat_phone \| alipay_phone \| sms \| manual`；§7.5.3 安全白名单：`wechat_phone \| alipay_phone \| sms_verified \| apple_email` | `§6.2` vs `§7.5.3` | 统一为一处权威枚举；`sms` → `sms_verified`，补 `apple_email`。**这是 R4 红线的判定依据，不能含糊** |
| **A7** | **refresh token 轮转字段名不一致**。§8.2 写"标记 `RT1.rotated_to = RT2.id`"；DDL 只有 `rotated_from`（在新令牌上指向旧令牌） | `§8.2` vs `§6.2` | 保留 `rotated_from` 单向链即可，改 §8.2 |
| **A8** | **§9.1 仍把已删除的 `accounts` 列为隔离对象**，且遗漏 `identity_claims`、`merge_operations` | `§9.1` | 更新为：`oauth_identities` / `oauth_bindings` / `identity_claims` / `refresh_tokens` / `merge_operations` / `auth_audit_logs` |

### B 组 · 术语与表述冲突（易误读，不致命）

| # | 冲突内容 | 位置 | 修正建议 |
| --- | --- | --- | --- |
| **A9** | **§1.1 第 4 条与文首规则 2/3 矛盾**。§1.1 写"用户在 iOS 和 Android 上的三方身份可能被识别成两个人"；但规则 2/3 明确 iOS 与 Android 同属 `wechat:app`，共享同一 openid，**不会分裂** | `§1.1` vs 术语章节 | v0.5 改术语时漏改此处。改为"用户在**不同接入场景**上的三方身份可能被识别成多个人" |
| **A10** | **`platform` / `provider` 命名不统一**。表字段与文档用 `platform`；API 参数、回调路径 `/v1/oauth/callback/{provider}`、接口名 `Provider` 用 `provider` | 全文 | 二者语义相同但混用会让开发者迷惑。建议：概念层用 **平台 Platform**，代码标识统一 `platform`；`Provider` 仅保留为"适配器"的接口名并注释说明 |
| **A11** | **Scene 枚举四处不一致**。§4.1 注释 `official_account/mini_program/web/app`；§6.2 注释 `official_account/mini_program/app/pc_qr`；§1.2 用中文名 | 多处 | 建立**唯一权威的 Scene 枚举表**，其余位置引用 |
| **A12** | `CapabilitySet.HasUnionID` 注释为"是否提供跨应用归并标识"，与 C1（不跨应用）冲突 | `§4.1` | 改为"是否提供跨接入场景的归并标识" |
| **A13** | §4.3 表头写"跨应用归并"，与 C1 冲突 | `§4.3` | 同上，改为"跨接入场景归并" |
| **A14** | §1.4 的 C3 行写"**必须**引入手机号/邮箱等多源归并依据"，与 C5 默认不自动归并冲突 | `§1.4` | 改为"引入多源**归并依据与验证手段**"（依 `merge` 配置决定是否用于自动归并） |
| **A15** | §14 第 5 项仍写"多端归并策略"，术语未随 v0.5 更新 | `§14` | 改为"跨接入场景归并策略" |
| **A16** | §5.3 的 `/v1/bind` 说明"入参含 `bind_ticket`"，但 §6.3 Redis 键表**没有 `bind_ticket` 的 key 定义** | `§5.3` vs `§6.3` | 补 `oauth:bindticket:{ticket}` 的 key 设计（内容、TTL 10min） |

---

## 2. 设计缺陷

### P0 · 必须先修，否则会导致线上数据错误或功能不可用

#### P0-1 · `identity_claims` 唯一索引把"未验证"凭证也算进去 ★★★

**位置**：§6.2 DDL

```sql
    -- 一个应用内，同一个已验证凭证只能属于一个身份 → 这就是归并的判定依据
    UNIQUE (app_id, claim_type, claim_value_hash)   -- ← 注释说"已验证"，约束里却没有 verified
```

**问题**：约束对**所有** claim 生效，包括 `verified = false` 的。后果：

```
用户 A 注册时手填手机号 138xxxx（未验证）→ 占用唯一键
用户 B 用真实微信授权拿到同一个 138xxxx（已验证）→ 插入冲突，登录失败
```

`revoked_at` 也没进索引，导致解绑/换绑手机号后**原号码无法再被任何人占用**，越积越多。

**修正**：改为部分唯一索引，与注释语义一致。

```sql
DROP INDEX ...;
CREATE UNIQUE INDEX uk_claims_verified
    ON identity_claims (app_id, claim_type, claim_value_hash)
    WHERE verified = true AND revoked_at IS NULL;
-- 未验证的 claim 只需普通索引，不参与唯一性判定
CREATE INDEX idx_claims_unverified
    ON identity_claims (app_id, identity_id)
    WHERE verified = false;
```

MySQL 无部分唯一索引，需用「生成列 + 唯一索引」实现（`CASE WHEN verified AND revoked_at IS NULL THEN hash ELSE NULL END`，NULL 不参与唯一性）。

#### P0-2 · 缺少 JWKS 端点，业务方无法验签 ★★★

**位置**：§5.3 API 清单 / §8.1

**问题**：§8.1 明确 `access_token` 是 ES256 签名 JWT、业务方"本地验签，无网络开销"。但 API 清单里**没有任何暴露公钥的端点**。业务方拿不到公钥 → 本地验签无法实现 → 只能每次调 `/v1/introspect`，`introspect` 又变成性能瓶颈。

**修正**：增加两个端点。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/v1/jwks` | 暴露 JWKS（公钥集，含 `kid`），供业务方本地验签 |
| GET | `/.well-known/openid-configuration` | OIDC Discovery（若要做 OIDC 兼容） |

同时需要定义**签名密钥轮换**策略：JWKS 中同时发布新旧两把公钥，等旧 token 全部过期后再下线。

#### P0-3 · 两段式合并存在永久孤儿窗口 ★★★

**位置**：§7.3

**问题**：当前描述把跨服务调用包在数据库事务里：

```
事务 A：写 merge_operations(pending) → 调 AccountProvider.Merge（HTTP）→ 提交
```

若**远端合并成功但事务 A 提交失败** → 本地无记录 → 补偿任务扫不到 → **远端已合并、本地仍视为两个独立账号**，且不会有任何重试。反向撕裂只在这一侧发生，且不可逆。

附带问题：HTTP 调用放在数据库事务内会长时间占用连接与行锁，高并发下是隐患。

**修正**：拆成三次独立事务，网络调用不持有数据库事务。

```
① 独立事务提交 merge_operations(status = pending)   ← 先持久化，保证可补偿
② 调 AccountProvider.Merge(target, source, idemKey) ← 带幂等键
③ 独立事务：改绑 oauth_bindings + 撤销 tokens + 置 status = done
```

任一步失败都可安全重试；补偿任务只需扫描 `status = 'pending'`。

#### P0-4 · `AccountProvider.Merge` 缺少幂等键参数 ★★★

**位置**：D3 接口定义 vs §7.3 描述

**问题**：§7.3 明确写"跨服务调用，**必须带幂等键**"，但接口签名是：

```go
Merge(ctx context.Context, targetUserID, sourceUserID string) error   // ← 没有幂等键
```

补偿任务重试时，用户中心无法判断这是"新请求"还是"重试"，可能重复执行合并（重复迁移订单、重复发通知）。

**修正**：

```go
type MergeRequest struct {
    IdempotencyKey string   // 由本服务生成，全局唯一（如 merge_operations.id）
    TargetUserID   string
    SourceUserID   string
    Reason         string   // 便于用户中心审计
}
Merge(ctx context.Context, req MergeRequest) (*MergeResult, error)
```

同步更新 §13「用户中心的建设要求」中的该条约定。

#### P0-5 · access_token 撤销存在最长 15 分钟窗口 ★★

**位置**：§8.1 / §10.2

**问题**：`access_token` 本地验签、有效期 15 分钟。账号劫持、注销、强制下线等场景下，**已签发的令牌在到期前仍然有效**，安全响应最长延迟 15 分钟。文档只提到撤销 `refresh_tokens`。

**修正**（三选一或组合）：

| 方案 | 说明 | 代价 |
| --- | --- | --- |
| jti 黑名单 | Redis 存已撤销的 `jti`，TTL = 剩余有效期；业务方验签后需查一次（或本服务在 introspect 时查） | 削弱"无网络开销"的优势 |
| 缩短有效期 | 15min → 5min，配合 refresh 频繁轮转 | 增加 refresh 调用量 |
| 版本号判定 | JWT 内加 `token_version`，账号级版本号入 Redis；撤销时 +1 | 仍需网络查询 |

建议：**默认 15 分钟 + jti 黑名单仅对"高危撤销"（账号劫持、注销）生效**，通过 `revoked_jti` 集合实现，业务方可选择是否校验。

#### P0-6 · 手机号存在两个权威源，无同步机制 ★★

**位置**：§6.2 `identity_claims` vs D3 `AccountProvider.GetByClaim` / C4

**问题**：手机号同时存在于：

- 本服务 `identity_claims`（用于归并判定与验证）
- 用户中心（账号主数据的手机号，C4 下才是主源）

业务方在用户中心改了手机号后，本服务 claim **不会同步**，导致：

- `merge.on_login = claim_verified` 的自动归并基于**过期数据**判定
- `GetByClaim` 与 `identity_claims` 两个"按手机号查账号"的入口结果可能不一致（见 P1-1）

**修正**：明确权威源与同步策略，三选一：

1. **claim 仅作为"本次授权中平台证明过的凭证"记录**，不声称是账号当前手机号；归并判定前**回源用户中心校验**（可靠但慢）
2. 用户中心手机号变更时**主动推送** `claim.invalidated` 事件给本服务
3. 归并前强制 `GetByClaim` + `identity_claims` **双向比对**，不一致即拒绝归并并告警（最保守）

建议方案 1 + 3 组合。**这条必须在用户中心建设前定下来**，否则后期改动涉及两个服务。

---

### P1 · 应在第一期～第三期之间修复

| # | 问题 | 位置 | 修正建议 |
| --- | --- | --- | --- |
| **P1-1** | `AccountProvider.GetByClaim` 与 `identity_claims` **职责重叠**，两个"按手机号查账号"的入口 | D3 / §6.2 | 明确定位：`identity_claims` 只用本服务内部归并判定；`GetByClaim` 用于**跨到用户中心核对账号真实性**。在接口注释中写清 |
| **P1-2** | 小程序 `session_key` **生命周期未设计**。微信 `getPhoneNumber` 需 `session_key` 解密，这是 R4 红线 1 的关键路径，但 `TokenSet` 结构未提，也无存储设计 | §4.1 / §4.3 | `TokenSet` 增加 `SessionKey` 字段 + 过期时间；明确存储位置（Redis，TTL 跟微信一致）与"解密手机号后是否立即丢弃" |
| **P1-3** | Apple `nonce` **无存储设计**。§4.4 要求"nonce 与授权时一致"，但 §6.3 Redis 键表无对应条目 | §4.4 / §6.3 | 复用 `oauth:ticket:{state}` 存 nonce，或单独 `oauth:nonce:{nonce}`；写明 |
| **P1-4** | `Provider.Unbind` 是**可选实现**，但 §10.2 注销流程依赖它 | §4.1 / §10.2 | 明确降级：返回 `ErrNotSupported` 时，本服务本地解绑 + 记录"需用户手动到三方侧撤销"，并向用户展示指引 |
| **P1-5** | §7.5.4 配置校验第 1 条**应为 error 而非 warning** | §7.5.4 | `mode=auto` + `on_login=claim_verified` 但无可用 claim 渠道时，`auto` 会静默退化为"不归并"，用户以为开了自动合并却实际没有。**应拒绝保存** |
| **P1-6** | §7.5.2 场景 A 中 `confirm` 模式写"可返回提示同手机号已有账号"，但同表又写 `on_login` **强制 off** —— 要检测就必须读 claim 并比对，逻辑矛盾 | §7.5.2 | 明确：`confirm` 下**不做** claim 检测（保持纯粹）；若产品需要"提示"，另加 `on_login: "detect_only"` 档位并明确其不产生归并 |
| **P1-7** | **缺出站 Webhook 的签名、重试、去重设计** | §5.3 | 补：HMAC 签名头、指数退避重试（如 5 次）、`event_id` 供业务方去重、失败进入死信 |
| **P1-8** | **限流维度不全**。仅有 `rl:{appId}:{ip}` | §6.3 | 补 provider 维度（微信日限额）、identity 维度（防撞库）、全局维度；并明确超限行为 |

---

### P2 · 可以延后，但应记录

| # | 问题 | 位置 | 建议 |
| --- | --- | --- | --- |
| **P2-1** | Apple 通知端点硬编码为 `/v1/oauth/notify/apple` | §5.3 | 改为 `/v1/oauth/notify/{platform}` 通用端点，为其他平台预留 |
| **P2-2** | `transfer` 策略说"仅可通过管理台手工触发"，但 **API 清单无对应端点** | §7.2 / §5.3 | 补 `POST /admin/v1/bindings/{id}/transfer` |
| **P2-3** | **无三方平台健康检查/熔断** | §4.1 | `Provider` 增加可选接口 `HealthChecker`；接入熔断器，平台故障时快速失败而非拖垮线程池 |
| **P2-4** | 凭据信封加密排在**第四期**，但第一期就要存渠道配置 | §13 | 第一期至少用**本地密钥 + AES-GCM** 加密（不上 KMS），避免明文凭据进入测试环境并被复制到生产 |

---

## 3. 扩展性评估

### 3.1 已经做对的部分

这些设计确实带来了可扩展性，经得起后续加需求：

| 设计 | 扩展收益 |
| --- | --- |
| **D1 · 平台 × 接入场景二维路由** | 新增一个接入场景 = 新增一个文件；`wechat` 从 1 个场景扩到 4 个场景没有改核心流程 |
| **D7 · 编译期注册 + blank import** | 新增平台 = 新增一个包 + 一行 import，符合"对扩展开放、对修改封闭" |
| **规则 2 · 承载形态不进路由键** | 新增 iOS/Android/鸿蒙/Web 客户端**零服务端改动** |
| **`applications.policy` JSONB** | 新增策略（如 `on_unbound_login`、`merge.*`）不改表结构 |
| **`app_provider_configs.extra` JSONB** | 各平台私有参数（回调域名、支付开关等）不改表 |
| **`identity_claims.claim_type`** | phone / email / union_id / custom 可扩展，未来接新的归并依据不用改表 |
| **`merge` 配置化** | S1 与 S2 共用同一套代码，仅靠配置区分——这是 v0.7 最成功的抽象 |
| **`account_links` 留口** | 未来要做跨应用 SSO 时是纯增量演进，不需要重构现有表 |

### 3.2 会"撞墙"的硬限制（建议尽早处理）

| # | 限制 | 触发场景 | 后果 | 建议 |
| --- | --- | --- | --- | --- |
| **E1** ★ | `app_provider_configs` 唯一键 `(app_id, platform, scene)` **限制一个业务应用在同一场景下只能配一套凭据** | 一个业务应用要接**两个小程序**（主/子）、或同一平台有多套开放平台账号 | 需要改唯一键 + 改路由逻辑，**属于破坏性变更** | 现在就加 `config_key` / `alias` 字段，唯一键扩为 `(app_id, platform, scene, config_key)`，路由键增加可选第四维（不填则走 `default`） |
| **E2** ★ | **缺 JWKS / OIDC Discovery**（同 P0-2） | 业务方要本地验签；未来要兼容标准 OIDC 客户端 | 无法验签；或被迫大改令牌体系 | 见 P0-2 |
| **E3** ★ | **无上游 IdP（OIDC / SAML）扩展位**。§1.3 承诺"架构上预留扩展位"，但全文没有任何落地设计——**这是一个空承诺** | 未来要接入企业 SSO、或让本服务作为 IdP 被其他系统联邦 | 需要新增一整套抽象，改动面大 | 把 `Provider` 抽象再上提一层为 `IdentitySource`（三方渠道 / 上游 IdP / 本地密码都是它的实现），`Provider` 只是其中一种。**现在改动成本极低，后期很高** |
| **E4** | **Scene 无权威枚举与治理** | 新增场景时字符串散落各处，易冲突/拼写错误 | 配置写入无效值，运行时才报错 | 建立 Scene 常量表 + Admin 校验 + 文档权威表 |
| **E5** | **无环境（prod / test）隔离维度** | 同一业务应用无法同时配置测试与生产凭据 | 需部署两套服务或手工切换，易产生测试凭据打进生产的风险 | `app_provider_configs` 加 `env` 字段，或在 `applications` 上加 `env` |
| **E6** | **无凭据轮换的过渡期设计**。`provider_app_id` 与 `secret_cipher` 1:1 | 轮换 appSecret 时，旧密文立刻失效 | 轮换即中断服务，或需停服窗口 | 支持 `secret_cipher_prev` + 过渡期双验证，轮换后保留 N 天 |
| **E7** | **限流/配额无 provider 维度** | 微信日调用量被打满 | **一个应用的行为会影响所有应用** | 按 provider 维度做配额与排队 |
| **E8** | **Webhook 事件无版本化** | 事件结构变更 | 直接破坏所有已接入的业务方 | 事件体带 `schema_version`，重大变更走新版本号 |
| **E9** | **`claim_type` 无校验器注册机制** | 新增凭证类型（企业工号、设备指纹）需改核心代码 | 扩展需侵入核心 | 定义 `ClaimValidator` SPI，按 `claim_type` 注册 |
| **E10** | **Provider 接口无版本/能力协商** | 三方平台 API 升级（如微信新版本接口） | 只能就地改适配器，无法灰度 | `Metadata` 增加 `APIVersion`；适配器内部做版本分支 |

### 3.3 扩展性缺口小结

按"修补成本随时间增长的速度"排序，**最该现在处理的三件事**：

1. **E3 · 把 Provider 抽象上提为 IdentitySource** —— 现在只需改一个接口名和一层目录结构；等接入企业 SSO 时再改，要动核心编排
2. **E1 · 给 `app_provider_configs` 预留 `config_key`** —— 现在加字段是零成本；等有应用要接第二个小程序时，是破坏性变更
3. **E2 · 补 JWKS / OIDC Discovery** —— 与 P0-2 同源，属于"不做就无法上线"的功能缺口

---

## 4. 建议修复顺序

按"阻塞性 × 修复成本"排序：

### 第一批 · 立即修（1～2 小时，纯文档）

A1～A16 全部。这些都是**文档内自相矛盾**，不改会让开发者按错误理解实现。尤其 **A2**（唯一索引缺 `app_id`）、**A6**（R4 红线判定依据的枚举不一致）优先级最高。

### 第二批 · 编码前必须定（设计定稿）

| 编号 | 事项 | 说明 |
| --- | --- | --- |
| P0-1 | `identity_claims` 唯一索引改部分唯一 | 涉及 DDL，必须在建表前定 |
| P0-3 | 两段式合并改三次独立事务 | 涉及核心流程 |
| P0-4 | `AccountProvider.Merge` 加幂等键 | 涉及接口签名，**要和用户中心一起定** |
| P0-2 | 补 JWKS 端点 | 涉及密钥体系，建签名逻辑前必须定 |
| P0-6 | 手机号权威源与同步策略 | **必须和用户中心一起定**，跨服务 |

### 第三批 · 第一期～第三期之间

P0-5（token 撤销窗口）、P1-1～P1-8、P2-1～P2-4。

### 第四批 · 架构留口（低成本，建议顺手做）

E3（IdentitySource 抽象）、E1（`config_key` 预留）、E10（Provider 版本字段）。这三项现在做成本极低，属于"给未来的自己留门"。

---

## 附录 · 审查方法说明

| 步骤 | 内容 |
| --- | --- |
| 1 | 全文通读，建立"同一事实出现的所有位置"索引 |
| 2 | 交叉比对：术语定义章节 vs 各章节实际用法；DDL vs 正文描述；接口签名 vs 调用方描述；API 清单 vs 流程描述 |
| 3 | 逐条推演失败路径：跨服务调用的事务边界、并发写入、平台异常返回、配置非法组合 |
| 4 | 扩展性压力测试：假设要加第 5 个场景 / 第 6 个平台 / 第二个小程序 / 企业 SSO，逐项判断需要改动哪些层 |
| 5 | 安全对抗推演：以攻击者视角检查归并判定、绑定冲突、令牌撤销、凭证唯一性 |

**未覆盖范围**：性能压测数据、具体三方平台 API 的字段级正确性（需对照官方文档逐条核验）、前端/客户端 SDK 设计、成本估算。
