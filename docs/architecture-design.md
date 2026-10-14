# 三方登录统一接入服务 · 架构设计

> 版本 v0.12 · 目标：一个通用的、多应用多平台的社交登录接入网关（Social Login Gateway）
> 技术栈：Go 1.22+ / MySQL 或 PostgreSQL / Redis
>
> 变更记录：
> - v0.2 确认「账号按应用隔离」（C1）与「必须支持 Apple 登录」（C2），据此调整 `oauth_identities` / `accounts` 表结构，新增 Apple 专项说明（§4.4）
> - v0.3 确认「不支持跨应用归并用户信息」（C3），unionid 归并路径失效。据此重写 D2 为多源归并键模型、新增 `identity_claims` 表、新增无 unionid 条件下的三套归并策略（§7.4）
> - v0.4 确认「账号主体采用 `remote` 模式，复用现有用户中心」（C4）与「归并策略采用独立账号 + 引导绑定」（C5）。据此**移除 `accounts` 表**、`oauth_bindings` 改为持有外部账号引用、定义 `AccountProvider` SPI、并调整首次登录流程不可独立完成的链路
> - v0.5 澄清术语：**「应用」指完全独立的业务单元（App1、App2），不等于同一应用下的 iOS / Android / 小程序等承载形态**。新增术语定义章节并全文校准，D1 中明确承载形态不参与路由
> - v0.6 明确 C4 + C5 的组合结论：**同一业务应用内、跨接入场景的同一用户支持账号合并**，提升为正式需求 R1/R2/R3，并补充合并验证手段
> - v0.7 需求 R2 改为**可配置化**：应用接入时可选择 `auto`（自动合并）/ `confirm`（用户确认）/ `manual`（仅提示）。新增 §7.5 配置模型，并确立 R4 安全红线（`auto` 必须基于平台已验证凭证 + 被合并账号须通知）
> - v0.8 **依据 `docs/design-review.md` 完成审查修复**：修复 16 处文档内冲突、6 项 P0 缺陷（`identity_claims` 部分唯一索引、JWKS 端点、三次独立事务合并、`Merge` 幂等键、jti 撤销黑名单、手机号权威源）、12 项 P1/P2 问题，并补齐 E1/E3/E10 三项架构扩展留口
> - v0.9 **新增 §15 管理端接口设计（Admin API）**：v0.8 及之前全文有 12 处提及"管理台/管理员"但只有 2 个具体接口，其余均为悬空需求。本节补齐 11 组共 52 个管理端接口、管理员身份与 RBAC 模型、管理端与业务端的隔离约定、高危操作二次确认机制与分期落地
> - v0.10 新增约束 **C6「调用外部渠道不做网络重试，重试责任归接入方」**，新增 §5.5 重试边界与失败语义（含 `retryable` 错误契约、分层超时、渠道熔断、`context.WithoutCancel` 取消隔离）；§5.3 错误响应新增 `retryable` 字段；熔断与超时从第四期提前至第二期
> - v0.11 **新增 §5.6 渠道熔断设计**：v0.10 有 5 处提及"熔断"但无落地设计（同类悬空需求）。补齐选型（`sony/gobreaker/v2`）、粒度（按 `platform`）、关键规则（**只有 `retryable` 错误计入熔断**，否则可被无效 code 攻击触发服务级拒绝服务）、服务级配置（不下放应用级）、与 `HealthChecker` 的职责分离、多副本一致性限制、熔断后行为与管理端复位接口
> - v0.12 **熔断判定信号扩展为四类独立统计**（§5.6.4b）：v0.11 用单一 `failure_ratio` 统计所有失败，丢了区分度——超时（慢失败）与 5xx（快失败）对资源的消耗差一个量级，且平台"半死"时典型表现是高延迟+低错误率，只看错误率永远触发不了熔断。现拆为 `failure_ratio` / `timeout_ratio` / `slow_ratio` / `consecutive_timeouts` 四类独立阈值；新增 §5.6.4c 说明 gobreaker 的能力边界（分类统计需自维护滑动窗口）；新增 §5.7 入站请求超时保护（与渠道熔断的概念区分）

---

## 术语定义（先读，全文以此为准）

本文档此前在表述上有过一处混淆：把「业务应用」和「承载形态」当成同一件事。以下定义是全文的基准，后续所有章节均遵循。

| 术语 | 代码标识 | 含义 | 举例 |
| --- | --- | --- | --- |
| **组织** | — | 使用本服务的整体，内含多个**完全独立的业务应用** | 某集团 / 某公司 |
| **业务应用** | `Application` · `app_id` | **完全独立的业务单元**。拥有独立的 `appId`/`appSecret`、独立的渠道配置、**独立的账号空间** | `App1`（电商业务）、`App2`（社区业务） |
| **承载形态** | `Client` | 同一业务应用下，用户实际使用的**客户端类型**。属于同一个业务应用的不同呈现形式 | `App1` 的 iOS App、Android App、小程序、公众号内 H5、PC Web |
| **三方平台** | `Platform` | 对外提供三方登录能力的平台 | 微信、支付宝、Apple |
| **接入场景** | `Scene` | **某三方平台为某类承载形态提供的具体接入形态**，是适配器与配置的最小粒度 | 微信的：小程序登录 / 移动应用登录 / 公众号网页授权 / PC 扫码 |
| **渠道** | `Channel` = Platform + Scene | 路由键的组成单位 | `wechat:mini_program` |

> **命名约定（修正 A10）**：`platform` 与 `provider` 在本文档中**指同一个概念**——三方平台。为避免混淆，采用如下约定：
> - **概念层统一用「平台 / Platform」**，数据库字段、路由键、配置项一律写作 `platform`
> - **`Provider` 仅作为"渠道适配器"的接口名保留**（即 `Provider` interface = 一个 `platform:scene` 的实现），不再用于指代平台本身
> - 历史遗留的 `provider_app_id` 字段名保留（语义是"平台侧的应用标识"），但新增字段一律用 `platform` 前缀

### 权威枚举表：Platform 与 Scene（修正 A11）

以下表格是全文**唯一权威**的枚举定义，其余章节引用此表，不再各自罗列。

**Platform**

| `platform` | 说明 |
| --- | --- |
| `wechat` | 微信 |
| `alipay` | 支付宝 |
| `apple` | Apple |
| `generic_oauth2` | 通用 OAuth2（配置驱动的标准协议） |
| 自定义 | 新增平台时在适配器中注册，并在本表补充 |

**Scene**（按平台分组；`scene` 的取值只需在**所属平台内**唯一）

| `platform` | `scene` | 中文名 | 典型承载形态 | 用户标识 |
| --- | --- | --- | --- | --- |
| `wechat` | `app` | 移动应用登录 | iOS App、Android App **共用** | openid |
| `wechat` | `mini_program` | 小程序登录 | 小程序 | openid |
| `wechat` | `official_account` | 公众号网页授权 | 公众号内 H5 | openid |
| `wechat` | `pc_qr` | PC 扫码登录 | PC Web | openid |
| `alipay` | `app` | App 登录 | iOS App、Android App **共用** | user_id |
| `alipay` | `mini_program` | 小程序登录 | 支付宝小程序 | user_id |
| `alipay` | `web` | 网页登录 | Web / 公众号内 H5 | user_id |
| `apple` | `app` | iOS 原生登录 | iOS App | sub |
| `apple` | `web` | Web 登录 | Web | sub |
| `apple` | `notify` | 服务端通知端点（非登录） | — | — |

**治理要求（对应扩展性 E4）**：`scene` 必须在代码中以常量集中定义，Admin 配置写入时做白名单校验，防止拼写错误流入数据库；新增场景时同步更新本表。

### 三条必须记住的规则

概念层级总览：

```
组织
 ├── 业务应用 App1        ← 独立 appId / 独立 appSecret / 独立账号空间（C1 的隔离边界）
 │    ├── 承载形态： iOS App │ Android App │ 小程序 │ 公众号内 H5 │ PC Web │ 管理后台
 │    └── 渠道配置（= 平台 × 接入场景，唯一键 (app_id, platform, scene)）
 │         ├── wechat:app               ← 同时服务 iOS 与 Android 两个承载形态
 │         ├── wechat:mini_program
 │         ├── wechat:official_account
 │         ├── wechat:pc_qr
 │         ├── alipay:mini_program │ alipay:app │ alipay:web
 │         └── apple:app │ apple:web
 ├── 业务应用 App2        ← 结构相同，与 App1 完全隔离
 └── 业务应用 App3        ← 结构相同
```

**规则 1 · 业务应用 ≠ 承载形态**

```
✅ 正确理解：
   App1 是一个业务应用
   App1 的 iOS / Android / 小程序 是这一个业务应用下的不同承载形态

❌ 错误理解（本文档早期版本的表述）：
   "一个组织有 App、小程序、Web 站多个应用"
   —— 这会把同一业务的不同端误判为不同业务
```

**规则 2 · 承载形态不参与路由**

路由键只有三元组 `(app_id, platform, scene)`。**iOS 与 Android 是同一个渠道 `wechat:app`**，不会因为客户端不同就拆成两份配置。

承载形态只作为**遥测与风控维度**记录（写入 `auth_audit_logs.client`、令牌的 `amr` 或 `device_id`），不进入配置查找与适配器选择。这样新增一个客户端类型（如鸿蒙版）无需在服务端加任何配置。

**规则 3 · 承载形态与接入场景是多对多**

| 承载形态 | 对应接入场景 | 说明 |
| --- | --- | --- |
| iOS App | `wechat:app` | iOS 与 Android 共用开放平台「移动应用」的一个 appid |
| Android App | `wechat:app` | 同上 —— **两个承载形态，一个场景** |
| 小程序 | `wechat:mini_program` | 小程序有独立的 appid |
| 公众号内 H5 | `wechat:official_account` | 公众号网页授权 |
| PC Web | `wechat:pc_qr` | 扫码登录 |

反过来，**同一个承载形态也可能对应多个场景**：`App1` 的 Web 站在微信内打开时走 `official_account`，在 PC 浏览器打开时走 `pc_qr`。这也是为什么承载形态不能直接当作路由键。

### 账号空间的边界

**账号空间边界 = 业务应用**（约束 C1）。`App1` 与 `App2` 是完全独立的业务，同一个自然人在两者中是**两个互不相干的账号**，不做跨应用归并（约束 C1）；C3 进一步使得**同一业务应用内跨接入场景之间**也无法自动归并。

---

## 1. 目标与范围

### 1.1 要解决的问题

一个组织内往往有多个**完全独立的业务应用**（例如电商 App1、社区 App2、金融 App3），每个业务应用通常还要覆盖多种**承载形态**（iOS App、Android App、小程序、公众号内 H5、PC Web、管理后台），每种承载形态又可能需要接入多种三方登录方式。

如果每个业务应用各自对接，会导致：

- 微信 / 支付宝 / Apple 的对接逻辑重复实现 N 遍，每家踩一遍同样的坑
- 密钥散落在各业务系统中，轮换和审计困难
- 三方平台接口变更（如 Apple 停用密码授权、微信 unionid 规则调整）需要 N 处修改
- 同一业务应用内，用户在不同**接入场景**上的三方身份可能被识别成多个人（例如小程序与 App 各建一个账号，后续需要合并）

**本服务的定位：把"三方认证"这件事从上到下收敛成一个独立服务。**

### 1.2 核心能力清单

| 能力 | 说明 |
| --- | --- |
| 多**业务应用**接入 | 每个独立业务（App1、App2…）一组 `appId`/`appSecret`，配置隔离、数据隔离，**账号空间也按业务应用隔离**（约束 C1） |
| 多**承载形态**接入 | 同一业务应用下的 iOS / Android / 小程序 / 公众号 H5 / PC Web 均可接入，且**新增承载形态不需要改服务端配置**（规则 2：承载形态不进路由键） |
| 多**平台**接入 | 微信、支付宝、Apple、通用 OAuth2、自定义 |
| 多**接入场景** | 如微信的小程序登录 / 移动应用登录 / 公众号网页授权 / PC 扫码，可任意组合启用 |
| 统一授权入口 | 对外只有一个 `/authorize` 和一个 `/callback`，不随平台与场景数量增长 |
| 身份归一化 | 各平台原始用户信息 → 统一 Identity 模型，屏蔽字段差异 |
| 账号绑定与合并 | 三方身份 ↔ 业务账号的绑定、解绑、查询；**同一业务应用内跨接入场景的同一用户支持合并，且合并模式（自动 / 用户确认 / 仅提示）可按应用配置**（需求 R1/R2，约束 C4/C5） |
| 令牌体系 | 本地 access_token / refresh_token 签发与校验，可轮转 |
| 配置管理 | 渠道凭据加密存储、热更新、版本化 |
| 事件通知 | 登录成功、绑定变更、账号合并等事件通过 Webhook 外发 |
| 审计合规 | 全链路审计日志，支持账号注销与数据删除 |
| **管理端运维能力** | 应用与渠道配置、凭据轮换与连通性校验、身份与绑定查询、合并运维、强制下线、签名密钥轮换、死信重投、审计查询。**与业务端接口严格分离**，详见 **§15** |

> 上表中「业务应用 / 承载形态 / 平台 / 接入场景」的严格定义见文首**术语定义**章节，两者不要混用。
> **能力边界说明**：§1.2 其余各行描述的是**面向接入方（业务系统）**的能力；管理端另有一套独立接口体系，见 §15。

### 1.3 明确不做的事（边界）

- 不做具体的业务鉴权（用户能访问哪些接口），只负责"证明这个人是谁"
- 不做用户资料的主数据（Profile 归业务方），本服务只缓存三方原始资料快照
- 不替代企业的 IAM / SSO（SAML、OIDC IdP）——但架构上预留扩展位

### 1.4 已确认的约束（Constraints）

以下约束已明确，后续设计以其为准：

| 编号 | 约束 | 影响 |
| --- | --- | --- |
| **C1** | 账号空间**按业务应用隔离**，不做跨业务应用 SSO | `oauth_identities` / `oauth_bindings` 必须带 `app_id`；同一个微信用户在 App1 和 App2 中是两套身份、两个账号 |
| **C2** | **必须支持 Apple 登录**（有 iOS 应用） | Apple 适配器列入第二期必做项，需处理 client_secret JWT 签发、JWKS 验签、授权撤销回调（详见 §4.4） |
| **C3** | **不支持跨接入场景归并用户信息**（微信 unionid 不可用） | 归并键退化为 `open_id`，`union_id` 保留但不写入；**引入多源归并依据与验证手段**（手机号 / 邮箱等），是否用于自动归并由 `policy.merge.on_login` 决定（详见 D2 与 §7.4） |
| **C4** | 账号主体采用 **`remote` 模式**，复用现有用户中心；若当前不存在，则后续单独构建一个用户中心服务 | **本服务不再维护 `accounts` 表**；`oauth_bindings` 改为持有外部账号引用；首次三方登录无法独立完成，需业务方配合 |
| **C5** | 归并策略采用 **独立账号 + 引导绑定**（即 §7.4 的 S1） | 登录阶段不做隐式归并；同一业务应用内，**每个接入场景各自映射独立账号**。**同一应用内跨接入场景的同一用户支持合并，且合并模式（`auto` / `confirm` / `manual`）可按应用配置**（需求 R1/R2，见 §7.5），故合并能力不可省略 |
| **C6** | **调用外部渠道不做网络重试，重试责任归接入方** | 本服务对三方平台（微信 / 支付宝 / Apple）的调用**一律不自动重试**；失败即快速返回并标注是否可重试。接入方的重试单位是**重新发起一次授权流程**，不是重放回调。详见 §5.5 |

**C6 的边界（必须说清，否则会被误执行）**

C6 约束的是**对三方渠道的同步调用**。以下三类**不属于** C6 的约束范围，仍然必须重试：

| 机制 | 是否受 C6 约束 | 说明 |
| --- | --- | --- |
| 三方渠道同步调用（`Exchange` / `UserInfo` / `Refresh` / `Unbind`） | ✅ 受约束，**不重试** | 一次性凭证，重放语义不成立 |
| **后台补偿任务**（`merge_operations` 重试，§7.3） | ❌ **不受约束，必须重试** | 这是跨服务最终一致性的唯一保障。**若按 C6 误删补偿重试，会造成 P0-3 的孤儿不可恢复** |
| **Outbox 事件投递**（§5.4） | ❌ **不受约束，必须重试** | 事件投递失败需要指数退避重试与死信 |
| **协议层重取**（Apple JWKS `kid` 未命中时刷新一次，§4.4 ②） | ❌ 不受约束 | 这是**协议语义要求**，不是重试策略——密钥轮换后必须重新拉取才能验签 |
| 用户中心调用（`AccountProvider`，§D3） | ❌ 不受约束 | 属于**内部服务**依赖，非"外部渠道"。`Merge` 的幂等重试是 P0-4 的前提 |

> **一句话区分**：C6 管的是「对**外部平台**的**同步业务调用**」；后台任务、内部服务、协议层语义都不在其列。

**C3 的完整影响链（这是本版本最需要关注的变化）**

约束 C3 不是"少了一个可选能力"，而是**抽掉了唯一的自动归并依据**。具体后果：

以**同一个业务应用 App1** 为例，假设它同时有 iOS/Android App、小程序、公众号内 H5 三种承载形态：

| 承载形态 → 接入场景 | 有 unionid（原设计） | C3 下（现状） |
| --- | --- | --- |
| iOS / Android App → `wechat:app` | 账号 A | 账号 A |
| 小程序 → `wechat:mini_program` | 账号 A（unionid 相同） | **账号 B**（openid 不同） |
| 公众号内 H5 → `wechat:official_account` | 账号 A（unionid 相同） | **账号 C**（openid 不同） |
| 换个业务应用：App2 的微信登录 | 各自账号（C1 隔离） | 各自账号（C1 隔离） |

也就是说，**在按 open_id 各自建号的默认策略下，同一个人在同一个业务应用里会因为接入场景不同而产生多个账号**。这是必须由产品策略解决的核心问题，见 §7.4 的三套方案。

注意第一行：iOS 与 Android 属于**同一个接入场景** `wechat:app`，所以它们天然共享同一个 openid、不会分裂成两个账号。**产生账号分裂的是接入场景的差异，不是承载形态的差异。**

**C3 的补偿性设计**：把归并能力从"依赖平台字段"改为"依赖服务自有的可信凭证"。手机号是其中最可行的替代物——它天然一人一号，且微信小程序、支付宝都提供了获取已验证手机号的授权接口。

**C4 + C5 的组合结论：同一业务应用内，跨接入场景的同一用户 —— 支持合并**

这是本服务的一条正式产品需求，直接记入需求清单：

| 编号 | 需求 | 说明 |
| --- | --- | --- |
| **R1** | 同一**业务应用**内，同一用户通过不同**接入场景**（`wechat:app` / `wechat:mini_program` / `wechat:official_account` / `wechat:pc_qr` 等）登录而产生的多个账号，**必须支持合并** | 这是 C5 能落地的前提，不是可选项 |
| **R2** | 合并的**触发方式由应用配置决定**（应用接入时选择）：`auto` 自动合并 / `confirm` 用户确认后合并 / `manual` 仅提示不合并 | 由 `applications.policy.merge.mode` 控制，完整配置见 **§7.5** |
| **R3** | 合并**不跨业务应用**（受 C1 约束） | App1 与 App2 的账号永不合并，只可能通过 `account_links` 做"认亲" |
| **R4** | `auto` 模式的**安全红线**：归并依据必须是**平台侧已验证的凭证**，且被合并账号必须收到通知 | 这两项**不可通过配置关闭**，详见 §7.5.3 |

**为什么 R1 是必需的**（而不是"可选增强"）：

```
用户在小程序登录  → 账号 B，小程序 openid 绑到 B
用户后来在 App 登录 → 账号 C，App openid 绑到 C
用户在账号 C 的"账号设置"里点击"绑定微信小程序"
  ↓
小程序的 openid 已经被账号 B 占用 → 冲突
  ↓
若不支持合并，这个渠道将永远无法绑定 → 「引导绑定」功能直接失效
```

所以 **C5 省掉的只是"登录时自动归并"这一步，合并能力仍然必需且不可省略。**

**R2 的含义（可配置化）**：合并的**目标状态不变**（同一用户在同一业务应用内最终只有一个账号），但**达成路径由应用自行选择**：

| 模式 | 决策主体 | 用户感知 | 适用 |
| --- | --- | --- | --- |
| `auto` | 系统自动执行 | 事后通知 | 内部系统、企业应用、强实名场景 |
| `confirm`（默认） | 用户确认 + 验证后执行 | 明确感知"我在合并两个账号" | 面向 C 端的产品 |
| `manual` | 不合并，仅提示冲突 | 感知"该渠道已被占用" | 高风险业务、合规要求严格的场景 |

注意这与原设计中的"自动归并"**不是一回事**：原设计是登录时无差别静默归并（已被 C3 否掉，因为没有 unionid 这个可信归并键）；而现在 `auto` 模式**只在存在平台侧已验证凭证时才触发**，见 §7.5.3 的安全红线。

完整配置模型见 **§7.5**。这也是为什么 §7.2 的四种冲突策略与 §7.3 的合并实现必须**全部交付**——它们分别对应 `merge.mode` 的不同取值。

**`confirm` 模式下的验证手段**：合并前必须证明用户对**双方账号**都有控制权。可用手段按强度排序：

1. 对端账号已有的另一条绑定渠道（如已在账号 C 绑定手机号 + 登录密码）
2. 待合并账号绑定的手机号/邮箱 —— 发送验证码验证
3. 短信验证码（C3 下最通用，因为 unionid 不可用）

验证通过后写入 `identity_claims`（`verified=true`），再执行 §7.3 的合并流程。

**C4 的连锁效应**

`remote` 模式意味着本服务在"三方登录成功但没有绑定"时**无法自己产出账号**，必须回调业务方。这带来两个必须提前约定的接口：

1. **首次三方登录的处置方式**（三选一，见 D3）
2. **业务方账号的对外标识**：`sub` 直接用业务方 userId，还是本服务生成映射别名？本版本建议前者（详见 §8.1）

**C1 为什么会反过来改变 Identity 表结构**

如果 `oauth_identities` 不带 `app_id`，当两个**业务应用**共用同一个微信 appid 时（很常见，例如 App1 与 App2 都接入了同一个公众号），它们的 identity 行会**共享同一条记录**：`profile_snapshot`、`last_login_at` 互相污染；更严重的是 Binding 上的部分唯一索引会阻止同一个 identity 被两个业务应用的账号分别绑定，直接破坏隔离。因此 `app_id` 必须作为 Identity 的一等字段，唯一索引也要相应扩展为 `(app_id, platform, provider_app_id, open_id)`。

**C1 的演进留口**

若未来需要跨应用 SSO，不需要改动 `oauth_bindings` / `oauth_identities` 结构，只需新增一张关联表：

```sql
CREATE TABLE account_links (
    id                  BIGSERIAL PRIMARY KEY,
    left_app_id         BIGINT       NOT NULL,
    left_user_id        VARCHAR(128) NOT NULL,
    right_app_id        BIGINT       NOT NULL,
    right_user_id       VARCHAR(128) NOT NULL,
    link_type           VARCHAR(32)  NOT NULL, -- same_person | merged | manual
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (left_app_id, left_user_id, right_app_id, right_user_id)
);
```

把不同应用的账号"认亲"即可（约束 C4 下引用的是 `external_user_id`，本服务仍不持有账号主数据）。这是纯增量演进，现在的隔离决策不会变成技术债。

---

## 2. 关键架构决策

这一节是全文最重要的部分。以下 8 个决策决定了后续的扩展成本和演进空间。

### D1 · 用「平台 × 接入场景」二维路由，而不是「一个平台一个适配器」

**先明确概念边界**（详见文首术语定义）：本节的「场景」指的是**三方平台侧的接入形态**，不是客户端类型。

- 一个**业务应用**（App1）下可以有多种**承载形态**（iOS / Android / 小程序 / 公众号 H5 / PC Web）
- 每种承载形态对应某个三方平台的某个**接入场景**
- **路由键 = `(app_id, platform, scene)`，其中不含承载形态**

**问题**：同一个微信平台有 4 种流程完全不同的接入方式：

| 接入场景（scene） | 通常对应的承载形态 | 流程 | 用户标识 |
| --- | --- | --- | --- |
| `official_account`（公众号网页授权） | 公众号内 H5 | 标准 OAuth2 授权码，`snsapi_userinfo` 需二次确认 | openid |
| `app`（开放平台移动应用登录） | **iOS App 与 Android App 共用** | 移动端 SDK 拉起，返回 code | openid |
| `mini_program`（小程序登录） | 小程序 | `code2session`，非标准 OAuth，无授权页 | openid |
| `pc_qr`（PC 扫码登录） | PC Web | 二维码 + 轮询，非标准 OAuth | openid |

如果按平台写一个适配器，`WeChatProvider` 内部会充斥 `switch scene` 分支，方法签名的参数含义在不同场景下不一致，最终不可维护。

**决策**：适配器注册键为 `platform + scene`，例如 `wechat:mini_program`、`wechat:official_account`。每个组合是一个独立的、自包含的实现。

**承载形态为什么不进路由键**（规则 2）：

```
✅ 正确：iOS 与 Android 都路由到 wechat:app，共用同一份 wx_appid 与配置
❌ 错误：wechat:ios_app / wechat:android_app 各配一份
        → 新增鸿蒙版就要加配置；改一次 appSecret 要改多份；两边容易不一致
```

承载形态只作为**遥测与风控维度**：写入 `auth_audit_logs.client`、`device_id`，以及令牌的 `amr` 字段。业务方若想按端做差异化（如"仅允许 iOS 登录"），那是业务层的策略，不是本服务的路由维度。

**收益**：新增平台 = 新增一个包；新增接入场景 = 新增一个文件；**新增承载形态 = 零服务端改动**。核心编排流程（授权 → 回调 → 归一化 → 绑定 → 签发）完全不知道 concrete provider 的存在。

### D2 · 统一身份模型 Identity + 多源归并键

**问题**：三方平台返回的用户标识语义各不相同。微信有 openid（应用内唯一）和 unionid（开放平台账号内唯一）；支付宝有 user_id 和 open_id；Apple 只有 sub，且**同一个 Apple ID 在不同 App 上 sub 不同**。

**已确认约束 C3**：**不支持跨接入场景归并用户信息**（微信 unionid 不可用 / 不启用开放平台账号绑定）。

这条约束的影响范围必须说清楚：它**不只是"跨业务应用不归并"，而是 unionid 这条归并路径整体失效**。后果是同一个自然人在同一个业务应用内，通过 `wechat:app`、`wechat:mini_program`、`wechat:official_account` 三个不同接入场景登录，拿到的 openid 各不相同，**会被识别为三个独立的人**。

**决策一：Identity 模型保留归并字段，但归并来源从"单源"升级为"多源"**

```
Identity {
  app_id            // 接入方应用 ID（约束 C1：身份按应用隔离）
  provider          // 平台: wechat / alipay / apple
  provider_app_id   // 平台侧的应用标识: wx_appid / alipay_app_id / apple_client_id
  open_id           // 平台内的用户标识（应用 + 端唯一）
  union_id          // 保留字段，约束 C3 下恒为空
  identity_key      // 归并键 = open_id（C3 下的退化结果）
}
```

**决策二：把归并能力抽象成多源 `MergeKey`，按可信度排序**

由于 unionid 不可用，归并不能依赖任何单一平台字段，必须由 `MergeKeyResolver` 从多个来源合成：

| 优先级 | 来源 | 作用范围 | 说明 |
| --- | --- | --- | --- |
| 1 | 显式绑定 | 应用内跨渠道 | 用户主动操作，意图最明确，最可靠 |
| 2 | **已验证手机号** | 应用内跨渠道 | **C3 下的主力替代方案**。微信小程序 `getPhoneNumber`、支付宝手机号授权、短信验证码均可提供 |
| 3 | 已验证邮箱 | 应用内跨渠道 | 次选，覆盖率和可信度都低于手机号 |
| 4 | `union_id` | 应用内跨端 | C3 下不可用，保留接口位以便未来开通 |
| 5 | `open_id` | **无归并能力** | 仅单渠道单端唯一，不能作为归并依据 |

实现上，`MergeKeyResolver` 返回一组 `MergeKey{Type, Value, Verified}`。**但匹配行为由 `applications.policy.merge.on_login` 控制，不是无条件自上而下归并**（修正 A4：此前本节前后表述矛盾）：

| `merge.on_login` | 行为 |
| --- | --- |
| `off`（默认） | **不做多源归并**。只按 `open_id` 精确匹配已有绑定；未命中即走"无绑定"分支（`on_unbound_login`） |
| `claim_verified` | 按上表优先级自上而下匹配，命中则归并到该账号；全部未命中才创建新账号（即 S2 行为） |

即**上表描述的是能力集合，不代表默认行为**。默认是"只匹配不归并"，`claim_verified` 需应用显式配置且受 §7.5.3 安全红线约束。

**决策三：归并结果落到 `identity_claims` 表，而不是 Identity 上的固定列**

手机号这类归并依据可能一个身份有多个（改绑手机号），且必须区分"已验证"与"未验证"，因此独立成表（DDL 见 §6.2）。

**注意**：`union_id` 字段保留但 C3 下不写入。若未来开通了开放平台账号绑定，无需改表结构，只需在 `MergeKeyResolver` 里启用第 4 级来源。

**C5 下第 2 级（已验证手机号）的角色**：在默认 `on_login = off` 时，手机号**不作为自动归并依据**，而是降级为：

- **绑定/合并时的身份验证手段**（证明"我确实是这两个账号的主人"）
- **可选的辅助归并依据**（应用显式配置 `on_login = claim_verified` 后启用）

**D2 的两条强制约束**：

- **所有 identity 查询必须携带 `app_id` 条件**（约束 C1），Repository 层强制注入，避免跨接入场景串号
- **归并判定使用的 claim 必须满足 `verified = true`**，且仅在 `on_login = claim_verified` 时才参与自动归并

### D3 · 账号主体走 `remote` 模式（约束 C4，已确认）

**决策**：本服务**不维护 `accounts` 表**，账号主数据归属于独立的用户中心服务。本服务只负责 identity（三方身份）与 binding（绑定关系）。

由于用户中心当前可能还不存在，**接口必须抽象，实现可以晚到**：

```go
package account

// AccountProvider 是账号体系的端口（port）。
// 生产环境实现为 HTTPAccountProvider（调用用户中心 API）；
// 早期可用 StubAccountProvider 做联调（见 §13 第一期）。
type AccountProvider interface {
    // Get 按 user_id 查询账号，不存在返回 ErrAccountNotFound
    Get(ctx context.Context, userID string) (*Account, error)

    // GetByClaim 按可信凭证反查账号，用于绑定冲突排查。
    // 返回 ErrMultipleAccounts 表示命中多个账号——此时必须报错而非择一（见 §7.4 通用护栏）。
    // 职责边界：本方法用于【跨到用户中心核对账号真实性】；
    //           本服务内部的归并判定只用 identity_claims 表，不走本方法（修正 P1-1）。
    GetByClaim(ctx context.Context, claim Claim) (*Account, error)

    // Create 创建账号。业务方未提供该能力时返回 ErrNotSupported，
    // 此时首次三方登录必须走「引导注册」流程。
    Create(ctx context.Context, req CreateAccountRequest) (*Account, error)

    // Merge 把 source 账号合并进 target。
    // 由业务方决定其内部数据（订单、资料、外键）如何迁移。
    // 必须幂等：相同 IdempotencyKey 重复调用须返回同一结果，不得重复执行（修正 P0-4）。
    Merge(ctx context.Context, req MergeRequest) (*MergeResult, error)

    // UnbindAll 账号注销时调用，由用户中心清理自身数据。
    // 本服务的 identity/binding 清理由本服务自行完成（见 §10.2）。
    UnbindAll(ctx context.Context, userID string) error
}

// MergeRequest 携带幂等键——这是补偿任务能安全重试的前提。
type MergeRequest struct {
    IdempotencyKey string // 由本服务生成，全局唯一（= merge_operations.id），跨服务传递
    TargetUserID   string
    SourceUserID   string
    Reason         string // 触发来源：bind_conflict_auto | bind_conflict_confirmed | admin
    Operator       string // 用户 ID 或管理员 ID，便于用户中心审计
}

type MergeResult struct {
    Merged         bool   // 是否本次实际执行了合并（幂等重试时为 false）
    EffectiveAt    string // 生效时间
    Detail         map[string]any
}

type Account struct {
    UserID    string            // 业务方账号的唯一标识
    Status    AccountStatus     // active / frozen / closed
    Claims    []Claim           // 已验证的手机号 / 邮箱，用于校验
    Extra     map[string]any    // 透传字段
}
```

**接口设计的两条约定**：

1. **`Merge` 必须带幂等键**。本服务在补偿任务中会重试该调用，用户中心必须能识别"这是重试"并返回首次结果。若用户中心无法实现幂等，补偿策略需降级为"仅告警、不自动重试"（见 §7.3）。
2. **`GetByClaim` 与 `identity_claims` 职责分离**（修正 P1-1）：
   - `identity_claims`（本服务的表）→ **只用于本服务内部的归并判定与凭证记录**
   - `GetByClaim`（跨服务调用）→ 用于**归并前回源核对**账号真实性与手机号的有效性（见 P0-6）

**三种首次登录处置方式**（通过 `applications.policy.on_unbound_login` 配置）：

| 取值 | 行为 | 前置条件 |
| --- | --- | --- |
| `need_register`（默认，最稳） | 返回 `AUTH.NEED_REGISTER`，业务方引导用户注册/登录后再调 `/v1/bind` | 无 |
| `auto_create` | 本服务调用 `AccountProvider.Create` 自动建号并绑定，直接签发令牌 | 用户中心提供创建接口 |
| `session_only` | 签发一个仅有 `scope=identity_only` 的受限令牌，业务方自行决定后续 | 无 |

**关键点：无论用户中心何时就位，本服务对外暴露的 `sub` 语义都保持一致**（见 §8.1），业务方在用户中心上线前后无需改动调用方。

**第一期落地方式**：先实现 `StubAccountProvider`（内存版或直接返回 `need_register`），把授权主链路跑通；用户中心就位后替换为 `HTTPAccountProvider` 即可，不改动任何业务逻辑。

### D4 · 绑定关系独立成聚合，冲突策略显式化

**问题**："这个微信已经绑了另一个账号"是这类服务最高频的线上问题。如果处理逻辑散落在各渠道代码里，就会出现微信的冲突处理和 Apple 的不一致。

**决策**：

- `Binding` 作为独立领域对象，而非 Identity 上的一个 `user_id` 字段
- Identity 表唯一索引 **`(app_id, platform, provider_app_id, open_id)`** —— 必须含 `app_id`，否则两个业务应用共用同一 `provider_app_id` 时会共享 identity 行，直接破坏 §1.4 的 C1 隔离（修正 A2：此前此处遗漏了 `app_id`、且误写为 `provider`）
- Binding 表对 `identity_id` 建**部分唯一索引**（`WHERE status = 'active'`）——保证一个三方身份同期只能绑一个账号，同时保留解绑历史用于审计
- **冲突策略不由策略清单直接配置，而是由 `applications.policy.merge.mode` 驱动**（修正 A3：此前此处列出的四策略清单已过时）。映射关系见 §7.2：

  | `merge.mode` | 底层策略 |
  | --- | --- |
  | `confirm`（默认） | `verify_then_merge` |
  | `auto` | `auto_merge` |
  | `manual` | `reject` |

  另有 `transfer` 作为**不开放配置的旁路**，仅通过管理台手工触发，实现在 `BindingConflictPolicy` 里，与渠道无关。

### D5 · 一次性票据贯穿全流程

三个环节全部使用一次性、短时效、服务端存储的凭据，杜绝重放和令牌泄漏：

| 凭据 | 生成方 | 生命周期 | 存储 |
| --- | --- | --- | --- |
| `state` / ticket | 授权开始时 | 5 分钟，一次性消费 | Redis |
| 业务方授权码 `auth_code` | 回调成功后 | 60 秒，一次性消费 | Redis |
| `refresh_token` | 换取令牌时 | 30 天，轮转 + 重放检测 | DB（存哈希） |

`state` 不只在客户端往返，而是**服务端的票据**：内部持有 appId、provider、scene、redirectUri、mode、codeChallenge、目标账号（bind 模式），回调时凭 state 反查全部上下文。这样回调 URL 只需一个，且前端无法篡改流程参数。

### D6 · 渠道凭据信封加密 + 配置热更新

- 凭据（appSecret、Apple 的 .p8 私钥）以**密文**入库，采用信封加密：KMS/主密钥加密 DEK，DEK 加密凭据
- 运行时解密后缓存在进程内，带 TTL
- 配置带 `version`，变更后通过 Redis Pub/Sub 广播失效通知，各实例惰性重载，无需重启

### D7 · 编译期注册，运行期查找

Go 的 `plugin` 包在跨平台和版本兼容上问题很多，不采用动态加载。

**决策**：每个适配器在 `init()` 中向全局 Registry 注册自己，主程序通过 blank import 引入 `adapters` 聚合包。

```go
// internal/provider/adapters/adapters.go
import (
    _ "github.com/xxx/social-login/internal/provider/adapters/wechat"
    _ "github.com/xxx/social-login/internal/provider/adapters/alipay"
    _ "github.com/xxx/social-login/internal/provider/adapters/apple"
    _ "github.com/xxx/social-login/internal/provider/adapters/generic_oauth2"
)
```

对使用方而言效果等同于插件：**新增渠道不触碰任何既有文件**（除了这行 blank import）。

### D8 · 把 `Provider` 上提一层为 `IdentitySource`（架构留口）

**动机**：§1.3 承诺"不替代企业 IAM / SSO，但架构上预留扩展位"——但 v0.7 之前全文**没有任何落地设计，是个空承诺**（审查发现 E3）。若未来要接入企业 SSO（OIDC / SAML）、或让本服务作为 IdP 被其他系统联邦，届时再抽象需要动核心编排。

**决策**：现在就把抽象上提一层，成本几乎为零；但**不实现**上游 IdP 适配器，只留出位置。

```
IdentitySource（身份来源，领域层定义的端口）
  ├── Provider          ← 三方渠道：wechat / alipay / apple / generic_oauth2（本服务当前实现）
  ├── UpstreamIdP       ← 上游身份提供方：OIDC / SAML / 企业 SSO（预留，暂不实现）
  └── LocalCredential   ← 本地凭证：密码 / 短信验证码（预留，暂不实现）
```

`IdentitySource` 只规定"如何获得一个已归一化的外部身份"，核心编排流程（授权 → 回调 → 归一化 → 绑定 → 签发）依赖这一层，而**不依赖 `Provider`**。当前的 `Provider` 接口（§4.1）不删不改，只是让它在概念上成为 `IdentitySource` 的一个实现族。

**改动成本对比**：

| 时机 | 成本 |
| --- | --- |
| 现在做 | 目录结构上多一层 `internal/domain/identitysource/`，接口定义多一个文件；编排层引用 `IdentitySource` 而非 `Provider`。**约 1 小时** |
| 接入企业 SSO 时再改 | 需要抽取接口 + 改造编排层 + 回归全部既有渠道。**数天，且有回归风险** |

**同时预留的两个小扩展位**：

- **E1 · `app_provider_configs` 预留 `config_key`**：唯一键从 `(app_id, platform, scene)` 扩为 `(app_id, platform, scene, config_key)`，`config_key` 默认 `default`。这样将来一个业务应用要接**两个小程序**或同平台多套开放平台账号时，是纯增量变更而非破坏性变更（见 §6.2）
- **E10 · `Provider.Metadata` 增加 `APIVersion`**：用于适配器内部处理三方平台 API 版本升级与灰度，无需改动核心

---

## 3. 分层架构

```
┌─────────────────────────────────────────────────────────┐
│ 接入层  业务端 /v1/* ‖ 管理端 /admin/* ‖ Webhook ‖ SDK  │
├─────────────────────────────────────────────────────────┤
│ 应用服务层  授权编排 / 绑定与合并 / 令牌签发 / 租户配置 │
├─────────────────────────────────────────────────────────┤
│ 领域层  IdentitySource / Identity / Binding / Ticket    │
├─────────────────────────────────────────────────────────┤
│ 渠道适配层  微信 / 支付宝 / Apple / 通用 OAuth2 / 自定义│
├─────────────────────────────────────────────────────────┤
│ 基础设施层  MySQL·PG / Redis / KMS / MQ / Tracing       │
└─────────────────────────────────────────────────────────┘
```

**依赖方向**：接入层 → 应用层 → 领域层。渠道适配层实现领域层定义的 `Provider` 接口（依赖倒置）。基础设施层被领域层通过 port 接口引用，不反向依赖。

### 3.1 Go 工程结构

```
social-login/
├── cmd/
│   └── server/main.go                 # 装配与启动
├── internal/
│   ├── bootstrap/                     # 依赖注入、配置加载、优雅退出
│   ├── interfaces/
│   │   └── http/
│   │       ├── handler/               # 业务端 /v1/*：oauth / token / binding / userinfo
│   │       │   └── admin/             # 管理端 /admin/v1/*：§15 的 A~K 共 11 组接口
│   │       ├── middleware/            # 业务端：app 鉴权、限流、trace、恢复
│   │       │   └── adminmw/           # 管理端：管理员鉴权 + RBAC、IP 白名单、高危操作审计
│   │       └── dto/                   # 请求响应结构 + 校验（业务端与管理端分开定义）
│   ├── application/                   # 用例编排（事务边界在这一层）
│   │   ├── authflow/                  # 授权主流程
│   │   ├── binding/                   # 绑定、解绑、合并
│   │   ├── token/                     # 令牌签发与校验
│   │   ├── tenantconfig/              # 租户与渠道配置
│   │   └── adminops/                  # 管理端用例：只做权限校验与编排，
│   │                                  #   内部调用上述用例，不重复实现业务逻辑（§15.2）
│   ├── domain/
│   │   ├── account/                   # AccountProvider port（本服务不持有账号，仅定义端口）
│   │   ├── identitysource/            # IdentitySource 端口（D8 留口，编排层依赖此层而非 Provider）
│   │   ├── identity/                  # Identity 聚合 + MergeKeyResolver
│   │   ├── binding/                   # Binding 聚合 + 冲突策略
│   │   ├── ticket/                    # Ticket 模型 + Repository port
│   │   └── provider/                  # Provider SPI 定义 + Registry（IdentitySource 的一种实现族）
│   ├── infrastructure/
│   │   ├── provider/adapters/         # 各渠道实现
│   │   │   ├── wechat/                # official / app / mini_program / qr
│   │   │   ├── alipay/
│   │   │   ├── apple/                 # JWKS 验签 + client_secret JWT 签发
│   │   │   └── generic_oauth2/        # 配置驱动的标准 OAuth2
│   │   ├── persistence/               # mysql / postgres 实现
│   │   ├── cache/                     # redis 实现
│   │   ├── crypto/                    # 信封加密、KMS 客户端
│   │   └── mq/                        # 事件外发
│   └── pkg/                           # 内部工具：错误码、日志、JWT
├── api/openapi.yaml
├── configs/config.yaml
└── migrations/
```

---

## 4. 渠道抽象：Provider SPI

### 4.1 接口定义

```go
package provider

// Provider 是所有三方渠道必须实现的契约。
// 一个实现对应一个 (平台, 场景) 组合，例如 wechat:mini_program。
//
// 两条实现约定（约束 C6，详见 §5.5）：
//   1. 实现内部【不做网络重试】——一次失败即返回错误。重试责任在接入方。
//   2. Exchange / Refresh 这类"已发出即不可撤销"的调用，必须使用调用方传入的
//      ctx（由上层用 context.WithoutCancel 构造），不得自行取消或超时截断。
type Provider interface {
    // Metadata 返回渠道的静态描述，用于路由与能力查询。
    Metadata() Metadata

    // AuthURL 生成三方授权跳转地址。
    // 小程序等无授权页的场景返回空 URL，并标记 Immediate=true。
    AuthURL(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error)

    // Exchange 用授权凭证换取三方令牌。
    // 不同场景的入参语义由 params 承载，由实现自行解释。
    Exchange(ctx context.Context, req ExchangeRequest) (*TokenSet, error)

    // UserInfo 拉取三方用户信息并归一化。
    UserInfo(ctx context.Context, token *TokenSet) (*ExternalUser, error)

    // Refresh 刷新三方令牌。平台不支持时返回 ErrNotSupported。
    Refresh(ctx context.Context, token *TokenSet) (*TokenSet, error)

    // Unbind 在三方平台侧解除授权（如微信拉黑、Apple 撤销令牌）。可选实现。
    Unbind(ctx context.Context, req UnbindRequest) error
}

// CallbackVerifier 由需要回调验签的平台实现（Apple / 支付宝）。
type CallbackVerifier interface {
    VerifyCallback(ctx context.Context, raw *CallbackPayload) error
}

// HealthChecker 由需要平台健康探测的适配器实现（可选，见 §5.6.6）。
// 注意职责边界：HealthChecker 只用于【管理台展示与告警】，
// 【不参与熔断决策】——熔断完全基于真实业务调用的被动统计（§5.6）。
type HealthChecker interface {
    // Ping 探测三方平台可达性
    Ping(ctx context.Context) error
}

type Metadata struct {
    Platform     string          // wechat / alipay / apple / generic_oauth2（权威枚举见文首）
    Scene        string          // 权威枚举见文首「Platform 与 Scene」表
    DisplayName  string
    Capabilities CapabilitySet   // 声明支持哪些能力
    APIVersion   string          // 适配器所对接的三方 API 版本，用于灰度与兼容分支（E10）
}

type CapabilitySet struct {
    ServerSideFlow bool // 是否有服务端授权码流程
    RequiresPKCE   bool // 是否必须 PKCE
    // HasCrossSceneID：是否提供跨接入场景的归并标识（如微信 unionid）。
    // 注意与 C1/C3 的关系：C1 禁止跨业务应用归并，C3 下微信 unionid 实际不可用，
    // 因此本字段当前所有渠道均为 false，保留以备未来开通。
    HasCrossSceneID bool
    ProvidesEmail   bool
    ProvidesPhone   bool
    SupportsUnbind  bool
    Immediate       bool // 是否无授权页（小程序 code2session）
}

// TokenSet 是三方令牌集合。除标准 OAuth2 字段外，必须能承载平台私有会话态。
type TokenSet struct {
    AccessToken  string
    RefreshToken string
    IDToken      string
    ExpiresIn    int

    // SessionKey：微信小程序 code2session 返回的会话密钥，
    // 是解密 getPhoneNumber 手机号的前提（R4 红线 1 的关键路径，见 P1-2）。
    // 生命周期：由适配器按平台规则设置 ExpiresIn；存储于 Redis，TTL 与平台一致，
    //          解密手机号后立即丢弃，不落库、不进日志。
    SessionKey string

    Raw map[string]any // 平台原始响应，脱敏后入库供排障
}

// ExternalUser 是渠道返回的归一化结果，核心流程只认这个结构。
type ExternalUser struct {
    OpenID    string
    UnionID   string
    Nickname  string
    AvatarURL string
    Email     string
    Phone     string

    // 凭证来源标记：写入 identity_claims.source 时必须使用这里的取值，
    // 保证 R4 红线 1 的白名单校验可判定（修正 A6、见 §7.5.3）。
    PhoneVerifiedBy string // wechat_phone | alipay_phone | apple_email | ""（未提供或未验证）
    EmailVerifiedBy string // 同上，空表示未验证

    Raw map[string]any // 原始响应，入库快照供排障
}
```

### 4.2 注册表

```go
package provider

type Registry struct {
    mu        sync.RWMutex
    providers map[string]Provider // key: "platform:scene"
}

func Register(p Provider) {
    m := p.Metadata()
    key := m.Platform + ":" + m.Scene
    global.mu.Lock()
    defer global.mu.Unlock()
    if _, dup := global.providers[key]; dup {
        panic("duplicate provider registered: " + key)
    }
    global.providers[key] = p
}

func Lookup(platform, scene string) (Provider, error) {
    global.mu.RLock()
    defer global.mu.RUnlock()
    p, ok := global.providers[platform+":"+scene]
    if !ok {
        return nil, ErrProviderNotFound
    }
    return p, nil
}

// 各适配器在自己的包内 init 时注册
func init() { Register(&wechatMiniProgram{}) }
```

### 4.3 平台差异速查表

这是实现时最容易踩坑的部分，必须在适配器里逐条处理。

| 维度 | 微信 | 支付宝 | Apple |
| --- | --- | --- | --- |
| 授权模式 | OAuth2 授权码（小程序为非标准 `code2session`） | OAuth2 + RSA2 签名 | OAuth2 + JWT 形式的 client_secret |
| 用户标识 | `openid` / `unionid` | `user_id` / `open_id` | `sub` |
| 跨接入场景归并 | `unionid`（需绑定开放平台账号）—— **C3 下不可用** | 无原生能力 | 无（旧版有 `transfer_sub`） |
| 手机号获取 | 小程序 `getPhoneNumber`（需 `session_key` 解密）；公众号/App 需用户确认 | 手机号授权接口 | **不提供**，需引导补填 + 短信验证 |
| 用户信息 | 昵称头像需 `snsapi_userinfo` 且用户确认 | 字段很少，部分需签约 | **仅首次授权返回 name/email，之后永远为空** |
| 回调验签 | 无（code 一次性） | 需 RSA2 验签 + 时间戳校验 | 需要 JWKS 验 `id_token`（iss/aud/exp/nonce） |
| 令牌刷新 | 网页授权支持 refresh_token | 支持 | refresh_token 存在，但 client_secret 需自行签发 |
| 特殊坑 | 小程序 session_key 有时效；PC 扫码需轮询 | 表单与 JSON 混合，网关参数名不一致 | email 可能是 `@privaterelay.appleid.com` 中继地址 |

**Apple 的 client_secret 是这里最特殊的**：它不是静态字符串，而是用 `.p8` 私钥签发的 ES256 JWT，有效期最长 6 个月，必须实现自动签发与续期，且要处理时钟漂移。

### 4.4 Apple 登录专项说明（约束 C2，必做）

有 iOS 应用时，App Store 审核指南 4.8 强制要求：**只要 App 提供了其他三方登录方式，就必须同时提供 Sign in with Apple**。这不是可选项。

#### 需要准备的材料

| 材料 | 来源 | 用途 |
| --- | --- | --- |
| Team ID | Apple Developer 账号 | JWT 的 `iss` |
| Key ID + `.p8` 私钥 | 创建 "Sign in with Apple" Key | 签发 client_secret |
| Service ID | 创建 Service ID（Web 场景） | `client_id`（Web） |
| Bundle ID | App 的 Bundle Identifier | `client_id`（iOS 原生） |

#### 三个必须处理的机制

**① client_secret 不是静态字符串**

它是运行时签发的 ES256 JWT，最长有效期 6 个月：

```json
// header
{ "alg": "ES256", "kid": "<Key ID>" }
// payload
{
  "iss": "<Team ID>",
  "iat": 1760000000,
  "exp": 1760000000 + 15552000,
  "aud": "https://appleid.apple.com",
  "sub": "<Service ID 或 Bundle ID>"
}
```

实现要点：进程启动时签发一份并缓存，剩余有效期不足 7 天时自动续期；注入可替换的 clock 以便处理时钟漂移与单元测试。

**② 用 JWKS 验 `id_token`**

从 `https://appleid.apple.com/auth/keys` 拉取公钥，按 `kid` 匹配后验签，并校验：

- `iss == "https://appleid.apple.com"`
- `aud == 本次请求使用的 client_id`
- `exp` / `iat` 在有效窗口内（允许少量时钟偏移）
- `nonce` 与授权时下发的一致 —— **必须开启，这是防重放的关键**

**nonce 的生成与存储**（修正 P1-3）：`nonce` 在 `/authorize` 阶段生成随机值，写入授权票据 `oauth:ticket:{state}`（与 state 同一份上下文，不额外建 key）。回调时从 ticket 取出比对，**比对成功后随即随 ticket 一起销毁**，保证一次性。若比对失败 → 返回 `AUTH.INVALID_NONCE` 并记安全事件。

JWKS 需要缓存；当验签失败且原因是找不到 `kid` 时，强制刷新一次 JWKS 再重试（Apple 会轮换密钥）。JWKS 缓存放 Redis（`oauth:jwks:apple`，TTL 1 小时）以避免多实例重复拉取。

**③ 用户信息只在首次授权返回**

Apple 只在**用户首次授权**时通过 `user` 字段返回 `name` 与 `email`，此后所有登录都只有 `sub`。必须：

- 首次授权时立即把 name / email 落库到 `profile_snapshot`，错过就没有第二次机会
- 业务逻辑中绝不假设再次登录能拿到姓名
- email 可能是 `xxxxx@privaterelay.appleid.com` 中继地址，**不要当作可靠的真实邮箱**使用

#### 容易漏掉的第四个机制：Server-to-Server Notification

Apple 会推送授权状态变更事件，必须提供接收端点 `POST /v1/oauth/notify/{platform}`（Apple 为 `/v1/oauth/notify/apple`）并验签，处理：

| 事件 | 处理动作 |
| --- | --- |
| `consent-revoked` | 用户撤销授权 → 标记 identity 失效并解绑，撤销该账号全部令牌 |
| `account-delete` | 用户在 Apple 侧删除账号 → 同上，并触发业务方账号注销流程 |

漏掉这个端点的后果：用户在 Apple 系统设置里撤销了授权，你的系统里仍显示"已绑定 Apple"，属于明确的合规风险。

---

## 5. 统一授权流程

### 5.1 时序

```
客户端          统一授权服务         Redis·DB        渠道适配器       三方平台
  │                  │                 │               │              │
  ├─① GET /authorize→│                 │               │              │
  │                  ├─② 生成票据──────→│               │              │
  │←③ 302 授权页──────┤                 │               │              │
  │                  │                 │               │              │
  ├─④ 用户在三方完成授权──────────────────────────────────────────────→│
  │                  │                 │               │              │
  │                  │←⑤ 回调 code+state───────────────────────────────┤
  │                  ├─⑥ 消费票据（防重放）→│            │              │
  │                  ├─⑦ Exchange(code)─────────────────→│              │
  │                  │                 │               ├─⑧ 换 token───→│
  │                  │                 │               │← 用户信息 ────┤
  │                  │←⑨ 归一化身份──────────────────────┤              │
  │                  ├─⑩ 落库 identity ─→│              │              │
  │                  │                 │               │              │
  │        ┌─────────┴── ⑪ 是否已有活跃绑定？（修正 A5）│              │
  │        │  有 → 建/复用 binding，继续 ⑫                │              │
  │        │  无 → 按 §5.2 分叉：                          │              │
  │        │        默认返回 NEED_REGISTER + bind_ticket   │              │
  │        └──       （不建 binding，第 ⑬ 步换不到令牌）    │              │
  │                  │                 │               │              │
  │←⑫ 302 回业务方────┤                 │               │              │
  ├─⑬ POST /token───→│                 │               │              │
  │←── access/refresh token ───────────┤               │              │
```

> 图中 ⑪ 是约束 C4 引入的必经分支。**默认配置（`on_unbound_login = need_register`）下，⑩ 之后不建立 binding**，流程在 ⑫ 返回注册引导，⑬ 换令牌必须等业务方完成注册后带 `bind_ticket` 调 `/v1/bind` 才能成功。

### 5.2 关键设计点

**回调不直接返回令牌。** 回调落点先换取短时效的一次性 `auth_code`，再由前端用 `auth_code` 调 `/token` 换取正式令牌。原因：

- SPA / 小程序场景下，重定向 URL 会进入浏览器历史和 Referer，直接带令牌不安全
- 令牌交换需要 `client_id` 参与，天然校验调用方身份
- 一次性 code 被截获也无法复用

**state 是服务端票据。** 回调 URL 只需要 `/v1/oauth/callback/{platform}` 一个，全部上下文（`appId`、`platform`、`scene`、`redirectUri`、`mode`、绑定目标 `external_user_id`、Apple `nonce`）凭 state 从 Redis 反查。前端无法篡改 flow 参数，也无法伪造 redirectUri 做开放重定向。

**并发绑定安全。** 两个请求同时为同一个 identity 建绑定，靠数据库唯一索引兜底，捕获冲突后转为"已存在"语义返回，而不是加分布式锁（更轻、更可靠）。

**未绑定身份的分支（约束 C4 带来的新增路径）。** `remote` 模式下本服务无法自己产出账号，因此回调后若 identity 无活跃绑定，流程会分叉为：

```
查 binding → 无活跃绑定
   ↓
读 applications.policy.on_unbound_login
   ├─ need_register（默认）→ 返回 AUTH.NEED_REGISTER + 一次性 bind_ticket
   │                         业务方引导用户注册/登录后，带 bind_ticket 调 /v1/bind
   ├─ auto_create          → 调 AccountProvider.Create 建号并绑定 → 正常签发令牌
   └─ session_only         → 签发 scope=identity_only 的受限令牌，业务方自行决定后续
```

`bind_ticket` 是一次性、10 分钟有效、与 identity 绑定的凭据，避免 `bind` 接口被用来抢绑他人身份。

### 5.3 API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/v1/authorize` | 统一授权入口。参数：`app_id` `platform` `scene` `mode=login\|bind` `redirect_uri` `state`（业务侧透传）`code_challenge` `client`（可选，承载形态，仅用于遥测，不参与路由） |
| GET | `/v1/oauth/callback/{platform}` | 统一回调。仅此一个回调地址，上下文由内部 ticket 还原 |
| GET | `/v1/jwks` | **暴露签名公钥集（JWKS）**，供业务方本地验签 `access_token` / `id_token`（修正 P0-2） |
| GET | `/.well-known/openid-configuration` | OIDC Discovery 元数据，指向 `/v1/jwks`（为未来 OIDC 兼容预留） |
| POST | `/v1/token` | `grant_type=authorization_code\|refresh_token\|silent` |
| POST | `/v1/introspect` | 令牌校验，返回 `sub` `app_id` `scope` `exp`。**默认纯本地验签**，仅当传 `check_revocation=true` 时才查 jti 黑名单 |
| GET | `/v1/userinfo` | 归一化的当前用户身份与已绑渠道列表 |
| POST | `/v1/revoke` | 撤销令牌 / 登出 |
| POST | `/v1/bind` | 将三方身份绑定到当前账号。入参含 `bind_ticket`（来自 `NEED_REGISTER` 分支）或当前登录态，二者必居其一 |
| DELETE | `/v1/bind/{identity_id}` | 解绑 |
| GET | `/v1/bindings` | 查询当前账号已绑的全部渠道（引导绑定页面的数据源） |
| POST | `/v1/bind/resolve` | **冲突处置入口**（C5 关键）：当目标身份已被占用时，按 `policy.merge.mode` 返回冲突详情并接收用户的处置选择（`reject` / 走验证合并） |
| POST | `/v1/account/merge` | 账号合并（需双方验证），内部调用 `AccountProvider.Merge`；返回 `{ merged_into }` |
| POST | `/v1/oauth/notify/{platform}` | **三方平台服务端通知接收端点**（修正 P2-1：原为硬编码 `/notify/apple`），内部按平台分发并验签 |
| — | `/admin/v1/*` | **管理端接口，与业务端严格分离**——鉴权、网络暴露、限流、审计体系均独立。完整清单见 **§15 管理端接口设计**（含 11 组共 52 个接口） |

> **本节只覆盖面向接入方（业务系统）的能力。** 管理端接口不属于本文的"业务能力"，其鉴权模型（管理员 Bearer Token + RBAC）、网络边界（内网/VPN）、高危操作二次确认机制等与业务端完全不同，单独成章放在 **§15**。此前版本用一行 `/admin/v1/*` 占位，属于覆盖不全，v0.9 已补齐。

**统一错误码**：形如 `AUTH.INVALID_STATE`、`AUTH.INVALID_NONCE`、`AUTH.NEED_REGISTER`、`BIND.IDENTITY_TAKEN`、`TOKEN.EXPIRED`、`TOKEN.REVOKED`、`PROVIDER.UNAVAILABLE`、`PROVIDER.TIMEOUT`、`PROVIDER.REJECTED`、`AUTH.INVALID_CONFIG`。

**每个错误响应必须携带 `retryable` 字段**（约束 C6 的核心契约，详见 §5.5）——本服务不重试，因此必须明确告知接入方"这个错误能不能通过重开授权流程来解决"。同时在 `details` 中保留三方平台原始错误，便于排障。

### 5.4 Webhook 事件契约（修正 P1-7）

出站 Webhook 必须定义签名、重试与去重，否则业务方无法可靠消费：

| 项目 | 设计 |
| --- | --- |
| 事件体 | `{ "event_id": "01J...", "schema_version": 1, "event_type": "account.merged", "app_id": "...", "occurred_at": "...", "data": {...} }` |
| 签名 | `X-Signature: t=<unix>,v1=<HMAC-SHA256(t + "." + body, app_webhook_secret)>`，与 Stripe 风格一致 |
| 重试 | 指数退避，最多 5 次（1s / 10s / 1min / 10min / 1h）；仍失败则进入死信并告警 |
| 去重 | 业务方按 `event_id` 幂等处理；本服务保证**同一 event_id 不重复投递成功**（至少一次语义） |
| 版本化 | `schema_version` 递增，**新增字段向后兼容，删除/改语义必须升版本号**（对应扩展性 E8） |
| 投递保证 | 至少一次（at-least-once）。若需要严格一次，由业务方用 `event_id` 去重 |
| 顺序 | **不保证**。业务方不得依赖事件到达顺序（例如 `binding.created` 可能晚于 `account.merged`） |

### 5.5 重试边界与失败语义（约束 C6）

**决策**：本服务**对三方渠道的同步调用一律不做网络重试**，重试责任归接入方。

**为什么这是语义问题，而不只是简化**

在授权流程里，正确的重试单位是**「整个授权流程」**，不是**「单个 HTTP 请求」**：

```
用户授权 → 三方平台发放一次性 code → 我们调 Exchange(code)
                                          │
                            ┌─────────────┴─────────────┐
                        超时/5xx                    成功
                            │
                  这个 code 到底被消费了没有？
                  ├─ 未消费 → 重放可以成功
                  └─ 已消费 → 重放必然失败（code 已使用）
            我们无法从客户端区分这两种情况
```

因此`Exchange` 的重放**既不可靠又有副作用**（可能触发平台风控）。而"按接口逐个判断是否幂等"是个**必然出错的抽象**——只要有例外，就有人判断错。

**接入方的正确重试形态**：

| 接入方看到 | 应采取的动作 |
| --- | --- |
| 网络错误 / 5xx（`retryable: true`） | **重新发起一次 `/v1/authorize`**，让用户重新授权取新的 code |
| `code` 已使用 / 无效（`retryable: false`） | 不要重试，重新发起授权或提示用户 |
| `AUTH.NEED_REGISTER` | 走注册引导，不是重试 |

**关键契约**：**接入方重试的是授权流程，不是重放回调**。回调 URL 携带的 `code` 是一次性的，重放同一个回调永远无意义。

**错误响应必须携带重试指引**（扩展 §5.3 的错误码契约）：

```jsonc
{
  "code": "PROVIDER.UNAVAILABLE",
  "message": "三方平台暂时不可用，请稍后重试",
  "retryable": true,           // ★ 新增：接入方据此决定是否重开授权流程
  "retry_after_ms": 0,         // 可选：建议退避时间
  "trace_id": "01J...",        // 便于接入方与我们对日志
  "details": { "platform": "wechat", "scene": "mini_program", "provider_code": 45011 }
}
```

| `retryable` | 典型错误码 | 成因 |
| --- | --- | --- |
| `true` | `PROVIDER.UNAVAILABLE`、`PROVIDER.TIMEOUT` | 网络超时、连接失败、三方 5xx。**接入方应重新发起授权流程**（带退避） |
| `false` | `PROVIDER.REJECTED`、`AUTH.INVALID_STATE`、`AUTH.INVALID_NONCE` | 授权码无效或已消费、state 校验失败。**重试无意义** |
| `false` | `AUTH.NEED_REGISTER`、`BIND.IDENTITY_TAKEN` | 需要业务处理，不是错误重试场景 |
| `false` | `AUTH.INVALID_CONFIG` | 渠道配置错误（凭据失效等），需运维介入 |

**不重试就必须补上的四件事**（否则会出问题）：

**① 超时必须分层且明确配置**

不重试意味着"一次失败就是失败"，所以超时值直接决定用户体验：

| 层级 | 建议值 | 说明 |
| --- | --- | --- |
| 连接超时 | 1s | 到三方平台一般 < 500ms，1s 足够且能快速发现网络问题 |
| 读写超时 | 2~3s | 单次请求 |
| 单渠道总超时 | 微信 3s / 支付宝 3s / Apple 5s | Apple 接口普遍更慢 |
| 整条授权链路预算 | 8s | 从 `/callback` 进入 `/token` 返回，超出即判失败 |

**超时不是可选项**：不重试 + 无超时 = 连接与 goroutine 被耗尽。

**② 快速失败：渠道熔断**

三方平台持续故障时，不做重试但也不能让每个请求都白等 3 秒。熔断器连续失败达阈值后直接快速返回 `PROVIDER.UNAVAILABLE`，不再发起真实调用。**这是"不重试"设计能够成立的配套前提**——没有熔断，不重试就变成了纯粹的慢。

> 完整设计见 **§5.6 渠道熔断设计**。

**③ 取消语义：`Exchange` 不能被调用方断开取消**

这是一个容易被忽略的坑：

```
接入方（浏览器/App）发起回调 → 用户等待 → 用户切走/断网
    → HTTP 连接断开 → 若我们用 request context，Exchange 被取消
    → 但请求可能已经到达微信、code 已被消费
    → 结果丢失：code 没了，我们也没拿到 token
```

因此 **`Exchange` / `Refresh` 这类"已发出即不可撤销"的调用，必须使用脱离调用方 context 的独立 context**（Go 1.21+ 的 `context.WithoutCancel` 加超时），让它跑完并落库结果，再决定如何响应接入方。

**这条与 C6 是配套的**：既然不做重试，就必须保证"唯一的那一次"不会因为客户端断开而丢失。

**④ 明文告知接入方我们的重试策略**

在接入文档中写清楚：

```
我们不重试。你收到的每一个错误要么可安全重开授权流程（retryable: true），
要么重试无意义（retryable: false）。请勿对回调 URL 做重放——
回调携带的 code 是一次性的。
```

### 5.6 渠道熔断设计（Provider Circuit Breaker）

> **本节的由来（v0.11）**：v0.10 引入约束 C6（不重试）后，全文有 5 处提及"熔断"，但都只有动作描述、没有落地设计。本节补齐。

#### 5.6.1 为什么熔断是必需的，不是可选项

C6 决定不重试，但**不重试本身不减少对故障平台的调用量**。没有熔断时，平台故障期间每个登录请求都会：

```
占住一个 goroutine → 占住一个连接 → 白等满超时（最长 5s）→ 失败
```

并发稍高，连接池与 goroutine 就会被耗尽。**而连接池是全局共享的**——微信挂了会连带把 Apple、支付宝的登录也拖垮，甚至影响不涉及任何三方平台的接口。

**熔断的作用就是把"平台故障"限制在单个渠道内，阻止其扩散为服务级故障。**

#### 5.6.2 选型：`sony/gobreaker/v2`

| 候选 | 结论 |
| --- | --- |
| **sony/gobreaker/v2** | ✅ **选用**。Go 生态最主流的熔断库，经典三态模型（Closed / Open / Half-Open），v2 支持泛型，API 简洁，无额外依赖 |
| afex/hystrix-go | ❌ 已长期不活跃 |
| go-kit/kit/circuitbreaker | ❌ 本质是对 gobreaker 的封装，多一层无收益 |
| 自研 | ❌ 熔断的状态迁移与并发边界容易写错，不值得自研 |

#### 5.6.3 熔断粒度：按 `platform`，不是 `platform:scene`

**故障域 = 平台侧集群。** 微信的 `code2session`、`sns/oauth2/access_token`、`sns/qrconnect` 都在 `api.weixin.qq.com` 同一域名下，一个接口不可达通常意味着整站异常。

按 `platform` 熔断的好处：

- **最快止损**——不必等每个场景各自熔断
- **避免无效流量**——若按场景熔断，`mini_program` 已熔断但 `app` 场景仍会持续打同一个故障域名

保留细化能力：`provider_guard.circuit_breaker.granularity = platform | platform_scene`，**默认 `platform`**。仅当某平台的不同场景确实落在独立故障域时才改为 `platform_scene`。

#### 5.6.4 ⚠️ 关键规则一：只有 `retryable` 的错误才计入熔断

**这条写错会造成服务级拒绝服务，必须写死。**

| 错误分类 | 是否计入熔断 | 说明 |
| --- | --- | --- |
| `PROVIDER.TIMEOUT` | ✅ 计入 | 网络超时，平台侧问题 |
| `PROVIDER.UNAVAILABLE` | ✅ 计入 | 连接失败、三方 5xx |
| **`PROVIDER.REJECTED`**（code 无效 / 已使用） | ❌ **不计入** | 这是**业务语义的正常返回**，不是平台故障 |
| `AUTH.INVALID_STATE` / `AUTH.INVALID_NONCE` | ❌ 不计入 | 本服务的校验失败，与平台无关 |
| `AUTH.INVALID_CONFIG`（凭据失效） | ⚠️ 计入，但**单独告警** | 是我们的配置错误，不是平台故障，需运维介入而非等待自愈 |

**反例（必须避免）**：如果把 `PROVIDER.REJECTED` 计入熔断，那么**攻击者只要用无效的 `code` 高频打我们的回调接口，就能把整个微信渠道熔断掉**——这就从"平台故障保护"变成了"服务级拒绝服务"。这不是理论风险，是很直接的攻击路径。

#### 5.6.4b ⚠️ 关键规则二：超时与慢请求必须独立计权

> **本小节的由来（v0.12）**：v0.11 用单一的 `failure_ratio` 统计所有失败，虽然已把超时与慢请求计入，但**丢了区分度**——这不够，需要独立统计、独立阈值。

**为什么超时不能与 5xx 混在一起算**

两者对资源的消耗不是一个量级：

| 失败类型 | 是否占用连接与 goroutine | 典型耗时 | 性质 |
| --- | --- | --- | --- |
| 连接失败 / 三方 5xx | ❌ 快速返回，几乎不占 | < 100 ms | **快失败** |
| **请求超时** | ✅ **占满整个超时窗口**（微信 3s / Apple 5s） | 3~5 s | **慢失败** |
| 慢但成功 | ✅ 占满响应时间 | 2~3 s | **慢失败** |

**平台"半死"状态的典型表现是高延迟 + 低错误率。** 如果只看错误率，这种情况下熔断永远不会触发——错误率可能只有 5%，但每个请求都拖满 3 秒，连接池照样被打满。**只看错误率的熔断，防不住平台变慢。**

**决策：四类信号独立统计、独立阈值，任一触发即 Open。**

| 信号 | 定义 | 默认阈值 | 作用 |
| --- | --- | --- | --- |
| **错误率** `failure_ratio` | 连接失败 + 三方 5xx / 窗口内总请求 | ≥ 50% | 平台宕机的直接信号 |
| **超时率** `timeout_ratio` | `PROVIDER.TIMEOUT` / 窗口内总请求 | ≥ 30% | **慢失败的独立信号**，比错误率更早暴露问题 |
| **慢请求率** `slow_ratio` | 成功且耗时 > `slow_threshold_ms` / 窗口内总请求 | ≥ 50% | 平台拥塞的最早期信号，早于报错出现 |
| **连续超时** `consecutive_timeouts` | 连续超时次数 | ≥ 5 | **低流量渠道兜底** |

`min_requests` 只作用于比率类阈值（防止低流量下 1 个请求失败就熔断）；`consecutive_timeouts` 专门解决"流量小到比率阈值永不触发，但每次都在超时"的场景。

**超时率的阈值故意低于错误率**（30% vs 50%）：因为超时的资源消耗是 5xx 的数十倍，容忍度应该更低。

**⚠️ 慢请求统计的限定（容易被忽略的攻击面）**

**只统计【成功】的慢请求。** `PROVIDER.REJECTED` 这类业务拒绝**即使耗时 3s 也不计入**慢请求率。

原因：业务拒绝是**可被攻击者构造**的（用无效 code 触发平台的慢路径）。如果把它计入慢请求率，攻击者就能**远程触发我们的熔断**——和 §5.6.4 是同一条攻击路径，只是换了个入口。

**超时则没有这个问题**——超时是网络层事实，攻击者无法伪造。

#### 5.6.4c 实现要点：gobreaker 的能力边界

需要说清楚一个实现约束：**`gobreaker` 的 `ReadyToTrip(counts Counts)` 回调里拿不到失败分类**。它只提供：

```
Counts{ Requests, TotalSuccesses, TotalFailures,
        ConsecutiveSuccesses, ConsecutiveFailures }
```

因此分工如下：

| 组件 | 职责 |
| --- | --- |
| **gobreaker** | **只负责状态机** —— Closed / Open / Half-Open 的并发安全迁移、Half-Open 的请求放行控制 |
| **我们自己的滑动窗口**（`internal/pkg/guards/breaker`，每个 platform 一个环形计数器） | **负责失败分类统计** —— 按 `Success / Slow / Timeout / ConnErr / ServerErr / BusinessReject` 分类计数 |
| `Settings.IsSuccessful` | 把 `retryable` 错误、超时、慢请求都判为 failure，让 gobreaker 自身的 counts 也正确 |
| `Settings.ReadyToTrip` | 回调里读取**我们自己的分类窗口**，按 §5.6.4b 的四类阈值判定 |

**自维护窗口的规模**：每个 platform 一个固定长度的环形缓冲（`window_seconds / bucket_seconds` 个桶，默认 60s / 6 桶），只存计数器，内存开销可忽略。**不引入第三方滑动窗口库**——分类计数逻辑与熔断判定耦合紧密，自己写更可控。

#### 5.6.5 配置：服务级，不放 `applications.policy`

```yaml
# configs/config.yaml
provider_guard:
  circuit_breaker:
    enabled: true
    granularity: platform          # platform | platform_scene
    window_seconds: 60             # 统计窗口
    bucket_seconds: 10             # 滑动窗口桶宽（60/10 = 6 个桶）
    min_requests: 20               # 窗口内最少请求数，不足不判熔断（防低流量误判）

    # ---- 四类独立阈值，任一触发即 Open（§5.6.4b）----
    failure_ratio: 0.5             # 连接失败 + 三方 5xx
    timeout_ratio: 0.3             # ★ 超时（慢失败，阈值为何更低见 §5.6.4b）
    slow_ratio: 0.5                # ★ 成功但耗时 > slow_threshold_ms
    slow_threshold_ms: 2000        #   慢请求的判定线
    consecutive_timeouts: 5        # ★ 连续超时（低流量渠道兜底）
    consecutive_failures: 10       #   连续失败

    open_seconds: 30               # Open 状态持续时长，之后转 Half-Open
    half_open_requests: 3          # Half-Open 允许放行的探测请求数
```

**为什么是服务级配置而不是应用级**（重要）：

熔断保护的是**所有应用共享的资源**——进程的连接池与 goroutine。平台故障也是全局的，不区分应用。

如果做成应用级配置，就会出现：App1 配了熔断、App2 配了"不熔断"。平台挂掉时 App2 的流量持续打在故障平台上，**消耗的是两个应用共享的连接池** —— 等于**一个应用可以为所有应用关掉保护**。所以这个开关不能下放到应用。

`count_only_retryable` 不暴露为配置项，**在代码中写死为 `true`**（见 §5.6.4，这是安全红线）。

#### 5.6.6 熔断与 `HealthChecker` 的分工（不要混用）

| 机制 | 类型 | 职责 |
| --- | --- | --- |
| **熔断器**（gobreaker） | **被动统计真实业务调用** | **唯一的熔断决策来源** |
| **`HealthChecker`**（P2-3） | 主动探测（定时 Ping） | **仅用于管理台展示与告警**，不参与熔断决策 |

**为什么不能用 HealthChecker 替代熔断**：主动探测走的**不是真实业务路径**——探测用的接口可能正常，而业务接口异常（限流、特定 appid 被拒等），用探测结果决定熔断必然误判。而且探测本身有开销，高频探测反而增加平台压力。

#### 5.6.7 ⚠️ 多副本的一致性限制（必须知晓）

**熔断器是进程内状态。** N 个副本 = N 个互相独立的熔断器，后果：

| 现象 | 影响 | 是否可接受 |
| --- | --- | --- |
| 各副本在略有偏差的时刻各自熔断 | 多失败几个请求 | ✅ 可接受 |
| `half_open_requests` 被放大为 N × 3 个探针 | 恢复瞬间对平台多打少量请求 | ✅ 副本数不大时可接受 |
| 状态不同步（A 已恢复、B 仍熔断） | 最坏多等一个 `open_seconds` | ✅ 可接受 |

**决策：初期用进程内熔断，不引入 Redis 共享状态。**

理由：**熔断是"降级保护"机制，不应有强外部依赖**。若把熔断状态放 Redis，那么 Redis 故障时熔断失效，保护也就没了——用一个可能故障的组件去保护对另一个组件的故障，逻辑上是错位的。

**需要记录的限制**：副本数超过约 20 后，探针放大与状态分歧会变明显。届时的正确演进是**熔断事件广播**（某副本熔断后通过 Redis Pub/Sub 通知其他副本在本地熔断），而**不是**每次调用都去读 Redis 共享状态。指标 `circuit_breaker_state` 按实例打 label，可直接观测分歧程度。

#### 5.6.8 熔断后的行为

```jsonc
HTTP 503
{
  "code": "PROVIDER.UNAVAILABLE",
  "message": "三方平台暂时不可用，请稍后重试",
  "retryable": true,
  "retry_after_ms": 30000,          // Open 状态的剩余时长，供接入方退避
  "details": { "platform": "wechat", "circuit": "open" }
}
```

关键：**不发起真实调用、不占连接、不等超时**，立即返回。

#### 5.6.9 管理端支持

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/admin/v1/providers/health` | **扩展**：返回中增加 `circuit_state`（`closed` / `open` / `half_open`）、`opened_at`、`recent_failure_ratio`、`half_open_probes_left` |
| POST | `/admin/v1/providers/{platform}:circuit-reset` | **新增**（§15.4 I 组）：手工复位熔断器。用于**误熔断**场景（如我们自己配置错导致的连续失败）。需 `reason`，写管理审计 |

#### 5.6.10 与 C6 的关系总结

```
C6：不重试                      →  一次失败就是失败
      ↓ 必须有
分层超时（§5.5 ①）              →  避免单个请求无限等待
      ↓ 必须有
渠道熔断（本节）                 →  避免故障平台的请求持续占用共享资源
      ↓ 必须有
四类信号独立判定（§5.6.4b）      →  错误率 / 超时率 / 慢请求率 / 连续超时
                                    只看错误率防不住"平台变慢"
      ↓ 必须有
快速失败 + retryable 契约        →  接入方据此决定是否重开授权流程
```

**缺一不可**：只有"不重试"而没有超时和熔断，等于把重试的责任推给接入方的同时，把自己变成了一个会被故障平台拖死的服务；而只有熔断而没有超时率/慢请求率的独立判定，则防不住平台"半死"（高延迟、低错误率）这种最典型的故障形态。

### 5.7 入站请求的超时保护（与渠道熔断的区别）

**概念澄清**：§5.6 的熔断是**出站**方向的——保护我们不被故障的**三方平台**拖垮。本节讨论**入站**方向的——保护我们不被**慢请求**拖垮。两者机制不同，不可互相替代：

| | 渠道熔断（§5.6） | 入站超时保护（本节） |
| --- | --- | --- |
| 保护对象 | 不被故障**平台**拖垮 | 不被**慢请求**拖垮 |
| 方向 | 出站（我们调别人） | 入站（别人调我们） |
| 机制 | 熔断器（三态状态机） | 超时中间件 + `context` deadline |
| 触发后 | 快速失败，**不再调用平台** | 立即返回 `504`，**释放连接与 goroutine** |
| 是否自愈 | 是（Half-Open 自动探测） | 否（每次请求独立判定） |

**三段超时配置**：

```go
// 1. HTTP Server 层（gin 之上）
srv := &http.Server{
    ReadHeaderTimeout: 5 * time.Second,   // 防 Slowloris（慢速 header 攻击）
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      15 * time.Second,
    IdleTimeout:       60 * time.Second,
}

// 2. 中间件层：按路由分组设置业务超时
r.Group("/v1",        timeoutMW(8*time.Second))           // 授权链路预算 8s（§5.5 ①）
r.Group("/admin/v1",  timeoutMW(30*time.Second))          // 管理端普通接口
r.Group("/admin/v1/exports", timeoutMW(10*time.Second))   // 导出类：只提交任务，不等结果

// 3. 依赖调用层：DB / Redis 各自超时，不继承请求的全额预算
ctx, cancel := context.WithTimeout(ctx, 2*time.Second)    // 单次 DB 查询
```

**三条设计要点**：

**① 长任务必须异步，不能靠放大超时** —— 审计导出（§15.4 H 组）这类操作若同步等待，会长时间占住连接。正确做法是提交任务立即返回 `task_id`，由后台 worker 执行。**这是 `/admin/v1/audit-logs:export` 设计成异步接口的原因。**

**② 超时后必须真正取消下游，否则等于没超时** —— 中间件返回 504 但 goroutine 仍在跑、DB 查询仍在执行，连接与 CPU 照样被占。所有超时都必须通过 `context` 向下传递。

**③ 例外：`Exchange` / `Refresh` 不随入站超时被取消** —— 这两类"已发出即不可撤销"的调用使用 `context.WithoutCancel` 脱离入站 context（§5.5 ③）。入站超时到了可以先给接入方返回 `504` + `retryable: true`，但**三方调用本身要继续跑完并落库结果**，避免授权码被消费却拿不到 token。

**三种保护机制的分工（互补，不可互相替代）**：

| 机制 | 保护什么 | 位置 |
| --- | --- | --- |
| 入站限流（§6.3） | **请求速率** | 中间件，入站 |
| 入站超时（本节） | **单请求时长** | 中间件，入站 |
| 渠道熔断（§5.6） | **下游可用性** | 出站调用点 |

---

## 6. 数据模型

### 6.1 领域关系

```
Application ──1:N──→ AppProviderConfig        应用持有多个渠道配置
Application ──1:N──→ Identity                 三方身份按应用隔离（约束 C1）
Application ──1:N──→ Binding                  绑定关系同样按应用隔离
Identity    ──1:N──→ IdentityClaim            可信凭证：手机号 / 邮箱 / union_id
Identity    ──1:1──→ Binding(active)          一个三方身份同期只能绑一个账号
ExternalAccount ─1:N→ Binding                 业务方账号（约束 C4：本服务不存，仅持引用）
ExternalAccount ─1:N→ RefreshToken            多设备多令牌
AppProviderConfig ─1:N─→ Ticket               配置驱动授权上下文
```

> `ExternalAccount` 是**逻辑实体，不是本服务的表**（约束 C4）。它以 `external_user_id` 的形式被 `oauth_bindings` 与 `refresh_tokens` 引用，主数据始终在用户中心。

### 6.2 DDL（PostgreSQL 语法，MySQL 差异见注释）

```sql
-- 接入方应用
CREATE TABLE applications (
    id            BIGSERIAL PRIMARY KEY,
    app_code      VARCHAR(64)  NOT NULL UNIQUE,   -- 对外 app_id
    name          VARCHAR(128) NOT NULL,
    app_secret_hash VARCHAR(128) NOT NULL,        -- 应用级密钥（哈希存储）
    status        SMALLINT     NOT NULL DEFAULT 1, -- 1 启用 0 停用
    account_mode  VARCHAR(16)  NOT NULL DEFAULT 'remote', -- 约束 C4：固定 remote
    policy        JSONB        NOT NULL DEFAULT '{}',    -- 首次登录处置 + 合并行为配置（见 §7.5.1）
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 渠道配置：一个业务应用、一个接入场景 对应一份凭据
-- 唯一键 = (app_id, platform, scene, config_key)，不含承载形态（规则 2）
CREATE TABLE app_provider_configs (
    id                   BIGSERIAL PRIMARY KEY,
    app_id               BIGINT       NOT NULL REFERENCES applications(id),
    platform             VARCHAR(32)  NOT NULL,  -- 权威枚举见文首表：wechat / alipay / apple / generic_oauth2
    scene                VARCHAR(32)  NOT NULL,  -- 接入场景：app / mini_program / official_account / pc_qr / web
                                                 -- 注意：app 场景同时服务 iOS 与 Android，不拆分配置
    -- config_key：同一 (app, platform, scene) 下的多套凭据标识（扩展性 E1）
    -- 默认 'default'。用于"一个业务应用要接两个小程序""同平台多套开放平台账号"等场景。
    -- 路由键扩展为可选四元组 (app_id, platform, scene, config_key)，未指定即取 'default'。
    config_key           VARCHAR(64)  NOT NULL DEFAULT 'default',
    provider_app_id      VARCHAR(128) NOT NULL,  -- wx_appid / alipay_app_id / apple_client_id
    secret_cipher        BYTEA,                  -- 信封加密后的凭据（当前有效）
    secret_cipher_prev   BYTEA,                  -- 上一版凭据，用于轮换过渡期双验证（扩展性 E6）
    secret_rotated_at    TIMESTAMPTZ,            -- 上次轮换时间，用于决定何时清理 prev
    secret_dek_id        VARCHAR(64),            -- 加密该凭据的 DEK 标识
    env                  VARCHAR(16)  NOT NULL DEFAULT 'prod', -- prod | test，环境隔离（扩展性 E5）
    extra                JSONB        NOT NULL DEFAULT '{}', -- 平台私有配置
    version              BIGINT       NOT NULL DEFAULT 1,
    status               SMALLINT     NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (app_id, platform, scene, config_key, env)
);

-- 账号主数据表已按约束 C4 移除：本服务不维护 accounts。
-- 账号由独立的用户中心服务持有，本服务通过 AccountProvider SPI 访问（见 D3）。
-- 若未来需要本地缓存用户中心的账号状态，可另建只读缓存表，且不得作为写入源。

-- 三方身份：唯一索引是整个模型的安全底线
CREATE TABLE oauth_identities (
    id              BIGSERIAL PRIMARY KEY,
    app_id          BIGINT       NOT NULL REFERENCES applications(id), -- 约束 C1：身份按应用隔离
    platform        VARCHAR(32)  NOT NULL,
    provider_app_id VARCHAR(128) NOT NULL,     -- 平台侧应用标识
    open_id         VARCHAR(191) NOT NULL,     -- 平台内用户标识
    union_id        VARCHAR(191),              -- 保留字段，约束 C3 下恒为空
    identity_key    VARCHAR(191) NOT NULL,     -- 约束 C3 下 = open_id（不再有 union_id 归并）
    profile_snapshot JSONB       NOT NULL DEFAULT '{}',
    profile_synced_at TIMESTAMPTZ,
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    UNIQUE (app_id, platform, provider_app_id, open_id)
);
-- 归并查询必须带 app_id，否则跨应用串号
CREATE INDEX idx_identities_key ON oauth_identities (app_id, platform, identity_key);

-- 归并依据（约束 C3 的核心表）：手机号 / 邮箱 / union_id 等可信凭证
-- 设计要点：一个身份可有多个 claim（改绑手机号），且必须区分是否已验证
CREATE TABLE identity_claims (
    id                 BIGSERIAL PRIMARY KEY,
    app_id             BIGINT       NOT NULL REFERENCES applications(id),
    identity_id        BIGINT       NOT NULL REFERENCES oauth_identities(id),
    claim_type         VARCHAR(32)  NOT NULL,  -- phone | email | union_id | custom
    claim_value_hash   VARCHAR(128) NOT NULL,  -- 归一化后的哈希，用于匹配（不存明文）
    claim_value_cipher BYTEA,                  -- 密文原文，仅在需要回显时使用
    verified           BOOLEAN      NOT NULL DEFAULT false,
    verified_at        TIMESTAMPTZ,
    -- source 权威枚举（修正 A6，须与 §7.5.3 白名单一致）：
    --   wechat_phone | alipay_phone | sms_verified | apple_email   ← 平台/服务端已验证，可用于自动归并
    --   manual                                                     ← 用户手填，永不参与自动归并
    source             VARCHAR(32)  NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ
);
CREATE INDEX idx_claims_identity ON identity_claims (app_id, identity_id);

-- ★ 修正 P0-1：唯一性必须只约束「已验证 + 未撤销」的 claim。
-- 原设计用普通 UNIQUE，会把未验证的手填手机号也占住唯一键，
-- 导致真正通过平台验证的用户反而插不进来；且 revoked_at 未进索引，
-- 解绑换号后原号码永久不可复用。
CREATE UNIQUE INDEX uk_claims_verified
    ON identity_claims (app_id, claim_type, claim_value_hash)
    WHERE verified = true AND revoked_at IS NULL;

-- 未验证的 claim 只需普通索引，不参与唯一性判定
CREATE INDEX idx_claims_unverified
    ON identity_claims (app_id, identity_id)
    WHERE verified = false;

-- MySQL 无部分唯一索引，等价实现（生成列 + 唯一索引）：
--   ALTER TABLE identity_claims
--     ADD COLUMN verified_key VARCHAR(128)
--       GENERATED ALWAYS AS (IF(verified = 1 AND revoked_at IS NULL, claim_value_hash, NULL)) STORED,
--     ADD UNIQUE KEY uk_claims_verified (app_id, claim_type, verified_key);
--   -- NULL 不参与唯一性判定，语义与部分唯一索引一致

-- 绑定关系：部分唯一索引保证「一个身份同期只绑一个账号」
CREATE TABLE oauth_bindings (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT       NOT NULL REFERENCES applications(id), -- 约束 C1
    external_user_id VARCHAR(128) NOT NULL,   -- 约束 C4：业务方账号标识，非本服务主键
    identity_id      BIGINT       NOT NULL REFERENCES oauth_identities(id),
    status           VARCHAR(16)  NOT NULL DEFAULT 'active', -- active | unbound
    is_primary       BOOLEAN      NOT NULL DEFAULT false,    -- 是否主登录方式
    bind_source      VARCHAR(32)  NOT NULL,                  -- login | explicit | merge | admin
    bound_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    unbound_at       TIMESTAMPTZ
);
-- 核心约束：一个三方身份同期只能绑一个账号
CREATE UNIQUE INDEX uk_bindings_active
    ON oauth_bindings (identity_id) WHERE status = 'active';
CREATE INDEX idx_bindings_user ON oauth_bindings (app_id, external_user_id, status);

-- 刷新令牌：只存哈希，支持轮转与重放检测
CREATE TABLE refresh_tokens (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT       NOT NULL,
    external_user_id VARCHAR(128) NOT NULL,
    token_hash       VARCHAR(128) NOT NULL UNIQUE,
    device_id        VARCHAR(128),
    scope            VARCHAR(512),
    expires_at       TIMESTAMPTZ  NOT NULL,
    rotated_from     BIGINT,                      -- 轮转来源，形成链条
    revoked          BOOLEAN      NOT NULL DEFAULT false,
    revoked_reason   VARCHAR(64),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_rt_user ON refresh_tokens (app_id, external_user_id);

-- 账号合并操作记录：幂等与补偿的依据（约束 C4 三次独立事务合并必需）
CREATE TABLE merge_operations (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT       NOT NULL,
    idempotency_key  VARCHAR(128) NOT NULL,
    target_user_id   VARCHAR(128) NOT NULL,
    source_user_id   VARCHAR(128) NOT NULL,
    status           VARCHAR(16)  NOT NULL,  -- pending | done | failed | rolled_back
    remote_result    JSONB,                  -- 用户中心 Merge 的返回，便于排障
    attempts         INT          NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (app_id, idempotency_key)
);
-- 补偿任务扫描待处理记录
CREATE INDEX idx_merge_pending ON merge_operations (status) WHERE status = 'pending';

-- 事件外发表（Transactional Outbox，修正 P0-3）
-- 事件与业务变更在同一事务写入，由独立 worker 投递，避免"事务回滚但事件已发出"
CREATE TABLE event_outbox (
    id             BIGSERIAL PRIMARY KEY,
    app_id         BIGINT       NOT NULL,
    event_id       VARCHAR(64)  NOT NULL UNIQUE,  -- 业务方按此去重（§5.4）
    event_type     VARCHAR(64)  NOT NULL,         -- account.merged | binding.created | ...
    schema_version INT          NOT NULL DEFAULT 1,
    payload        JSONB        NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'pending', -- pending | sent | dead
    attempts       INT          NOT NULL DEFAULT 0,
    next_retry_at  TIMESTAMPTZ,
    last_error     TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    sent_at        TIMESTAMPTZ
);
-- worker 拉取待投递事件
CREATE INDEX idx_outbox_pending ON event_outbox (next_retry_at)
    WHERE status = 'pending';

-- 审计日志
CREATE TABLE auth_audit_logs (
    id               BIGSERIAL PRIMARY KEY,
    app_id           BIGINT,
    external_user_id VARCHAR(128),
    platform         VARCHAR(32),
    scene            VARCHAR(32),        -- 接入场景（路由键的一部分）
    client           VARCHAR(32),        -- 承载形态：ios | android | mini_program | h5 | web | admin
                                         -- 仅用于遥测与风控，不参与配置查找（规则 2）
    action           VARCHAR(32) NOT NULL,   -- login / bind / unbind / merge / revoke
    result           VARCHAR(16) NOT NULL,   -- success / failure
    error_code       VARCHAR(64),
    client_ip        INET,
    user_agent       TEXT,
    trace_id         VARCHAR(64),
    detail           JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_user_time ON auth_audit_logs (app_id, external_user_id, created_at DESC);
-- 按承载形态做分析（如"iOS 端登录成功率"），但配置不按此维度拆分
CREATE INDEX idx_audit_client ON auth_audit_logs (app_id, platform, client, created_at DESC);
```

**约束 C4 的落地要点**

1. `external_user_id` 是**外部引用**，不加外键约束（用户中心是另一个服务/库）
2. 该字段长度按用户中心实际 ID 规则设定，若用户中心用 ULID/UUID 则 128 足够；用自增数字则需评估可枚举风险（见 §8.1）
3. 用户中心不可用时的降级行为必须明确：**登录链路不可用**（因为无法确认账号状态），但**已签发的 access_token 仍然有效**（本地验签，15 分钟自然过期）
4. 用户中心与本服务之间建议使用内部服务鉴权（mTLS 或内网签名），并对 `Merge` 这类高危接口做二次确认

**关于 `app_id` 的一点说明（约束 C1 的直接后果）**

如果两个**业务应用**配置了**同一个** `provider_app_id`（例如 App1 与 App2 都接入了同一个微信公众号），它们在 `oauth_identities` 中会是**两条独立记录**，各自 `profile_snapshot`、各自绑定到各自的账号。这是刻意的：隔离优先于存储节省。代价是同一个自然人跨业务应用使用时会创建两份身份数据，业务方若有合并需求，走 `account_links`（见 §1.4）。

### 6.3 Redis 键设计

| Key 模式 | 内容 | TTL |
| --- | --- | --- |
| `oauth:ticket:{state}` | 授权上下文 JSON（appId/platform/scene/configKey/redirectUri/mode/bindExternalUserId/codeChallenge/**appleNonce**） | 5 min |
| `oauth:code:{code}` | 待交换的登录结果（externalUserId/identityId/appId/mode） | 60 s |
| `oauth:bindticket:{ticket}` | `NEED_REGISTER` 分支返回的一次性绑定票据，绑定到具体 identity（修正 A16） | 10 min |
| `oauth:replay:{fingerprint}` | 已消费票据指纹，用于重放检测告警（修正 A16：原命名与 Apple nonce 混淆） | 10 min |
| `oauth:jwks:{platform}` | 三方平台公钥集缓存（如 Apple JWKS，修正 P1-3） | 1 h |
| `oauth:sessionkey:{identityId}` | 小程序 `session_key`，仅用于解密手机号，用后即删（修正 P1-2） | ≤ 平台有效期 |
| `oauth:revoked_jti:{jti}` | 已撤销的 `access_token` 标识**黑名单**（修正 P0-5），仅高危撤销（账号劫持 / 注销 / 强制下线）写入 | = 该 token 剩余有效期 |
| `config:app:{appId}` | 解密后的应用配置缓存 | 5 min |
| `lock:merge:{targetUserId}` | 账号合并互斥锁 | 30 s |
| `rl:app:{appId}:ip:{ip}` | 限流：应用 + IP 维度 | 60 s |
| `rl:platform:{platform}:day` | 限流：**平台维度日配额**（如微信日调用量上限，修正 P1-8） | 当日 |
| `rl:identity:{identityId}` | 限流：**身份维度**（防撞库与暴力绑定，修正 P1-8） | 60 s |
| `rl:global:{endpoint}` | 限流：**全局维度**兜底保护 | 60 s |

**限流超限行为**（修正 P1-8）：`rl:platform:*` 超限 → 快速失败并返回 `PROVIDER.QUOTA_EXCEEDED`（**不排队**，避免请求堆积拖垮服务）；`rl:app:*` / `rl:identity:*` 超限 → 返回 `RATE.LIMITED` 并带 `Retry-After`；`rl:global:*` 仅用于过载保护，触发时全量降级。

---

## 7. 账号绑定与冲突处理

### 7.1 决策流程

```
① 三方授权成功 → 归一化 identity（open_id 精确匹配）
        ↓
② 该 identity 是否已有活跃绑定？
   ├─ 否 → ③ 无绑定分支（约束 C4：本服务不能自己产出账号）
   │        · login 模式：
   │            先看 policy.merge.on_login（仅 mode=auto 时为 claim_verified）
   │              命中已验证凭证对应的既有账号 → 直接登录该账号并建绑定（S2 自动归并）
   │            未命中 → 读 policy.on_unbound_login
   │              need_register（默认）→ 返回 AUTH.NEED_REGISTER + bind_ticket
   │              auto_create          → 调 AccountProvider.Create 建号并绑定
   │              session_only         → 签发 scope=identity_only 受限令牌
   │        · bind 模式：断言登录态，把 identity 绑到当前账号
   └─ 是 → ④ 比对已绑定的 external_user_id 与当前上下文
            · 一致（login 命中 / bind 目标就是本人）→ 直接放行
            · 不一致 → 按 policy.merge.mode 分叉（§7.5.2）
                 auto    → 直接合并（须过 R4 安全红线校验）
                 confirm → 返回冲突详情，用户确认 + 验证后合并
                 manual  → 返回 BIND.IDENTITY_TAKEN，不提供合并
        ↓
⑤ 签发本地令牌与一次性 auth_code
```

> 注意步骤 ④ 的"不一致"分支在 C5 下是**设计预期内的正常路径**，而不是异常：用户先在小程序登录产生了账号 B，之后在 App 登录产生账号 C，当他在 C 里点"绑定微信小程序"时必然命中此分支。这正是需求 R1（同应用内跨接入场景支持合并）要处理的主场景。

### 7.2 冲突策略

冲突发生时的行为由 **`applications.policy.merge.mode`** 驱动（需求 R2，配置模型见 §7.5），下表是配置取值与底层策略的对应关系：

| `merge.mode` | 底层冲突策略 | 行为 | 适用场景 |
| --- | --- | --- | --- |
| `confirm`（默认） | `verify_then_merge` | 返回冲突详情，用户通过已绑定渠道或验证码二次验证后合并 | 面向 C 端的产品 |
| `auto` | `auto_merge` | 直接把原绑定账号并入当前账号，无需确认（须过 §7.5.3 安全红线） | 内部系统、企业应用 |
| `manual` | `reject` | 返回 `BIND.IDENTITY_TAKEN`，提示"该微信已绑定其他账号"，仅展示不处理 | 高风险业务 |

另有 `transfer` 策略（把 identity 从旧账号转移到当前账号，旧账号保留）作为特殊业务的旁路，仅可通过管理台手工触发，不开放配置。

**同一配置在 login 与 bind 两种 mode 下行为不同**，必须区分：

| mode | 命中冲突时的行为 |
| --- | --- |
| `login` | **不合并**。返回冲突提示，引导用户"用原账号登录"。理由：登录场景下用户尚未证明对当前账号的控制权，此时合并等于开了后门 |
| `bind` | 按 `merge.mode` 处理。因为是已登录用户主动发起的绑定操作，用户意图明确 |

### 7.3 账号合并的实现要点

> 合并的边界：受约束 C1 限制，**合并只发生在同一个业务应用内部**的两个账号之间。跨业务应用的账号关联走 `account_links`（§1.4），语义是"认亲"而非"合并"，两者的数据影响面和风险等级完全不同，不要混用一套接口。

**约束 C4 带来的关键变化**：本服务不再是账号的持有者，合并必须跨服务完成。**修正 P0-3**：v0.7 描述的"一段事务包住跨服务调用"存在**永久孤儿窗口**，现改为**三次独立事务，网络调用不持有数据库事务**：

```
第 0 步 · 前置校验（只读，不开启长事务）
  · 校验双方归属：confirm 模式走用户验证；auto 模式校验 claim 白名单（§7.5.3 红线 1）
  · P0-6：若归并依据是手机号，回源 AccountProvider.GetByClaim 核对用户中心的有效手机号
  · 取互斥锁 lock:merge:{targetUserId}

第 1 步 · 独立事务 ①  ——  先持久化，保证可补偿
  · INSERT merge_operations(status = 'pending', idempotency_key, ...)
  · COMMIT（必须先提交，不能与后续步骤共用一个事务）

第 2 步 · 无数据库事务  ——  跨服务调用
  · AccountProvider.Merge({ IdempotencyKey: merge_operations.id, Target, Source, Reason })
  · 失败 → 更新 status = 'failed'（可重试），到此为止，本地数据零变更

第 3 步 · 独立事务 ②  ——  本地收敛
  · 改绑 oauth_bindings：把 source 的 active 绑定改挂到 target
  · 撤销 source 的全部 refresh_tokens
  · UPDATE merge_operations SET status = 'done'
  · COMMIT

第 4 步 · 事务 ② 提交成功后（事务外）
  · 发 account.merged 事件（走 outbox，见下）、写审计日志、通知 source 账号
```

**为什么必须这样拆（修正 P0-3 的核心）**：

| 旧设计的问题 | 后果 |
| --- | --- |
| 第 1 步的 `pending` 记录与远端调用在**同一个事务**里 | 远端**成功**后若事务提交失败 → 本地无记录 → 补偿任务扫不到 → **远端已合并、本地仍视为两个账号，永久孤儿且不可逆** |
| HTTP 调用持有数据库事务 | 长时间占用连接与行锁，高并发下拖垮连接池 |

新设计中**任一步失败都可安全重试**——因为 `pending` 记录在调用远端之前就已经持久化。

**补偿任务**：定时扫描 `merge_operations WHERE status IN ('pending','failed') AND attempts < N`，按 `idempotency_key` 重试第 2~4 步。**这要求用户中心的 `Merge` 必须幂等**（§D3 的 `MergeRequest.IdempotencyKey`）。

> **若用户中心暂时无法实现幂等**：补偿策略降级为**只告警不自动重试**，由人工通过管理台核对后手动推进，并在 §13 第一期中明确记录该降级。**不要把非幂等的 `Merge` 放进自动重试链路**——重复执行合并会造成数据损坏。

**事件外发走 Outbox**：`account.merged` 等事件在第 3 步事务内写入 `outbox` 表，由独立 worker 投递（而非事务内直接发 HTTP）。这样避免"事务回滚了但事件已经发出"的不一致。投递保证与签名见 §5.4。

合并必须满足三个条件，缺一不可：

1. **双方归属都需要被证明** —— 不能凭单侧登录就吞掉另一个账号。`confirm` 模式下由用户完成验证；`auto` 模式下由**平台侧已验证凭证**（§7.5.3 红线 1 的白名单）替代用户验证。**两种模式都必须满足此条，只是证明方式不同。**
2. **幂等** —— `lock:merge:{target}` 加锁 + `merge_operations` 记录幂等键，重复请求返回首次结果
3. **可回溯** —— 本地只做数据标记（binding 改挂而非删除），远端账号是否软删由用户中心决定；保留 N 天回滚窗口

**业务方必须订阅 `account.merged` 事件**：业务方自己的 user 表、订单、外键关系都需要它来处理。这是 C4 模式下刻意暴露给业务方的核心耦合点，也是必须在用户中心建设时一并设计的部分。

**合并的返回与前端配合**：`/v1/account/merge` 成功后返回 `{ "merged_into": "<target_user_id>" }`。因为 source 账号的 `refresh_tokens` 已被全部撤销，持有 source 令牌的客户端会收到 `TOKEN.REVOKED` —— 业务方前端应据此引导用户重新登录（或直接用 target 账号的会话继续）。**这一步的产品引导必须做**，否则用户会突然"被登出"而不知所措。

**合并后的身份归属**：source 账号下的所有 `oauth_bindings` 改挂到 target，因此合并完成后 target 账号同时持有 `wechat:app`、`wechat:mini_program` 等多个 identity —— 这正是需求 R1 想要的结果。

### 7.4 无 unionid 条件下的归并策略（约束 C3 的核心应对）

**必须先认清问题**：C3 生效后，同一个自然人在同一个业务应用里，通过 `wechat:app`、`wechat:mini_program`、`wechat:official_account` 三个接入场景登录会得到**三个不同的 openid**，默认会被识别为三个独立账号。这不是 bug，是缺失归并依据的必然结果。

三套候选策略见下，**已确认采用 S1**（约束 C5）。注意 S1 描述的是**登录阶段的归并与账号创建策略**；账号产生之后的**合并激进度**另由 `applications.policy.merge.mode` 控制（§7.5）。两者的关系是：S1 决定"怎么产生账号"，`merge.mode` 决定"怎么收敛账号"。

#### ✅ 方案 S1 · 独立账号 + 引导绑定 + 支持合并（**已选定，约束 C5**）

**目标状态**：同一用户在同一个业务应用内**最终只有一个账号**；达成路径由 `merge.mode` 配置决定（需求 R1 / R2）。

- 每个接入场景各自创建账号，互不识别（注意：iOS 与 Android 同属 `wechat:app` 一个场景，因此它们不会互相分裂）
- 用户在"账号设置 → 关联账号"里主动绑定其他渠道；若该渠道已被另一个账号占用，则按 **`merge.mode`** 处置（`confirm` 默认验证后合并 / `auto` 直接合并 / `manual` 仅提示），见 §7.5
- 优点：不做隐式归并，行为可预测；合并激进度可按应用配置，从"用户明确确认"到"无感自动"都能覆盖
- 代价：默认 `confirm` 模式下合并前会短暂存在多个账号；**合并能力必须完整实现**（见 §1.4 的 C4+C5 结论与需求 R1）

**S1 必须交付的三项能力**（缺一不可，否则"引导绑定"是空话）：

| # | 能力 | 说明 |
| --- | --- | --- |
| 1 | 关联账号管理页 | `GET /v1/bindings` 返回已绑渠道列表 + 可绑渠道列表（含各渠道当前绑定状态） |
| 2 | 绑定入口与冲突处置 | `POST /v1/bind` + `POST /v1/bind/resolve`；冲突时展示"该微信已绑定账号 B"，给用户两个选项：改用账号 B 登录 / 验证后合并 |
| 3 | 合并链路 | §7.3 的完整实现，含 `verify_then_merge` 验证手段（短信验证码是 C3 下最通用的验证方式） |

**合并的触发场景举例**（全部是同一业务应用内部）：

| 用户操作顺序 | 产生结果 | 用户后续动作 |
| --- | --- | --- |
| 先在小程序登录，后在 App 登录 | 账号 B（小程序）、账号 C（App） | 在 C 里绑定"微信小程序" → 验证 → C 合并 B |
| 先在公众号 H5 登录，后在小程序登录 | 账号 D、账号 E | 在 E 里绑定"微信公众号" → 验证 → E 合并 D |
| 只在 iOS 和 Android 用微信登录 | **只有一个账号**（同属 `wechat:app`） | 无需合并 |

#### 方案 S2 · 手机号为账号主键（**已降级为 S1 的一个配置档位**）

原先 S2 是作为 S1 的替代方案提出的。引入 §7.5 的合并配置后，**S2 不再是独立方案，而是 S1 的一个配置组合**：

```jsonc
"merge": {
  "mode": "auto",
  "on_login": "claim_verified"   // ← 开了这个，行为就等价于 S2
}
```

- 授权时**同时要求手机号**：微信小程序用 `getPhoneNumber`、支付宝用手机号授权、其他渠道用短信验证码
- 手机号写入 `identity_claims`，作为第 2 优先级归并依据
- 登录流程变为：拿到 openid → 拿到已验证手机号 → 按手机号哈希查 claim → 命中则归并到既有账号，未命中则新建
- 优点：一人一号，跨接入场景自动归并，且手机号是业务方通用的用户标识
- 缺点：多一步授权，iOS 上 Apple 登录**拿不到手机号**（需引导补填或短信验证）
- **注意**：`on_login = claim_verified` 受 §7.5.3 红线 1 约束，只能使用平台侧已验证的手机号，**不能使用用户手填的手机号**

**这就意味着不需要"未来再单应用试点 S2"** —— 哪个应用想用 S2，直接改它的 `merge` 配置即可，无需任何代码或表结构变更。这是需求 R2 配置化带来的直接收益。

#### 方案 S3 · 临时账号 + 升级合并（本期不采用）

- 首次登录先建"临时账号"，可浏览但功能受限
- 触发关键操作（下单、发布内容）时要求验证手机号
- 验证通过后：若手机号已有对应账号 → 把临时账号合并过去；若无 → 直接把临时账号升级为正式账号
- 优点：转化率高，符合"先体验后注册"
- 缺点：需要完整的合并链路与数据迁移，且用户中途可能流失在"临时账号"状态
- 未采用原因：C4 模式下"临时账号"需要用户中心支持账号状态机，建设成本高，本期不做

#### 通用护栏（S1 下仍然必须实现）

| 护栏 | 原因 |
| --- | --- |
| 只有 `verified = true` 且 `revoked_at IS NULL` 的 claim 才能参与任何归并/合并判定 | 未验证的手机号可被任意填写，用它归并等于开放账号劫持（对应 P0-1 的索引修正） |
| **归并依据的 `source` 必须命中 §7.5.3 白名单**（`wechat_phone` / `alipay_phone` / `sms_verified` / `apple_email`） | `source = manual`（用户手填）永不参与自动归并，这是 R4 红线的判定基础 |
| `confirm` 模式下合并前必须向该手机号/邮箱发送确认，或要求用户在当前会话中完成验证 | 防止 A 用户输入 B 的手机号把 B 的账号并走 |
| 归并前回源 `GetByClaim` 核对用户中心侧的**当前**手机号归属，不一致则拒绝归并 | 本服务 claim 可能滞后于用户中心（§8.5）。**宁可漏归并，不可错归并** |
| claim 匹配到**多个**身份时报错而非择一 | 说明数据已有脏数据，静默择一会造成不可逆的账号错乱 |
| 绑定/合并操作全部写审计日志并支持人工回滚 | 归并是高风险不可逆操作 |
| 监控 `bind_resolve_total{resolution}`、`claim_mismatch_total` 与 `merge_compensation_lag_seconds` | 冲突率异常说明产品引导有问题；后两项是数据一致性的探针 |

#### 与 unionid 的兼容

`MergeKeyResolver` 的第 4 级来源预留给 `union_id`。若未来开通了微信开放平台账号绑定并能拿到 unionid，只需在该 resolver 中启用该级别，**表结构无需变更**，`oauth_identities.union_id` 与 `identity_claims` 中的 `union_id` 类型都已预留。

---

### 7.5 合并行为的配置化（需求 R2）

不同业务对"合并激进度"的容忍度差异很大：企业内部系统希望无感自动合并，面向 C 端的消费产品则必须让用户明确确认。因此合并行为做成**应用级配置**，在应用接入时一次性选定，后续可在管理台调整。

#### 7.5.1 配置模型

合并配置统一挂在 `applications.policy.merge` 下（`applications.policy` 是 JSONB，无需改表）：

```jsonc
// applications.policy
{
  // 首次三方登录但无绑定时的处置（见 D3）
  "on_unbound_login": "need_register",        // need_register | auto_create | session_only

  // ★ 合并行为（需求 R2 的核心配置）
  "merge": {
    // 合并模式：应用接入时选择
    "mode": "confirm",                        // auto | confirm | manual

    // confirm 模式下的验证强度（mode=confirm 时必填且不可为 none，见 §7.5.4）
    "verification": "sms",                    // existing_binding | sms | strict
                                              //   existing_binding 最弱但体验最好
                                              //   sms              最通用（C3 下推荐）
                                              //   strict           sms + 二次确认弹窗

    // 登录时对已验证凭证的处理（修正 P1-6）
    "on_login": "off",                        // off | detect_only | claim_verified
                                              //   off            只按 open_id 精确匹配（默认）
                                              //   detect_only    检测到"同凭证已有账号"时，
                                              //                  返回提示但不归并，由前端引导用户
                                              //                  主动走合并流程（confirm 模式可用）
                                              //   claim_verified 直接归并到该账号（仅 mode=auto 允许）

    // 被合并账号是否发送通知（R4 红线，不允许为 false）
    "notify_source_account": true,

    // 合并后 source 账号的处置
    "source_disposal": "mark_merged",         // mark_merged | request_delete

    // 跨平台自动合并开关（R4 红线 3，默认关闭）
    "allow_cross_platform_auto": false
  }
}
```

**`on_login` 三档语义澄清（修正 P1-6）**：v0.7 的表格里，`confirm` 模式写"可返回提示同手机号已有账号"，但又写 `on_login` 强制 `off`——**这是矛盾的**：要检测就必须读取 claim 并比对，属于一种（只读的）归并判定。现引入独立的 `detect_only` 档位消除歧义：

| `on_login` | 是否读取 claim | 是否归并 | 返回给前端 |
| --- | --- | --- | --- |
| `off` | 否 | 否 | 正常登录 / `NEED_REGISTER` |
| `detect_only` | 是 | **否** | 额外返回 `hint: "same_claim_exists"`，前端据此引导用户主动合并 |
| `claim_verified` | 是 | **是** | 直接登录到命中的账号 |

`detect_only` 是**只读判定，不改变任何数据**，因此 `confirm` 与 `manual` 模式均可使用；`claim_verified` 会写数据，**仅 `mode=auto` 允许**。

#### 7.5.2 三种模式的行为差异

关键是要区分**两个触发场景**，它们在同一个 `mode` 下行为不同：

**场景 A · 登录时（`mode=login`）**——三方登录成功，identity 无活跃绑定

| `merge.mode` | 允许的 `on_login` | 行为 |
| --- | --- | --- |
| `auto` | `claim_verified` | 提取平台返回的**已验证手机号/邮箱** → 命中已有账号 → 直接登录该账号并建绑定（**这就是 S2 的自动归并**） |
| `auto` | `off` / `detect_only` | 不归并，按 `on_unbound_login` 处置（`detect_only` 额外返回同凭证提示） |
| `confirm` | `off` / `detect_only` | **不允许 `claim_verified`**。`detect_only` 时返回 `hint: "same_claim_exists"`，前端引导用户走"绑定 → 冲突 → 验证 → 合并"的正常流程 |
| `manual` | `off` / `detect_only` | 同 `confirm`，但前端**不提供合并入口**，仅提示"该渠道已被占用" |

**场景 B · 绑定时（`mode=bind`）**——用户已登录账号 C，要绑的 identity_X 已绑账号 B

| `merge.mode` | 行为 | 用户路径 |
| --- | --- | --- |
| `auto` | 直接合并 B → C，无需用户确认 | 点"绑定"即完成，前端提示"已合并" |
| `confirm` | 返回冲突详情，用户确认后按 `verification` 强度验证，再合并 | 点绑定 → 弹窗确认 → 收验证码 → 完成 |
| `manual` | 返回 `BIND.IDENTITY_TAKEN`，不提供合并 | 提示"该微信已绑定其他账号，请改用该账号登录" |

#### 7.5.3 `auto` 模式的安全红线（需求 R4，不可配置关闭）

**这条必须写死，否则 `auto` 就是一个账号劫持漏洞。**

🔴 **红线 1 · 归并依据必须是平台侧已验证的凭证**

```
✅ 允许：微信小程序 getPhoneNumber 返回的手机号（微信已验证）
✅ 允许：支付宝手机号授权返回的手机号（支付宝已验证）
✅ 允许：Apple id_token 中已验证的 email
❌ 禁止：用户在表单里手填的手机号
❌ 禁止：未经验证的 openid / 昵称 / 头像等弱标识
❌ 禁止：unionid（C3 下不可用）
```

**校验方式**（修正 A6，枚举须与 §6.2 DDL 完全一致）：

```
允许的 source 白名单（同时要求 verified = true 且 revoked_at IS NULL）：
  wechat_phone      ← 微信小程序 getPhoneNumber（需 session_key 解密）
  alipay_phone      ← 支付宝手机号授权
  sms_verified      ← 短信验证码（本服务发起并校验）
  apple_email       ← Apple id_token 中已验证的 email

拒绝：manual（用户手填）、以及任何 verified = false 的记录
```

服务端**强制**走此白名单校验；配置项 `merge.verification = "none"` 在 `mode=auto` 且 `on_login=claim_verified` 时**不生效**——安全红线优先于应用配置。

**Apple email 的特殊说明**：Apple 返回的 email 可能是 `xxxxx@privaterelay.appleid.com` 中继地址。它在**同一 App 内**对同一用户是稳定的，可以用于**本应用内的**归并判定；但它**不是用户的真实邮箱**，所以：

- ❌ 不能用它去匹配用户在其他地方填写的真实邮箱
- ❌ 不能用它做跨平台归并依据
- ✅ 仅限 `apple:app` / `apple:web` 场景内的身份归并

**为什么这条不能松**：如果允许用"用户手填未验证的手机号"做归并，攻击者只需在注册时填上别人的手机号，就能在下次登录时被自动归并进受害者的账号。

🔴 **红线 2 · 被合并账号必须收到通知**

`merge.notify_source_account` 强制为 `true`。source 账号被合并是**账号归属的重大变更**，属于用户知情权范围，也是合规审计的必查项。服务端在合并完成后必须通过业务方 Webhook 或用户中心推送通知。

🔴 **红线 3 · 跨渠道自动合并需额外评估**

上述红线适用于**同平台内跨接入场景**（如微信 `app` ↔ 微信 `mini_program`）。若是**跨平台**自动合并（如微信 ↔ 支付宝），因两边手机号可能属于不同实名主体，建议：

- 强制 `verification = "strict"`，或
- 直接不允许 `auto`，只允许 `confirm`

建议在配置层增加 `merge.allow_cross_platform_auto: false`（默认 `false`），需要时显式打开。

#### 7.5.4 配置校验规则

服务端在保存 `applications.policy` 时必须做一致性校验。**区分 REJECT（拒绝保存）与 WARN（保存但提示）**，修正 P1-5：

| 校验项 | 处置 | 理由 |
| --- | --- | --- |
| `mode = confirm` + `verification = none` | 🔴 **REJECT** | confirm 模式的全部意义就是验证；`none` 使其退化为 `auto` 却少了安全红线。v0.7 已列出 `none` 为合法取值，现从枚举中移除 |
| `mode ≠ auto` + `on_login = claim_verified` | 🔴 **REJECT** | 只有 `auto` 允许写入式归并；`confirm`/`manual` 只能 `off` 或 `detect_only` |
| `notify_source_account = false` | 🔴 **REJECT** | R4 红线 2，不可关闭 |
| `mode = auto` + 跨平台 + `allow_cross_platform_auto = false` | 🔴 **REJECT** | R4 红线 3。v0.7 写"降级为 confirm 并告警"属于**静默改变用户配置**，应改为直接拒绝并让用户显式选择 |
| `mode = auto` + `on_login = claim_verified`，但该应用**未启用任何可产出 claim 的渠道** | 🔴 **REJECT**（修正 P1-5：v0.7 为 WARN） | 此时 `auto` 会**静默退化为"不归并"**，用户以为开了自动合并却实际没有——这种"配置生效但行为不符"的静默失败必须拒绝 |
| `mode = manual` + `verification` / `on_login` 非默认值 | 🟡 **WARN** | `manual` 下这两项不生效，提示用户配置无效即可 |
| `mode = auto` + `on_login = detect_only` | 🟡 **WARN** | 合法但语义矛盾（`auto` 下通常期望直接归并），提示确认 |

**原则**：凡是"配置保存成功但运行行为与配置语义不符"的情况，一律 REJECT 而非静默降级。**静默降级比报错更危险**——运维以为配置生效了，实际没有。

#### 7.5.5 推荐配置组合

| 应用类型 | `mode` | `verification` | `on_login` |
| --- | --- | --- | --- |
| 企业内部系统 / 管理后台 | `auto` | — | `claim_verified` |
| 面向 C 端的 App | `confirm` | `sms` | `off` |
| 强合规行业（金融、医疗） | `confirm` | `strict` | `off` |
| 低风险工具类应用 | `confirm` | `existing_binding` | `off` |

---

## 8. 令牌与会话

### 8.1 令牌形态

| 令牌 | 形态 | 有效期 | 校验方式 |
| --- | --- | --- | --- |
| `access_token` | JWT（ES256） | 15 分钟 | 本地验签，无网络开销 |
| `refresh_token` | 不透明随机串（32 字节） | 30 天 | 查库比对哈希 |
| `id_token` | JWT（可选，OIDC 兼容） | 15 分钟 | 本地验签 |

`access_token` 载荷：

```json
{
  "iss": "https://auth.example.com",
  "sub": "u_01J8XK...",         // 业务方账号标识（约束 C4）
  "aud": "app_web_portal",      // 消费方 app_id
  "iat": 1760000000,
  "exp": 1760000900,
  "jti": "01J...",
  "scope": "openid profile",
  "amr": ["wechat:official_account"]  // 认证方式，业务方可用于风控
}
```

**`sub` 的取值（约束 C4 的直接影响）**

`remote` 模式下本服务不持有账号，因此 `sub` **直接使用业务方账号标识（`external_user_id`）**。理由是业务方本来就知道自己的 userId，这是它能直接使用的标识；若本服务再生成一层别名，业务方还得反查一次映射，纯属多余。

由此带来一个必须转嫁给用户中心的要求：**账号对外标识不能是连续自增整数**。如果用户中心目前用自增 ID，请在其建设时改为 ULID / UUID / 带前缀的不可枚举 ID。原因：

- 虽然 C1 已按应用隔离，跨应用枚举风险被削弱
- 但同一应用内若 `user_id` 可枚举，攻击者可批量探测用户存在性（配合注册接口做用户画像）
- 这是**在用户中心设计阶段就要定的事**，事后迁移成本极高

**关于 `scope`**：`need_register` 与 `session_only` 分支下签发的令牌 `scope` 为 `identity_only`，业务方据此判断"此人身份可信但尚未注册"，只允许走注册引导流程，不允许访问业务数据。

### 8.2 refresh_token 轮转

```
POST /token (grant_type=refresh_token, refresh_token=RT1)
  → 校验 RT1 存在、未过期、未撤销
  → 签发 RT2，记录 RT2.rotated_from = RT1.id，并置 RT1.revoked = true
  → 返回新 access_token + RT2

若 RT1 已被使用过（检测到重放）：
  → 沿 rotated_from 链条向上追溯，撤销该链条上所有令牌
  → 记录安全事件，要求重新登录
```

> **字段说明（修正 A7）**：轮转关系用**单向链 `rotated_from`** 表达——新令牌指向旧令牌。v0.7 曾写作 `RT1.rotated_to = RT2.id`，与 DDL 不一致；单向链的好处是无需回写旧记录（旧记录只需置 `revoked`），减少写放大。重放检测时沿链回溯即可定位整个会话链。

这是 RFC 6819 推荐的 Refresh Token Rotation + Reuse Detection，能有效发现令牌被窃取的情况。

### 8.3 签名密钥与 JWKS（修正 P0-2）

`access_token` / `id_token` 是 ES256 签名 JWT，业务方需要公钥才能本地验签。v0.7 缺少暴露公钥的端点，导致"本地验签"无法实现。

| 项目 | 设计 |
| --- | --- |
| 密钥存储 | 私钥由 KMS / 配置中心托管，**不入库、不进代码仓库**；与 §D6 的信封加密体系复用同一套 KMS 接入 |
| 签名算法 | ES256（P-256），每把密钥有唯一 `kid` |
| 暴露端点 | `GET /v1/jwks` 返回 JWKS（仅公钥），`GET /.well-known/openid-configuration` 指向它 |
| 缓存头 | `Cache-Control: public, max-age=3600`，便于业务方与 CDN 缓存 |
| **密钥轮换** | ① 生成新密钥并开始用它签名；② JWKS **同时发布新旧两把公钥**；③ 等待旧 token 全部过期（> `access_token` TTL）；④ 从 JWKS 移除旧密钥。**顺序不可颠倒，否则旧 token 验签失败** |
| 轮换周期 | 建议 90 天；密钥泄漏时走紧急轮换流程（立即切换 + 保留旧公钥至过期 + 撤销受影响 token） |
| 多实例一致性 | 密钥从 KMS 统一获取，各实例无本地状态；JWKS 响应可加 `ETag` 减少流量 |

**业务方的验签契约**：业务方应实现"`kid` 未命中时强制刷新一次 JWKS 再重试"，与本服务校验 Apple JWKS 的做法一致（§4.4 ②）。

### 8.4 令牌撤销与生效延迟（修正 P0-5）

`access_token` 本地验签、有效期 15 分钟，因此**撤销后存在最长 15 分钟的生效窗口**。v0.7 只提到撤销 `refresh_tokens`，未处理已签发的 `access_token`。

**分层撤销策略**：

| 场景 | 处理 | 生效延迟 |
| --- | --- | --- |
| 普通登出 | 撤销该设备的 `refresh_token`；`access_token` 自然过期 | ≤ 15 min |
| **高危撤销**：账号劫持、账号注销、管理员强制下线、合并后清理 source | 撤销 `refresh_token` + **写入 jti 黑名单** `oauth:revoked_jti:{jti}`（TTL = 该 token 剩余有效期） | ≤ 一次 `introspect` 调用 |
| 密钥泄漏 | 见 §8.3 紧急轮换 | 立即（旧密钥下线后全部失效） |

**黑名单的校验方式**：默认 `/v1/introspect` **纯本地验签**（不查黑名单）；仅当调用方传 `check_revocation=true` 时才查 jti 黑名单。这样：

- 绝大多数业务请求（业务方自行验签）不受影响，保持"无网络开销"
- **安全敏感操作**（改密、提现、绑定新渠道等）调用方应开启 `check_revocation=true`
- 黑名单只存高危撤销，量级可控

**在文档与 SDK 中必须明确写出**："撤销不是立即全局生效，最坏情况 15 分钟"。这是设计权衡，不是 bug——需要立即生效的场景请使用 `check_revocation=true`。

### 8.5 手机号凭证的权威源与同步（修正 P0-6）

手机号同时存在于两个地方，v0.7 未定义谁是权威、如何同步：

| 存储位置 | 角色 |
| --- | --- |
| 用户中心（C4 下的账号主数据） | **权威源**——账号当前的手机号以此为准 |
| 本服务 `identity_claims` | **归并判定与授权凭证记录**——只记录"**某次授权中，某平台证明过这个身份拥有该手机号**"，不声称是账号当前手机号 |

**问题**：业务方在用户中心改了手机号后，本服务 claim 不会自动更新 → 基于 claim 的归并判定会用到**过期数据**。

**解决方案（组合采用）**：

1. **归并前回源核对**（强制）。凡是用手机号做归并判定（`on_login = claim_verified` 或合并前的凭证校验），必须先调 `AccountProvider.GetByClaim` 确认用户中心侧该手机号**当前**确实属于被归并的账号。核对不一致 → **拒绝归并**、记录 `identity.claim_mismatch` 事件并告警。
2. **用户中心变更时反向通知**（建议）。用户中心在手机号变更时推送 `claim.invalidated` 事件 → 本服务将该 `identity_claims` 记录置 `revoked_at = now()`。
3. **claim 不需要主数据的一致性**。因为有了第 1 条的强制回源核对，claim 即使滞后也不会造成错误归并——最坏情况是"该归并没发生"，而不是"归并错了账号"。**这个不对称性是刻意设计的：宁可漏归并，不可错归并。**

**与用户中心的对齐要求**（补充到 §13 并行事项）：`GetByClaim` 必须保证**强一致读**，不能用有延迟的从库——否则回源核对本身就可能读到过期数据，防线失效。

---

## 9. 多租户与配置管理

### 9.1 层级

```
Application（接入方应用）
  └── AppProviderConfig（渠道配置，按 platform + scene 维度）
        ├── 平台公开标识：wx_appid / alipay_app_id / apple_client_id
        ├── 加密凭据：appSecret / private_key.p8
        └── extra：平台私有参数（回调域名、支付授权开关等）
```

数据隔离优先级：`app_id` 是最小隔离单元（约束 C1）。以下表的**所有查询路径都必须带 `app_id`**（修正 A8：此前遗漏了 `identity_claims` 与 `merge_operations`，并残留了已删除的 `accounts`）：

| 表 | 隔离方式 |
| --- | --- |
| `app_provider_configs` | 直接持有 `app_id` |
| `oauth_identities` | 直接持有 `app_id` |
| `oauth_bindings` | 直接持有 `app_id` |
| `identity_claims` | 直接持有 `app_id` |
| `refresh_tokens` | 直接持有 `app_id` |
| `merge_operations` | 直接持有 `app_id` |
| `auth_audit_logs` | 直接持有 `app_id` |

隔离不能依赖调用方自觉，必须在持久层强制：建议提供 `MustAppScope(ctx) (AppID, error)` 守卫，Repository 的每个方法开头调用它，缺失 `app_id` 时直接 panic 或返回错误，让隔离漏洞在开发阶段就暴露，而不是等到线上串号。

### 9.2 配置变更流程

```
Admin API 更新配置
  → 加密凭据（KMS 信封加密）
  → version + 1，落库
  → Redis Pub/Sub 发布 config.changed:{appId}
  → 各实例收到通知，删除本地缓存
  → 下次请求时惰性重载并解密
```

所有实例保持一致，无重启、无滚动发布。

---

## 10. 安全设计

### 10.1 攻击面与对策

| 威胁 | 对策 |
| --- | --- |
| CSRF / 授权码注入 | 服务端 `state` 票据，一次性消费，绑定 redirectUri |
| 开放重定向 | `redirect_uri` 白名单校验（按 app 配置），仅允许精确匹配或已登记前缀 |
| 授权码截获 | code 一次性 + 60 秒超时 + PKCE（公开客户端强制） |
| 令牌重放 | access_token 短时效 + jti；refresh_token 轮转 + 重放检测 |
| 回调伪造 | Apple 走 JWKS 验签；支付宝 RSA2 验签 + 时间戳窗口 |
| 凭据泄漏 | 信封加密存储、内存中仅短暂持有、日志脱敏 |
| 用户枚举 | **`sub` 直接使用业务方 `external_user_id`，本服务不做别名**（修正 A1）——可枚举风险已转嫁给用户中心，要求其账号对外标识不可枚举（§8.1）。本服务侧：错误码不区分"用户不存在"与"凭据错误" |
| 归并误判 | 归并依据强制走 §7.5.3 凭证白名单；归并前回源 `GetByClaim` 核对（§8.5）；claim 命中多个账号时报错而非择一（§7.4 护栏） |
| 平台配额耗尽 | 按 provider 维度限流（§6.3），超限快速失败，**不做请求排队**，避免堆积拖垮服务 |
| 密钥泄漏 | JWKS 双密钥过渡 + 紧急轮换流程（§8.3）；撤销全部受影响令牌 |
| 撞库 / 暴力绑定 | 按 appId + IP + identity 限流；异常绑定模式触发风控事件 |
| 中间人 | 全链路 HTTPS，三方回调域名强制 HTTPS |

### 10.2 数据合规

- **PII 最小化**：`profile_snapshot` 只存必要字段，敏感字段（手机号、邮箱）单独列存 + 加密
- **账号注销**（约束 C4 下由用户中心发起，本服务提供内部接口配合）：级联解绑该 `external_user_id` 的全部 identity（同时调用 `Provider.Unbind` 撤销三方授权）、撤销全部 refresh_tokens、写入 jti 黑名单（§8.4）、删除 `identity_claims` 中该身份的可回显密文、匿名化审计日志中的 PII。**本服务不标记账号状态**——账号状态由用户中心持有
- **`Provider.Unbind` 不支持的降级（修正 P1-4）**：`Unbind` 是可选实现，渠道可返回 `ErrNotSupported`。此时**不能当作失败而中止注销**，处理方式为：本地正常解绑 + 记录 `unbind_manual_required` 标记 + 在注销结果的 `warnings` 中返回需要用户手动撤销的渠道清单（如"请到微信 → 设置 → 隐私 → 授权管理 中取消授权"）。审计日志保留该降级记录。**理由**：三方侧授权撤销是"尽力而为"，用户在本服务的注销权利不应因三方接口缺失而被阻塞
- **反向触发**：三方平台侧的授权撤销（Apple `consent-revoked` / `account-delete`）到达时，本服务标记 identity 失效并**通知用户中心**（通过 Webhook 或 SPI），由用户中心决定是否注销账号
- **数据留存**：审计日志保留期可配置（默认 180 天），到期归档
- **日志脱敏**：openid 全量哈希后入日志，昵称/头像不落日志

---

## 11. 可观测性

### 11.1 指标

| 指标 | 类型 | 用途 |
| --- | --- | --- |
| `auth_flow_total{app,platform,scene,result}` | Counter | 各渠道成功率 |
| `provider_request_duration_seconds{platform,scene,op}` | Histogram | 三方接口耗时（区分 exchange/userinfo） |
| `auth_flow_stage_duration{stage}` | Histogram | 定位是网络慢还是自己慢 |
| `binding_conflict_total{mode,resolution}` | Counter | 冲突频率与处理方式分布（`mode` 取自 `policy.merge.mode`） |
| `identity_duplicate_total` | Counter | 数据质量红灯 |
| `provider_error_total{platform,code}` | Counter | 三方平台故障感知 |
| `account_provider_request_duration_seconds{op}` | Histogram | **用户中心调用耗时**（`op` = get/get_by_claim/create/merge）。C4 下用户中心是本服务的关键依赖，必须单独观测 |
| `account_provider_error_total{op,reason}` | Counter | 用户中心故障感知；`merge` 的失败会直接阻断合并流程 |
| `merge_operation_total{status,mode}` | Counter | 合并成功率；`status=pending` 长期不降说明补偿任务异常 |
| `merge_compensation_lag_seconds` | Gauge | **补偿任务滞后时间**——超过阈值告警，这是 §7.3 孤儿风险的唯一监控手段 |
| `outbox_pending_total` / `outbox_dead_total` | Gauge / Counter | Webhook 投递积压与死信 |
| `claim_source_total{source,verified}` | Counter | 各来源凭证的产出量，用于判断 `auto` 模式的前提渠道是否真的可用 |
| `claim_mismatch_total` | Counter | **回源核对不一致次数**（§8.5），非零说明用户中心与本服务数据已漂移，需人工介入 |
| `rate_limit_exceeded_total{dimension}` | Counter | 限流触发分布，用于容量规划 |
| `token_revoked_total{reason}` | Counter | 撤销量与原因（`logout` / `hijack` / `merge` / `account_closed`） |
| `jwks_kid_miss_total` | Counter | 业务方验签时 `kid` 未命中次数，用于评估密钥轮换是否平滑 |
| `provider_failure_total{platform,scene,retryable}` | Counter | **按 `retryable` 维度切分失败**（§5.5）——`retryable=true` 占比高说明网络/平台问题，`false` 占比高说明配置或调用方式有问题 |
| `circuit_breaker_state{platform,instance}` | Gauge | 熔断器状态（0 closed / 1 half_open / 2 open）。**按实例打 label，可直接观测多副本状态分歧程度**（§5.6.7） |
| `circuit_breaker_rejected_total{platform}` | Counter | 被熔断快速拒绝的请求数。与 `provider_failure_total` 对比可估算熔断挽回的无效调用量 |
| `circuit_breaker_transition_total{platform,from,to}` | Counter | 状态迁移次数。**`open → half_open` 频繁抖动说明平台在"半死"状态**，需人工介入 |
| `provider_slow_total{platform,op}` | Counter | 耗时超过 `slow_threshold_ms` 但**成功**的请求（计入 `slow_ratio`，见 §5.6.4b） |
| `provider_outcome_total{platform,outcome}` | Counter | **按熔断分类维度统计**（`success` / `slow` / `timeout` / `conn_err` / `server_err` / `business_reject`）。**四类阈值中任一被触发时，可直接从本指标看出是哪一类的问题** |
| `circuit_breaker_trip_total{platform,reason}` | Counter | 熔断触发次数与**触发原因**（`failure_ratio` / `timeout_ratio` / `slow_ratio` / `consecutive_timeouts`）。用于校准阈值——若总是 `slow_ratio` 先触发，说明平台在变慢而非宕机 |
| `httpclient_timeout_total{platform,stage}` | Counter | 超时分布（连接 / 读写），用于校准超时配置 |
| `http_server_duration_seconds{route,status}` | Histogram | **入站请求耗时**（§5.7），用于定位"是我们的接口慢，还是下游慢" |
| `http_server_timeout_total{route}` | Counter | **入站请求被超时中间件终止的次数**。与 `http_server_duration_seconds` 对照可判断超时设置是否合理——若大量请求卡在超时线上，说明超时值过紧或下游确实慢 |

### 11.2 追踪

`trace_id` 从 `/authorize` 生成，写入 ticket，回调时取出继续使用，贯穿整个流程。这样一次登录的 12 个步骤在 Jaeger 里是一条完整的链路，而不是两段。

### 11.3 日志

结构化 JSON 日志，必带字段：`trace_id` `app_id` `platform` `scene` `external_user_id` `stage` `duration_ms` `error_code`。三方原始响应只在 DEBUG 级别记录且脱敏。

---

## 12. 部署与运维

- **无状态服务**：状态全在 Redis 和 DB，可水平扩容。授权上下文不依赖本地内存，任意实例都能处理回调
- **优雅停机**：收到 SIGTERM 后停止接收新请求，等待在途请求完成（授权流程 5 秒内完成）
- **健康检查**：`/healthz`（进程存活）+ `/readyz`（DB / Redis 可达）
- **配置降级**：Redis 不可用时授权入口直接快速失败（不能降级为无状态，否则失去防重放）；DB 不可用时只读接口仍可服务
- **用户中心降级（约束 C4）**：用户中心不可用时，**登录链路快速失败**（无法确认账号状态），但**已签发的 access_token 仍有效**（本地验签，15 分钟内自然过期）。`/v1/introspect` 若需查账号状态则需明确超时与熔断策略，建议设为纯本地验签以保持可用性
- **灰度**：渠道配置带 version，可按 appId 维度灰度启用新渠道
- **后台任务必须独立部署**：补偿任务（扫描 `merge_operations` 待处理）与 Outbox 投递 worker 建议独立进程/独立副本部署，避免与在线请求争抢资源；多副本时必须用分布式锁或 `SELECT ... FOR UPDATE SKIP LOCKED` 保证不重复处理
- **平台配额保护**：按 provider 维度限流（§6.3），微信等有日调用量上限的平台需设置预留水位（如用量达 80% 告警、95% 拒绝新请求），**不要让一个应用的行为影响其他应用**
- **超时与熔断是 C6 的配套前提（§5.5 / §5.6）**：本服务对三方渠道不重试，因此**超时配置与熔断器不是优化项而是必需项**——不重试 + 无超时会让连接与 goroutine 被耗尽；不重试 + 无熔断会让平台故障期间每个请求都白等满超时。上线前必须实测超时值并配置熔断阈值
- **熔断配置与配置中心**：`provider_guard` 是**服务级配置**（`configs/config.yaml`），变更需灰度与重启，**不走 §9.2 的应用级热更新**——因为它的变更会立即改变所有应用的调用行为。若后续要支持动态调整，需单独设计带审计的配置通道
- **多副本熔断状态分歧的观测**：`circuit_breaker_state{platform,instance}` 必须按实例打 label 上报，否则无法发现"部分副本熔断、部分未熔断"的分歧（§5.6.7）
- **上下文取消隔离**：`Exchange` / `Refresh` 等不可撤销调用使用 `context.WithoutCancel`（§5.5 ③），避免客户端断开导致授权码被消费但结果丢失
- **JWKS 与密钥轮换**：密钥从 KMS 统一获取，服务无本地密钥状态；轮换按 §8.3 的四步执行，建议做成管理台一键操作 + 轮换后的平滑性校验（观察 `jwks_kid_miss_total`）
- **补偿任务滞后监控**：`merge_compensation_lag_seconds` 是唯一的孤儿风险探针，必须配告警
- **管理端网络隔离（§15.2）**：`/admin/v1/*` **不暴露公网**，需置于内网 / VPN / IP 白名单之后。推荐做法是同进程部署、由网关按路径分流——`/v1/*` 走公网入口，`/admin/v1/*` 走内网入口，避免维护两套服务。管理端失败的鉴权尝试要单独告警（暴力猜管理员令牌）

---

## 13. 分期落地路线

### 第一期 · 骨架与最小闭环（打地基）

- Domain 模型 + 五张核心表（`oauth_identities` / `oauth_bindings` / `identity_claims` / `refresh_tokens` / `event_outbox`）
- **`IdentitySource` 抽象层 + `Provider` SPI + Registry**（D8 留口现在就做，成本约 1 小时；`domain/identitysource/` 目录 + 编排层依赖它）
- **`AccountProvider` 接口 + `StubAccountProvider` 实现**（约束 C4：用户中心尚未就位，先用桩实现打通链路，接口不将就）
- 通用 OAuth2 适配器（用它验证抽象是否合理）
- 统一授权流程：`/authorize` → `/callback` → `/token`，**含 `NEED_REGISTER` 分支**
- Ticket 票据 + `bind_ticket` 机制 + JWT 签发
- **`GET /v1/jwks` + 密钥管理骨架**（修正 P0-2：第一期就签发 JWT，业务方必须能验签，不能拖到第四期）
- **凭据加密：本地主密钥 + AES-GCM**（修正 P2-4：第一期就要存渠道配置，先不做 KMS 但**绝不能明文入库**，避免测试凭据被复制到生产）
- `event_outbox` 表 + 投递 worker 骨架
- **管理端（§15）**：A 组（应用与策略，含 `policy:validate` dry-run）+ B 组（渠道配置，**含 `secret:verify` 连通性校验**）+ I 组的 `/providers` 与 `/health`；`admin_grants` / `admin_audit_logs` 建表并接入管理员鉴权中间件
- **验收标准**：接入一个自建 OAuth2 测试服务，走通"授权 → 回调 → 返回 NEED_REGISTER → 模拟业务方登录 → 绑定 → 签发令牌"完整链路；业务方能从 `/v1/jwks` 取公钥并成功验签；能通过管理端创建应用、配置渠道并点 `verify` 校验连通性

### 第二期 · 真实渠道

- 微信四接入场景（`app` / `mini_program` / `official_account` / `pc_qr`）—— `app` 场景同时服务 iOS 与 Android；C3 下这四个场景**不自动共享身份**
- 支付宝三接入场景
- **Apple（约束 C2，必做）** —— client_secret JWT 自动签发与续期、JWKS 验签与轮换应对、nonce 防重放、首次授权才有的 name/email 落库、`/v1/oauth/notify/{platform}` 处理 `consent-revoked` / `account-delete`
- **小程序 `session_key` 生命周期管理**（修正 P1-2：这是 `getPhoneNumber` 解密的前提，直接决定 R4 红线 1 能否成立）
- 各渠道的 capability 差异处理
- **超时分层 + 渠道熔断（约束 C6 的配套前提，§5.5 / §5.6 / §5.7）** —— `HealthChecker` 实现（仅管理台展示）+ **`sony/gobreaker/v2` 熔断器（按 `platform` 粒度，服务级配置）** + **四类独立阈值的分类滑动窗口**（§5.6.4b/4c）+ `context.WithoutCancel` 的取消隔离 + **入站三段超时中间件**（§5.7）。**这一项从原第四期提前到第二期**：C6 决定不重试后，超时与熔断成为正确性的组成部分，不再是"生产化优化项"。**实现时必须写死两条**：只有 `retryable` 错误计入熔断（§5.6.4）；慢请求率只统计成功的慢请求（§5.6.4b）
- **管理端（§15）**：G 组（事件与死信重投）+ H 组（审计查询与异步导出）。渠道一接入，排查就只能靠管理端，这两个必须同期交付
- **验收标准**：同一业务应用下的 iOS、Android、小程序均可完成微信登录；其中 iOS 与 Android 因共用 `wechat:app` 场景而归为同一账号；小程序能成功解密并写入 `source = wechat_phone` 的 claim

### 第三期 · 账号绑定与合并（约束 C5 + 需求 R1/R2 的核心交付）

- **引导绑定三件套**：`GET /v1/bindings`、`POST /v1/bind`、`POST /v1/bind/resolve`（冲突处置）
- **合并行为配置化（需求 R2）**：`applications.policy.merge` 配置模型 + 三种 mode + `on_login` 三档（`off` / `detect_only` / `claim_verified`）+ **配置一致性校验器**（§7.5.4，含 REJECT/WARN 区分）
- **R4 安全红线实现**：`auto` 模式的凭证来源白名单校验、被合并账号通知、跨平台自动合并默认关闭
- **三次独立事务的合并链路**（修正 P0-3）：`merge_operations` 先独立提交 → 调远端（带幂等键）→ 本地收敛 → Outbox 发事件
- **补偿任务**：扫描 `pending` / `failed`，按 `idempotency_key` 重试；**滞后时间必须配告警**
- **合并前回源核对**（修正 P0-6）：调 `GetByClaim` 确认用户中心当前手机号归属，不一致则拒绝归并并告警
- **验证手段**：短信验证码、对端已绑定渠道、待合并账号手机号/邮箱验证
- **`HTTPAccountProvider` 接入真实用户中心**（替换第一期的 Stub）
- **管理端（§15）**：C 组（身份与绑定查询、强制解绑、`transfer` 旁路）+ D 组（合并运维，含 `retry` / `resolve` / `impact`）+ J 组（claim 一致性与 mismatch 排查）。**与合并功能同批交付**——合并是高风险操作，没有管理端兜底就不能上线
- Admin 管理台前端（接上述接口）
- **验收标准（对应 R1~R4）**：
  - R1：用户先在小程序登录得账号 B，后在 App 登录得账号 C，在 C 中绑定"微信小程序"，合并后该用户在此业务应用内**只有一个账号**
  - R2：同一套代码在 `mode=confirm` 下要求验证后才合并，`mode=auto` 下直接合并，`mode=manual` 下返回 `BIND.IDENTITY_TAKEN`；非法组合（`confirm` + `claim_verified`、`confirm` + `verification=none`）被校验器**拒绝**
  - R3：跨业务应用的合并请求被明确拒绝
  - R4：用未验证的手填手机号无法触发 `auto` 归并；合并完成后 source 账号收到通知
  - **P0-3 专项：模拟"远端 Merge 成功但本地事务提交失败"，验证补偿任务能在 5 分钟内自愈，不产生孤儿**

### 第四期 · 生产化

- KMS 信封加密升级（替换第一期的本地主密钥）+ 配置热更新
- 限流（含 provider 维度配额）、风控、可观测性全量接入
- Webhook 事件体系（签名 / 重试 / 去重 / 死信）
- 账号注销与数据合规（含 `Unbind` 不支持的降级提示）
- jti 撤销黑名单（修正 P0-5）
- 密钥轮换流程与演练（§8.3 四步）
- **管理端（§15）**：E 组（会话查询与强制下线）+ F 组（签名密钥轮换，把 §8.3 的四步变成 `rotate` / `retire` 两个按钮）+ K 组（管理员授权）+ 审计导出 + 双人复核流程
- 压测与故障演练
- **与用户中心联调压测**：用户中心不可用时的降级行为验证（登录链路快速失败、已签发 access_token 仍有效）

### 并行事项 · 用户中心的建设要求

用户中心是独立服务，但它必须满足本服务的几个硬性约定，建议尽早对齐：

| 约定 | 原因 |
| --- | --- |
| 账号对外标识不可枚举（ULID / UUID） | 见 §8.1，事后迁移成本极高 |
| `Merge` 必须**接收幂等键且真正幂等** | 见 §D3 / §7.3。若不实现，补偿策略必须降级为"只告警不重试" |
| `GetByClaim` 必须**强一致读**（不能用延迟从库） | 见 §8.5，它是归并前的最后一道防线 |
| 提供 `Create`（或明确不提供） | 决定首次三方登录能否走 `auto_create` |
| 订阅 `account.merged` 事件并处理数据迁移 | C4 模式下的核心耦合点 |
| 手机号变更时推送 `claim.invalidated` | 见 §8.5 第 2 条，用于让本服务及时失效过期 claim |
| 内部服务鉴权（mTLS 或签名） | `Merge` 是高危接口 |

---

## 14. 风险与待确认项

| # | 事项 | 状态 | 结论 / 影响 |
| --- | --- | --- | --- |
| 1 | 账号主体：自建 `accounts` 表，还是复用用户中心 | ✅ 已确认 | **`remote` 模式**（约束 C4）：本服务不建账号表，只做身份与绑定的搬运工；用户中心若当前不存在则后续单独建设。落地见 D3、§6.2、§8.1 |
| 2 | 是否需要跨应用 SSO | ✅ 已确认 | **不做**，账号空间按应用隔离（约束 C1）。已落地到 `oauth_identities.app_id`、`oauth_bindings.app_id` 与 D2 的归并范围 |
| 3 | unionid 获取条件是否满足 | ✅ 已确认 | **不可用（C3）**。归并键退化为 `open_id`；跨接入场景不自动归并 |
| 4 | Apple 登录是否必须 | ✅ 已确认 | **必须**（有 iOS 应用）。已列入第二期必做，专项说明见 §4.4 |
| 5 | **跨接入场景**归并策略（修正 A15：原表述为"多端"，术语未随 v0.5 更新） | ✅ 已确认 | **独立账号 + 引导绑定**（约束 C5，即 S1）。**合并能力仍需完整实现**，落地见 §7.2 / §7.3 / §7.4 |
| 6 | 三方平台侧回调域名备案与配置 | ⏳ 待确认 | 上线阻塞项。Apple 还需额外申请 Service ID 与 "Sign in with Apple" Key（.p8）。**建议尽早启动，周期长** |
| 7 | 并发量级与三方接口限流 | ⏳ 待确认 | 微信有日调用量限制，需评估是否要请求排队与本地缓存 |
| 8 | 用户中心账号对外标识是否可枚举 | ⏳ **需与用户中心对齐** | 见 §8.1。若为自增 ID，建议在用户中心建设阶段就改为 ULID/UUID，事后迁移成本极高 |
| 9 | 同一业务应用内、跨接入场景是否支持账号合并 | ✅ 已确认 | **支持**（需求 R1），且**触发方式可按应用配置**（R2：`auto` / `confirm` / `manual`）。落地见 §1.4、§7.2、§7.3、§7.5 |
| 10 | `auto` 模式的安全边界 | ✅ 已确认 | **R4 红线不可配置关闭**：归并依据必须是平台侧已验证凭证；被合并账号必须通知。见 §7.5.3 |
| 11 | 手机号凭证的权威源 | ✅ 已定（v0.8） | **用户中心为权威源**，本服务 `identity_claims` 仅记录授权凭证；归并前强制回源核对，不一致则拒绝归并。见 §8.5 |
| 12 | 令牌撤销的生效延迟 | ✅ 已定（v0.8） | 普通登出 ≤15 min（自然过期）；**高危撤销走 jti 黑名单**，敏感操作需 `check_revocation=true`。见 §8.4 |
| 13 | 是否现在就做 `IdentitySource` 抽象 | ✅ 已定（v0.8） | **是**（D8）。现在约 1 小时，接入企业 SSO 时再改需数天且有回归风险 |
| 14 | 对三方渠道的调用是否重试 | ✅ 已确认（v0.10） | **不重试**（约束 C6）。重试责任归接入方，且接入方的重试单位是**重新发起授权流程**而非重放回调。配套要求见 §5.5 |

### 14.1 已确认决策汇总（blocking 项全部关闭）

原待确认项 1 已被约束 C4 关闭，方案对比留档如下：

| 对比维度 | ~~模式 A：`local`（自建账号）~~ | ✅ **模式 B：`remote`（复用用户中心）** |
| --- | --- | --- |
| 本服务存什么 | `accounts` 表 | 只存 `identity` + `binding` + `identity_claims`，binding 持有 `external_user_id` |
| 首次三方登录 | 自动建账号并绑定 | 默认返回 `NEED_REGISTER`（可配 `auto_create` / `session_only`） |
| 业务方要做什么 | 拿 `account_id` 建自己的用户记录 | 实现 `AccountProvider` SPI：`Get` / `GetByClaim` / `Create` / `Merge` |
| 主要代价 | 业务方需接受外来 ID 作主键 | 首次登录链路变长；用户中心故障会阻塞登录链路 |

**第一期不再被阻塞**：`AccountProvider` 接口先落地，实现用 `StubAccountProvider`，用户中心就位后替换为 `HTTPAccountProvider`，业务逻辑零改动。

**仍需你推进的外部事项**：第 6 项（回调域名备案、Apple Service ID 与 Key 申请）周期最长，建议与第一期开发并行启动。

### 14.2 审查修复记录（v0.8）

本版本依据 `docs/design-review.md` 完成修复，明细如下：

| 类别 | 编号 | 内容 | 状态 |
| --- | --- | --- | --- |
| 文档冲突 | A1～A16 | §1 修正清单（16 处） | ✅ 全部修正 |
| P0 缺陷 | P0-1 | `identity_claims` 改**部分唯一索引**（仅约束已验证且未撤销的凭证） | ✅ §6.2 |
| P0 缺陷 | P0-2 | 新增 `GET /v1/jwks` + `/.well-known/openid-configuration` + 密钥轮换四步 | ✅ §5.3 / §8.3 |
| P0 缺陷 | P0-3 | 合并改为**三次独立事务**，网络调用不持有数据库事务；事件走 Outbox | ✅ §7.3 / §6.2 |
| P0 缺陷 | P0-4 | `AccountProvider.Merge` 增加 `IdempotencyKey` | ✅ D3 |
| P0 缺陷 | P0-5 | 高危撤销引入 jti 黑名单；`introspect` 增加 `check_revocation` | ✅ §8.4 / §6.3 |
| P0 缺陷 | P0-6 | 手机号权威源定义为用户中心 + 归并前强制回源核对 | ✅ §8.5 |
| P1 问题 | P1-1～P1-8 | `GetByClaim` 职责划分、`session_key` 生命周期、Apple nonce 存储、`Unbind` 降级、配置校验改 REJECT、`detect_only` 档位、Webhook 契约、限流维度 | ✅ 已修正 |
| P2 问题 | P2-1～P2-4 | 通用 notify 端点、`transfer` 端点、`HealthChecker`、第一期凭据加密 | ✅ 已修正 |
| 扩展留口 | E1 | `app_provider_configs` 预留 `config_key` | ✅ §6.2 / D8 |
| 扩展留口 | E3 | `Provider` 上提为 `IdentitySource` | ✅ D8 / §3.1 |
| 扩展留口 | E10 | `Metadata.APIVersion` | ✅ §4.1 / D8 |
| 扩展留口 | E4/E5/E6/E8 | Scene 治理、`env` 隔离、凭据轮换过渡期、事件版本化 | ✅ 已落地 |
| 扩展留口 | E7/E9 | provider 维度配额（✅ §6.3）、`ClaimValidator` SPI（📋 记录待实现，见 §7.4） | 部分 |

**遗留待实现**（不阻塞编码，但需在对应阶段处理）：

- **E9 · `ClaimValidator` SPI**：当前 claim 校验逻辑写死在核心流程里，新增凭证类型（企业工号、设备指纹）需改核心代码。建议在第三期与其他 claim 逻辑一起抽出接口
- **E2 · OIDC 完整兼容**：v0.8 只提供了 `/v1/jwks` 与 discovery 骨架，未实现标准 OIDC 的 `/userinfo` 语义对齐与 `id_token` 完整规范。若未来要作为标准 OIDC Provider，需专项设计

---

## 15. 管理端接口设计（Admin API）

> **本节的由来（v0.9）**：v0.8 及之前，全文有 12 处提及"管理台 / 管理员"，但只定义了 2 个具体接口（`/admin/v1/apps/{id}/policy`、`/admin/v1/bindings/{id}/transfer`），其余全是"只有动作描述、没有接口定义"的悬空需求。本节把这些散落的运维诉求收敛成一套完整的管理端 API。

### 15.1 悬空需求清点（本节要覆盖的目标）

先把散落在各章节的运维诉求列出来，作为管理端接口的需求来源：

| # | 出处 | 诉求 | 对应接口 |
| --- | --- | --- | --- |
| 1 | §6.2 / §附录A | 新增渠道时配置 `client_key` / `client_secret`、编排参数 | B 组 · 渠道配置 |
| 2 | §术语定义 / E4 | `scene` 白名单校验（防止拼写错误入库） | B 组 · 配置校验 |
| 3 | §8.3 / §12 | **密钥轮换一键操作** + 轮换平滑性校验 | F 组 · 密钥管理 |
| 4 | §7.3 | 补偿任务失败时**人工核对后手动推进** | D 组 · 合并运维 |
| 5 | §8.4 | **管理员强制下线**（高危撤销，写 jti 黑名单） | E 组 · 会话令牌 |
| 6 | §5.4 / §6.2 | Outbox **死信重投** | G 组 · 事件死信 |
| 7 | §11.1 | `claim_mismatch_total` 非零时**人工介入** | J 组 · claim 一致性 |
| 8 | §7.2 | `transfer` 旁路（已定义） | C 组 · 身份绑定 |
| 9 | §7.5 | 合并模式配置（已定义） | A 组 · 策略配置 |
| 10 | §10.2 | 账号注销运维配合 | C + D 组 |
| 11 | §11 | 审计日志查询与导出 | H 组 · 审计 |
| 12 | §4.1 / P2-3 | 渠道健康状态查看 | I 组 · 观测 |

### 15.2 与业务端 API 的隔离（必须严格区分）

管理端**不是**业务端的超集，两者在鉴权、网络、审计上完全独立：

| 维度 | 业务端 `/v1/*` | 管理端 `/admin/v1/*` |
| --- | --- | --- |
| 调用方 | 接入的业务系统 | 运维 / 客服 / 管理员 |
| 鉴权 | `appId` + `appSecret`，或 OAuth2 令牌 | **管理员 Bearer Token + RBAC**，与业务凭据完全分离 |
| 数据范围 | **仅自己的 `app_id`**（C1 隔离） | 全部应用（受 RBAC 授权范围约束） |
| 网络暴露 | 公网 | **内网 / VPN / IP 白名单**，不暴露公网 |
| 限流 | 按 appId / IP / identity | 按管理员账号，更严格；高危操作单独限流 |
| 审计 | `auth_audit_logs` | **独立的 `admin_audit_logs`**，保留期更长（默认 3 年） |
| 错误信息 | 脱敏，不泄漏内部细节 | 可详细（便于运维定位） |
| 破坏性操作 | 无 | 有（transfer / revoke / 下线密钥），需二次确认 |

**关键约束**：管理端**不重复实现业务逻辑**，只调用应用层已有的用例（`application/` 层），确保"管理台做一次"与"业务方调用一次"的效果与副作用完全一致（尤其是合并、撤销这类有事件外发的操作）。

### 15.3 管理员身份与权限模型

约束 C4 下账号主数据在用户中心，因此**管理员身份也复用用户中心的账号**，本服务只维护"谁拥有什么角色"的授权关系：

```sql
-- 管理员授权（身份来自用户中心，本服务只存映射）
CREATE TABLE admin_grants (
    id           BIGSERIAL PRIMARY KEY,
    subject_id   VARCHAR(128) NOT NULL,        -- 用户中心的管理员账号 ID
    role         VARCHAR(64)  NOT NULL,        -- 角色码
    scope_app_id BIGINT,                       -- 授权范围：NULL = 全部应用
    granted_by   VARCHAR(128) NOT NULL,
    granted_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,                  -- 支持临时授权
    revoked_at   TIMESTAMPTZ,
    UNIQUE (subject_id, role, scope_app_id)
);

-- 管理端审计（与业务审计分离）
CREATE TABLE admin_audit_logs (
    id           BIGSERIAL PRIMARY KEY,
    subject_id   VARCHAR(128) NOT NULL,
    action       VARCHAR(64)  NOT NULL,   -- app.update | config.rotate | binding.transfer | token.revoke
    target_type  VARCHAR(32)  NOT NULL,
    target_id    VARCHAR(128) NOT NULL,
    app_id       BIGINT,
    reason       TEXT         NOT NULL,   -- 高危操作必填
    before_state JSONB,                   -- 变更前快照
    after_state  JSONB,                   -- 变更后快照
    client_ip    INET,
    trace_id     VARCHAR(64),
    result       VARCHAR(16)  NOT NULL,
    error_code   VARCHAR(64),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_admin_audit_subject ON admin_audit_logs (subject_id, created_at DESC);
CREATE INDEX idx_admin_audit_target  ON admin_audit_logs (target_type, target_id, created_at DESC);
```

**角色与权限**：采用 `resource:action` 粒度，角色是权限的集合。

| 角色 | 权限 | 适用 |
| --- | --- | --- |
| `viewer` | `*:read` | 值班查看、客诉排查 |
| `operator` | `viewer` + `binding:*` `token:revoke` `merge:retry` | 一线运维 |
| `config_admin` | `viewer` + `app:*` `config:*` `key:*` `event:*` | 配置与密钥管理 |
| `super_admin` | 全部 + `admin:grant` | 管理员授权 |

### 15.4 接口清单

#### A 组 · 应用与策略

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/apps` | 应用列表（分页、按名/状态筛选） | `app:read` |
| POST | `/admin/v1/apps` | 创建应用，返回 `app_code` 与一次性展示的 `app_secret` | `app:write` |
| GET | `/admin/v1/apps/{id}` | 应用详情 | `app:read` |
| PATCH | `/admin/v1/apps/{id}` | 改名称、启停状态 | `app:write` |
| POST | `/admin/v1/apps/{id}/secret:rotate` | 轮换应用级密钥（`secret_hash` 双活过渡） | `app:write` |
| GET | `/admin/v1/apps/{id}/policy` | 读取 `policy`（含 `merge` 配置） | `app:read` |
| PUT | `/admin/v1/apps/{id}/policy` | 保存 `policy`，**执行 §7.5.4 一致性校验，非法组合 REJECT 并返回具体原因** | `app:write` |
| POST | `/admin/v1/apps/{id}/policy:validate` | **dry-run 校验**：只校验不落库，供前端实时提示 | `app:read` |

#### B 组 · 渠道配置

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/apps/{appId}/provider-configs` | 列出该应用的渠道配置（凭据只返回掩码） | `config:read` |
| POST | `/admin/v1/apps/{appId}/provider-configs` | 新增渠道配置。**`platform` / `scene` 走权威枚举白名单校验（E4）**；凭据加密入库 | `config:write` |
| GET | `/admin/v1/apps/{appId}/provider-configs/{id}` | 详情 | `config:read` |
| PATCH | `/admin/v1/apps/{appId}/provider-configs/{id}` | 改 `extra` / `env` / 绑定关系等非凭据字段 | `config:write` |
| POST | `.../{id}/secret:rotate` | **凭据轮换**：写入 `secret_cipher_prev` 与新值，进入过渡期（E6） | `config:write` |
| POST | `.../{id}/secret:finalize` | 结束过渡期，清空 `prev` | `config:write` |
| POST | `.../{id}/verify` | **连通性校验**：用该凭据真实调一次平台接口（如拉 access_token），返回结果 | `config:write` |
| POST | `.../{id}/enable` `.../disable` | 启停渠道 | `config:write` |
| DELETE | `.../{id}` | 软删 | `config:write` |

> `verify` 是本组最有价值也最容易漏的接口 —— 配置错一个字符，只有等用户在线上登录失败才会暴露。

#### C 组 · 身份与绑定

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/identities` | 按 `app_id` / `platform` / `open_id` / `identity_key` / `external_user_id` 多维查询 | `identity:read` |
| GET | `/admin/v1/identities/{id}` | 详情：`profile_snapshot`、全部 claims、绑定历史 | `identity:read` |
| GET | `/admin/v1/bindings` | 按 `app_id` / `external_user_id` / `status` 查询 | `binding:read` |
| GET | `/admin/v1/accounts/{externalUserId}/bindings` | 某账号的全部绑定（含已解绑历史） | `binding:read` |
| DELETE | `/admin/v1/bindings/{id}` | **强制解绑**（如客服处理用户申诉），写审计并通知业务方 | `binding:write` |
| POST | `/admin/v1/bindings/{id}/transfer` | **`transfer` 旁路**（§7.2）：把 identity 从旧账号转到新账号，旧账号保留。**高危，需 `reason`** | `binding:transfer` |

#### D 组 · 账号合并运维

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/merge-operations` | 按 `status`（`pending` / `failed` / `done`）与 `app_id` 查询 | `merge:read` |
| GET | `/admin/v1/merge-operations/{id}` | 详情：幂等键、`remote_result`、`attempts`、失败原因 | `merge:read` |
| POST | `/admin/v1/merge-operations/{id}:retry` | **人工重试**（§7.3 补偿任务未自动处理的场景）。复用同一 `IdempotencyKey` | `merge:retry` |
| POST | `/admin/v1/merge-operations/{id}:resolve` | 标记"人工已核对处理"，停止补偿重试 | `merge:retry` |
| GET | `/admin/v1/merge-operations/{id}/impact` | **影响面预估**：将改绑多少 identity、撤销多少令牌（供二次确认） | `merge:read` |

> `retry` 必须复用原 `IdempotencyKey` —— 否则用户中心会当成一次新合并，可能造成重复执行。

#### E 组 · 会话与令牌

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/tokens` | 按 `external_user_id` 查活跃会话（设备、签发时间、到期时间） | `token:read` |
| POST | `/admin/v1/tokens:revoke` | **管理员强制下线**（§8.4 高危撤销）：撤销全部 refresh_token + 写入 jti 黑名单 | `token:revoke` |
| GET | `/admin/v1/revoked-jti` | 查询当前黑名单（排查"用户被登出"类客诉） | `token:read` |

#### F 组 · 签名密钥管理

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/signing-keys` | 密钥列表：`kid`、算法、状态（`signing` / `published` / `retired`）、创建时间 | `key:read` |
| POST | `/admin/v1/signing-keys:rotate` | **一键轮换第 1·2 步**：生成新密钥并开始签名，同时把旧密钥保留在 JWKS | `key:write` |
| POST | `/admin/v1/signing-keys/{kid}:retire` | **轮换第 3·4 步**：下线旧密钥。**前置校验：不得存在用该 `kid` 签发且未过期的 token**，否则拒绝 | `key:write` |
| GET | `/admin/v1/signing-keys/jwks:preview` | 预览当前 `/v1/jwks` 会返回的内容（轮换后核对） | `key:read` |

> 这把 §8.3 的"四步轮换"变成了两个按钮：`rotate` 和 `retire`。**`retire` 的前置校验是防止轮换事故的关键**——提前下线旧密钥会让所有旧 token 验签失败。

#### G 组 · 事件与死信

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/events/outbox` | 按 `status`（`pending` / `sent` / `dead`）、`event_type`、时间范围查询 | `event:read` |
| GET | `/admin/v1/events/outbox/{id}` | 详情：`payload`、`attempts`、`last_error` | `event:read` |
| POST | `/admin/v1/events/outbox/{id}:retry` | **重投死信**，重置 `attempts` | `event:write` |
| POST | `/admin/v1/events/outbox/{id}:discard` | 丢弃（需 `reason`，记审计） | `event:write` |

> 死信重投必须**保持原 `event_id`** —— 业务方按 `event_id` 去重（§5.4），生成新 ID 会导致重复处理。

#### H 组 · 审计日志

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/audit-logs` | 业务审计：按 `app_id` / `action` / `result` / `external_user_id` / `trace_id` / 时间范围筛选 | `audit:read` |
| GET | `/admin/v1/audit-logs/admin` | 管理端审计：按 `subject_id` / `action` / `target_id` 筛选 | `audit:read` |
| POST | `/admin/v1/audit-logs:export` | **异步导出**（大数据量），返回 `task_id` | `audit:read` |
| GET | `/admin/v1/audit-logs/export/{taskId}` | 查询导出任务状态并取下载链接 | `audit:read` |

#### I 组 · 观测与健康

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/providers` | 已注册渠道清单：`platform:scene`、`capabilities`、`api_version`、启用状态 | `config:read` |
| GET | `/admin/v1/providers/health` | **各渠道健康探测结果**（调 `HealthChecker.Ping`），含响应耗时；**扩展返回熔断状态** `circuit_state` / `opened_at` / `recent_failure_ratio`（§5.6.9） | `config:read` |
| POST | `/admin/v1/providers/{platform}:circuit-reset` | **手工复位熔断器**（§5.6.9）。用于误熔断场景（如配置错误导致的连续失败）。需 `reason`，写管理审计 | `config:write` |
| GET | `/admin/v1/health/overview` | 关键指标摘要：授权成功率、合并积压、outbox 积压、claim 不一致数、各平台熔断状态 | `app:read` |

#### J 组 · 凭证一致性运维

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/claims` | 按 `app_id` / `claim_type` / `identity_id` 查询 claim（值只返回哈希前缀） | `identity:read` |
| GET | `/admin/v1/claims/mismatches` | **`claim_mismatch` 记录**（§8.5 回源核对失败），非零即需人工介入 | `identity:read` |
| POST | `/admin/v1/claims/{id}:revoke` | 人工失效某条 claim（需 `reason`） | `identity:write` |

#### K 组 · 管理员授权

| 方法 | 路径 | 说明 | 权限 |
| --- | --- | --- | --- |
| GET | `/admin/v1/admin-grants` | 授权列表 | `admin:grant` |
| POST | `/admin/v1/admin-grants` | 授予角色（支持 `expires_at` 临时授权） | `admin:grant` |
| DELETE | `/admin/v1/admin-grants/{id}` | 撤销授权 | `admin:grant` |

### 15.5 通用约定

**分页**：`?page_size=50&page_token=<opaque>`，返回 `{ items, next_page_token }`。用游标而非 offset，避免深分页性能问题。

**幂等**：所有 `POST` 写操作支持 `Idempotency-Key` 请求头，服务端缓存 24 小时内的结果。

**高危操作的二次确认**（对应 §15.4 中标 🔴 的接口）：

| 机制 | 说明 |
| --- | --- |
| `reason` **必填** | 所有高危写操作必须带 `reason`，写入 `admin_audit_logs.reason` |
| **影响面预估** | 提供 `.../impact` 或 `?dry_run=true`，先返回"将影响 N 个绑定 / M 个令牌"，由前端二次确认 |
| **前后快照** | 高危操作自动记录 `before_state` / `after_state` 到审计表 |
| **双人复核**（P2，可选） | 对 `binding:transfer`、`key:retire` 等超高危操作，支持"提交审批 → 第二人确认"流程；初期可先不做，但表结构上预留 `admin_approvals` |

**高危操作清单**：`binding:transfer`、`bindings:delete`（强制解绑）、`tokens:revoke`、`signing-keys/{kid}:retire`、`merge-operations:retry`、`claims/{id}:revoke`、`events/outbox/{id}:discard`。

### 15.6 分期落地

| 期 | 管理端交付 |
| --- | --- |
| **第一期** | A 组（应用与策略）+ B 组（渠道配置 + `verify`）+ I 组的 `/providers` 与 `/health`。**B 组的 `verify` 接口必须在真实渠道接入前就位**，否则调试期只能靠日志猜配置错误 |
| **第二期** | G 组（事件死信）+ H 组（审计查询，渠道接入后必然要排查） |
| **第三期** | C 组（身份绑定）+ D 组（合并运维）+ J 组（claim 一致性）。**与合并功能同批交付** |
| **第四期** | E 组（会话令牌）+ F 组（密钥管理）+ K 组（管理员授权）+ 审计导出 + 双人复核 |

**表结构建议第一期就建**：`admin_grants` / `admin_audit_logs` 即使前期只用 `super_admin` 一个角色，也应先建表——否则后期补审计会让早期所有变更都无法追溯。

---

## 附录 A · 新增一个渠道的完整步骤

以新增"抖音登录"为例，验证扩展成本：

1. 新建 `internal/infrastructure/provider/adapters/douyin/web.go`
2. 实现 `Provider` 接口（6 个方法，其中 `Refresh` / `Unbind` 可返回 `ErrNotSupported`；可选实现 `HealthChecker`）
3. 文件内 `func init() { provider.Register(&douyinWeb{}) }`
4. 在 `adapters/adapters.go` 加一行 blank import
5. 在管理台为需要的应用配置抖音的 client_key / client_secret
6. 在平台侧配置回调地址 `https://auth.example.com/v1/oauth/callback/douyin`
7. 在文首**权威枚举表**补充 `douyin` 平台与对应 scene，并加入代码中的 Scene 常量表（§术语定义，治理要求 E4）

**不改动任何既有文件**（除了一行 import 和枚举表的登记）。这就是 D1 + D7 两个决策带来的效果。

---

## 附录 B · 新增一个"承载形态"的步骤

验证规则 2（承载形态不进路由键）的实际收益：

1. 在客户端接入时把 `client` 参数传上（如 `client=harmony`，仅用于遥测）
2. 若该形态对应的接入场景已有配置（例如鸿蒙版仍用微信开放平台同一个 appid → `wechat:app`），**服务端零改动**

**无需**新增渠道配置、无需改路由、无需发布服务。这就是"承载形态不参与路由"带来的效果（D1 规则 2）。

---

## 附录 C · 与审查报告的对应

本文档 v0.8 的所有修正均来自 `docs/design-review.md`。两份文档的编号体系（A* / P0-* / P1-* / P2-* / E*）一一对应，便于回溯"某条建议最终怎么落地的"。修复明细见 §14.2。
