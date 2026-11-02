// src/lib/types.ts — 与后端 JSON 对齐的类型。
//
// 字段命名按"后端 JSON 是大写驼峰，前端保持一致"。
// 因为 gin 默认 JSON encoder 是 Go 字段名（不 snake_case），所以保留原样。

export type Role =
  | 'super_admin'
  | 'config_admin'
  | 'operator'
  | 'viewer'

// --- 错误体（§4.4 错误契约）---

export interface ApiError extends Error {
  code: string
  message: string
  retryable: boolean
  details?: Record<string, unknown>
  status?: number
}

// --- Auth ---

export interface LoginInput {
  username: string
  password: string
}

export interface LoginOutput {
  token: string
  user_id: number
  username: string
  role: Role
  expires_at: string // ISO
}

export interface MeOutput {
  user_id: number
  username: string
  display_name: string
  role: Role
  /** 有效权限集（基础角色 ∪ grants）；super_admin 为 ["*"] */
  permissions: string[]
  last_login_at: string | null
  session_expires_at: string
}

// --- A 组（应用与策略）---

export interface Policy {
  on_unbound_login: string
  merge: MergePolicy
  allowed_redirect_uris: string[]
}

export interface MergePolicy {
  mode: string
  verification: string
  on_login: string
  notify_source_account: boolean
  source_disposal: string
  allow_cross_platform_auto?: boolean
}

export interface Application {
  ID: number
  AppCode: string
  Name: string
  // 服务端不再下发 app_secret 的哈希（adminapp.AppView 白名单投影）。
  // 密钥明文只在创建 / 轮换时返回一次。
  Status: number // 1=enabled, 0=disabled
  AccountMode: string
  Policy: Policy
  /** 用户中心注册状态（运维字段）：未同步的应用，其登录会被对端拒绝 */
  AccountSync: AccountSyncState
  CreatedAt: string
  UpdatedAt: string
}

/**
 * 应用在用户中心的注册状态。
 *
 * 为什么要展示：同步是旁路的（失败不阻塞建应用），不显示的话，运维要等到
 * "这个应用的登录全部失败"才知道它根本没注册上。
 */
export interface AccountSyncState {
  /** 最近一次成功同步时间；null 表示从未同步过 */
  SyncedAt: string | null
  /** 最近一次失败原因（成功后由后端清空） */
  LastError: string
}

export interface CreateAppInput {
  name: string
  reason: string
  policy?: Policy
  account_mode?: string
}

export interface UpdateAppInput {
  name?: string
  status?: number
  reason: string
}

export interface RotateSecretOutput {
  app_secret: string
}

// --- B 组（渠道配置）---

export interface ProviderConfig {
  ID: number
  AppID: number
  Platform: string
  Scene: string
  ConfigKey: string
  ProviderAppID: string
  // 服务端不再下发凭据密文与 KEK 版本（adminchan.ConfigView 白名单投影）。
  // 只保留"是否处于轮换过渡期"这一个前端真正需要的派生字段。
  SecretRotationInProgress: boolean
  SecretRotatedAt?: string | null
  Env: string
  Extra: Record<string, unknown>
  Version: number
  Status: number
  CreatedAt: string
  UpdatedAt: string
}

export interface CreateConfigInput {
  app_id?: number
  platform: string
  scene: string
  config_key?: string
  env?: string
  provider_app_id: string
  client_secret: string
  extra?: Record<string, unknown>
  reason: string
}

export interface UpdateConfigInput {
  extra?: Record<string, unknown>
  reason: string
}

export interface VerifyConfigOutput {
  ok: boolean
  latency_ms: number
  error?: string
  http_status?: number
  provider_error?: string
}

// --- I 组（观测）---

export interface ProviderMetadata {
  Platform: string
  Scene: string
  DisplayName: string
  APIVersion: string
  Capabilities: Record<string, boolean>
}

export interface ProviderHealth {
  platform: string
  scene: string
  display_name: string
  api_version: string
  ok: boolean
  latency_ms: number
  error?: string
}

export interface OverviewStats {
  provider_count: number
  apps_count: number
  healthy_providers: number
  unhealthy_providers: number
  by_platform: Record<string, number>
  /** 未闭环的凭证漂移数：非 0 说明有一批用户本该被归并、却被拦住了（J 组） */
  claim_mismatch_open: number
  /** 账号体系现状：桩或真实用户中心 */
  account_center: AccountCenterInfo
}

/**
 * 账号体系的"当前实现"标记。
 *
 * 为什么要有它：stub 与 http 在外部表现上几乎一样（都能登录成功、都能发令牌），
 * 差别只在账号落在哪里。用户中心未就绪期间，这个标记是唯一不会看错的地方。
 */
export interface AccountCenterInfo {
  /** stub | http */
  provider: string
  base_url?: string
  /** true 仅表示"接的是真实用户中心"，不代表连通性 */
  production_ready: boolean
  note?: string
}
// --- C 组（身份与绑定）---

export interface IdentityItem {
  id: number
  app_id: number
  platform: string
  provider_app_id: string
  open_id: string
  identity_key: string
  profile_snapshot?: Record<string, unknown>
  first_seen_at: string
  last_login_at?: string
  profile_synced_at?: string
}

/**
 * 凭证状态。
 *
 * - verified    已验证且生效：可以作为归并依据
 * - unverified  未验证（用户手填，永不参与自动归并）
 * - revoked     已撤销：号码已释放，可被其他身份占用
 *
 * 由后端下发而不是前端从 verified + revoked_at 推：撤销只置 revoked_at、
 * 不改 verified 位，前端自己推会把"已撤销"算成"已验证"。
 */
export type ClaimStatus = 'verified' | 'unverified' | 'revoked'

export interface ClaimItem {
  id: number
  app_id: number
  identity_id: number
  claim_type: string
  /** 只返回哈希前缀：库里没有明文，后端也不回显 */
  value_hash_prefix?: string
  status: ClaimStatus
  verified: boolean
  source: string
  verified_at?: string
  revoked_at?: string
  created_at: string
}

export interface ClaimListOutput {
  items: ClaimItem[]
  total: number
  page: number
  page_size: number
}

/**
 * 凭证明细漂移的类型（后端 claim_mismatches.kind）。
 *
 * - account_not_found  用户中心查无此凭证（换号 / 解绑）
 * - account_mismatch   用户中心说归 A，本地绑定挂在 B（最危险）
 * - multiple_accounts  该凭证在用户中心命中多个账号（数据已脏）
 * - identity_missing   claim 指向的身份已被删除
 */
export type MismatchKind =
  | 'account_not_found'
  | 'account_mismatch'
  | 'multiple_accounts'
  | 'identity_missing'

export interface ClaimMismatch {
  id: number
  app_id: number
  claim_id: number
  identity_id: number
  claim_type: string
  value_hash_prefix?: string
  platform: string
  claim_source: string
  kind: MismatchKind
  /** 本地绑定认为该凭证属于谁 */
  expected_user_id?: string
  /** 用户中心说它属于谁 */
  actual_user_id?: string
  detail?: string
  status: 'open' | 'resolved'
  /** >1 说明这处漂移长期存在，每次登录都命中 */
  occurrences: number
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  resolved_by?: string
  resolution?: string
}

export interface MismatchListOutput {
  items: ClaimMismatch[]
  total: number
  page: number
  page_size: number
  /** 未闭环总数：不受筛选影响，是"这个应用还有多少条待处理"的全量信号 */
  open_total: number
}

export interface BindingItem {
  id: number
  app_id: number
  external_user_id: string
  identity_id: number
  status: 'active' | 'unbound'
  is_primary: boolean
  bind_source: string
  bound_at: string
  unbound_at?: string
}

export interface IdentityDetail {
  identity: IdentityItem
  claims: ClaimItem[]
  bindings: BindingItem[]
}

export interface IdentityListOutput {
  items: IdentityItem[]
  total: number
  page: number
  page_size: number
}

export interface BindingListOutput {
  items: BindingItem[]
  total: number
  page: number
  page_size: number
}

// --- D 组（合并运维）---

export type MergeStatus = 'pending' | 'done' | 'failed' | 'dead' | 'rejected'

export interface MergeOperation {
  id: number
  app_id: number
  idempotency_key: string
  target_user_id: string
  source_user_id: string
  identity_id?: number
  status: MergeStatus
  reason?: string
  attempts: number
  last_error?: string
  remote_result?: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface MergeListOutput {
  items: MergeOperation[]
  total: number
  page: number
  page_size: number
}

export interface MergeImpact {
  Bindings: number
  Tokens: number
  Identities: string[]
}

// --- E 组（会话与令牌）---

export interface SessionTokenItem {
  id: number
  app_id: number
  external_user_id: string
  device_id?: string
  scope?: string
  revoked: boolean
  revoked_reason?: string
  expires_at: string
  created_at: string
  rotated_from?: number
  active: boolean
}

export interface SessionListOutput {
  items: SessionTokenItem[]
  total: number
  page: number
  page_size: number
}

export interface ForceOfflineOutput {
  revoked_tokens: number
  revoked_at: string
  /** 未开启 check_revocation 的调用方仍可能接受旧令牌的剩余秒数 */
  effective_window_seconds: number
}

export interface RevocationView {
  app_id: number
  external_user_id: string
  revoked_at?: string
  jti?: string
  jti_revoked?: boolean
}

// --- F 组（签名密钥）---

export interface SigningKeyInfo {
  kid: string
  algorithm: string
  status: 'signing' | 'published'
  created_at: string
  demoted_at?: string
  retirable_at?: string
}

export interface RotateKeyOutput {
  new_kid: string
  previous_kid?: string
  retirable_at?: string
  published_keys: number
}

// --- H 组（审计）---

export interface AuditRecord {
  id: number
  app_id?: number
  external_user_id?: string
  platform?: string
  scene?: string
  client?: string
  action: string
  result: string
  error_code?: string
  client_ip?: string
  user_agent?: string
  trace_id?: string
  detail?: Record<string, unknown>
  created_at: string
}

export interface AdminAuditRecord {
  id: number
  subject_id: string
  action: string
  target_type: string
  target_id: string
  reason?: string
  before_state?: Record<string, unknown>
  after_state?: Record<string, unknown>
  result: string
  error_code?: string
  created_at: string
}

export interface AuditListOutput<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface ExportTask {
  task_id: string
  status: 'pending' | 'running' | 'succeeded' | 'failed'
  row_count: number
  file_size: number
  error_code?: string
  error_message?: string
  criteria?: Record<string, unknown>
  created_at: string
  started_at?: string
  finished_at?: string
  expires_at?: string
  download_path?: string
}

// --- K 组（管理员授权）---

export interface AdminGrant {
  id: number
  subject_id: string
  role: string
  scope_app_id?: number
  granted_by: string
  granted_at: string
  expires_at?: string
  revoked_at?: string
  effective: boolean
}

export interface GrantListOutput {
  items: AdminGrant[]
  total: number
  page: number
  page_size: number
}

// --- G 组（事件与死信）---

/**
 * 事件投递状态。
 *
 * - pending    待投递（排队中，或在等下一次重试）
 * - sent       已送达
 * - dead       死信：重试耗尽，或被对方明确拒收（4xx）
 * - skipped    已跳过：应用没配 webhook_url（配置状态，不是故障）
 * - discarded  已丢弃（人工，必须写理由）
 */
export type EventStatus = 'pending' | 'sent' | 'dead' | 'skipped' | 'discarded'

export interface EventOutboxItem {
  id: number
  app_id: number
  /** 业务方按它去重；重投时保持不变 */
  event_id: string
  event_type: string
  schema_version: number
  status: EventStatus
  /** 已尝试投递次数（最大 5） */
  attempts: number
  next_retry_at?: string
  /** 最近一次失败原因（对方返回的原文） */
  last_error?: string
  created_at: string
  sent_at?: string
  /** 只有详情接口返回：列表不带 payload，单条事件体可能很大 */
  payload?: Record<string, unknown>
}

export interface EventListOutput {
  items: EventOutboxItem[]
  total: number
  page: number
  page_size: number
}
