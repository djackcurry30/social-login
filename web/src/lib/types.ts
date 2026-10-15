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
  AppSecretHash: string
  Status: number // 1=enabled, 0=disabled
  AccountMode: string
  Policy: Policy
  CreatedAt: string
  UpdatedAt: string
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
  SecretCipher: string // base64
  SecretCipherPrev: string | null
  SecretRotatedAt: string | null
  SecretDEKID: string
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
}