// src/lib/api.ts — 管理端 HTTP 客户端。
//
// 设计要点：
//   - 所有 admin 接口都走 /admin/v1/*（vite dev proxy + 生产 go embed 都对齐这个前缀）
//   - 鉴权：Bearer Token 走 localStorage；401 时清掉 token 并跳转 /login
//   - 错误：统一按 §4.4 错误体解析（code / message / retryable / details）
//   - 高危操作接口携带 reason，由调用方提供（UI 上 dialog 强制输入）

import type { ApiError } from '@/lib/types'

const TOKEN_KEY = 'admin_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export type FetchOptions = RequestInit & {
  /** 当 401 时不要自动跳转 /login（用于登录接口本身） */
  skipAuthRedirect?: boolean
}

/**
 * 通用 fetch 包装，自动处理 Bearer Token 与错误体解析。
 *
 * - 解析成功：返回解析后的 JSON
 * - 解析失败：抛 ApiError（带 code/message/retryable/details）
 * - HTTP 401：清 token 后抛 ApiError；除非 skipAuthRedirect=true（登录接口用）
 */
export async function api<T>(path: string, opts: FetchOptions = {}): Promise<T> {
  const headers = new Headers(opts.headers)
  headers.set('Content-Type', 'application/json')
  const token = getToken()
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const res = await fetch(`/admin/v1${path}`, {
    ...opts,
    headers,
  })

  // 401：清 token + 跳转登录（除非显式跳过）。
  if (res.status === 401) {
    if (!opts.skipAuthRedirect) {
      clearToken()
      // 用 location 而不是 router.navigate：避免在非 React 上下文被调用
      if (window.location.pathname !== '/login') {
        window.location.assign('/admin/login')
      }
    }
    throw await toApiError(res)
  }

  if (!res.ok) {
    throw await toApiError(res)
  }

  // 204 No Content
  if (res.status === 204) {
    return undefined as T
  }

  return (await res.json()) as T
}

async function toApiError(res: Response): Promise<ApiError> {
  let body: Partial<ApiError> = {}
  try {
    body = await res.json()
  } catch {
    body = { message: res.statusText || '请求失败' }
  }
  const err = new Error(body.message ?? '请求失败') as ApiError
  err.code = body.code ?? 'UNKNOWN'
  err.message = body.message ?? '请求失败'
  err.retryable = body.retryable ?? false
  err.details = body.details
  err.status = res.status
  err.name = 'ApiError'
  return err
}

// --- 业务方法（按 §15.4 第一期）---

import type {
  LoginInput,
  LoginOutput,
  MeOutput,
  Application,
  Policy,
  CreateAppInput,
  UpdateAppInput,
  RotateSecretOutput,
  ProviderConfig,
  CreateConfigInput,
  UpdateConfigInput,
  RotateSecretOutput as RotateChannelSecretOutput,
  VerifyConfigOutput,
  ProviderMetadata,
  ProviderHealth,
  OverviewStats,
  IdentityListOutput,
  IdentityDetail,
  BindingListOutput,
  BindingItem,
  MergeListOutput,
  MergeOperation,
  MergeImpact,
  SessionListOutput,
  ForceOfflineOutput,
  RevocationView,
  SigningKeyInfo,
  RotateKeyOutput,
  AuditRecord,
  AdminAuditRecord,
  AuditListOutput,
  ExportTask,
  GrantListOutput,
  AdminGrant,
} from '@/lib/types'

export const AuthApi = {
  login: (inp: LoginInput) =>
    api<LoginOutput>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(inp),
      skipAuthRedirect: true,
    }),
  me: () => api<MeOutput>('/auth/me'),
  logout: () => api<{ ok: true }>('/auth/logout', { method: 'POST' }),
}

export const AppsApi = {
  list: () => api<{ items: Application[]; next_page_token: string }>('/apps'),
  get: (id: number) => api<{ app: Application }>(`/apps/${id}`),
  create: (inp: CreateAppInput) =>
    api<{ app: Application; app_secret: string }>('/apps', {
      method: 'POST',
      body: JSON.stringify(inp),
    }),
  update: (id: number, inp: UpdateAppInput) =>
    api<{ app: Application }>(`/apps/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(inp),
    }),
  rotateSecret: (id: number, reason: string) =>
    api<RotateSecretOutput>(`/apps/${id}/secret/rotate`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  getPolicy: (id: number) => api<{ policy: Policy }>(`/apps/${id}/policy`),
  savePolicy: (id: number, policy: Policy, reason: string) =>
    api<{ policy: Policy }>(`/apps/${id}/policy`, {
      method: 'PUT',
      body: JSON.stringify({ policy, reason }),
    }),
  validatePolicy: (policy: Policy) =>
    api<{ warnings: string[] | null; normalized: Policy }>(
      '/apps/0/policy/validate',
      {
        method: 'POST',
        body: JSON.stringify({ policy }),
      },
    ),
}

export const ChannelsApi = {
  list: (appId: number) =>
    api<{ items: ProviderConfig[] }>(`/apps/${appId}/provider-configs`),
  get: (appId: number, id: number) =>
    api<{ config: ProviderConfig }>(`/apps/${appId}/provider-configs/${id}`),
  create: (appId: number, inp: CreateConfigInput) =>
    api<{ config: ProviderConfig }>(`/apps/${appId}/provider-configs`, {
      method: 'POST',
      body: JSON.stringify({ ...inp, app_id: appId }),
    }),
  update: (appId: number, id: number, inp: UpdateConfigInput) =>
    api<{ config: ProviderConfig }>(
      `/apps/${appId}/provider-configs/${id}`,
      { method: 'PATCH', body: JSON.stringify(inp) },
    ),
  rotateSecret: (
    appId: number,
    id: number,
    newClientSecret: string,
    reason: string,
  ) =>
    api<RotateChannelSecretOutput>(
      `/apps/${appId}/provider-configs/${id}/secret/rotate`,
      {
        method: 'POST',
        body: JSON.stringify({ new_client_secret: newClientSecret, reason }),
      },
    ),
  finalizeSecret: (appId: number, id: number, reason: string) =>
    api<{ ok: true }>(
      `/apps/${appId}/provider-configs/${id}/secret/finalize`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    ),
  verify: (appId: number, id: number, reason: string) =>
    api<VerifyConfigOutput>(
      `/apps/${appId}/provider-configs/${id}/secret/verify`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    ),
  enable: (appId: number, id: number, reason: string) =>
    api<{ ok: true }>(
      `/apps/${appId}/provider-configs/${id}/enable`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    ),
  disable: (appId: number, id: number, reason: string) =>
    api<{ ok: true }>(
      `/apps/${appId}/provider-configs/${id}/disable`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    ),
  delete: (appId: number, id: number, reason: string) =>
    api<{ ok: true }>(`/apps/${appId}/provider-configs/${id}`, {
      method: 'DELETE',
      body: JSON.stringify({ reason }),
    }),
}

export const ProvidersApi = {
  list: () => api<{ items: ProviderMetadata[] }>('/providers'),
  health: () =>
    api<{ probed_at: string; items: ProviderHealth[] }>('/providers/health'),
  overview: () => api<OverviewStats>('/health/overview'),
}
// --- C 组：身份与绑定 ---

export const IdentitiesApi = {
  list: (q: {
    app_id?: number
    platform?: string
    open_id?: string
    identity_key?: string
    external_user_id?: string
    page?: number
    page_size?: number
  }) => api<IdentityListOutput>(`/identities${qs(q)}`),
  get: (id: number, appId: number) =>
    api<IdentityDetail>(`/identities/${id}?app_id=${appId}`),
  bindings: (q: {
    app_id?: number
    external_user_id?: string
    status?: string
    identity_id?: number
    page?: number
    page_size?: number
  }) => api<BindingListOutput>(`/bindings${qs(q)}`),
  /** 某账号的全部绑定（含已解绑历史） */
  accountBindings: (appId: number, externalUserId: string) =>
    api<BindingListOutput>(
      `/accounts/${encodeURIComponent(externalUserId)}/bindings?app_id=${appId}`,
    ),
  /**
   * 强制解绑。reason 走 body：DELETE 带 body 在部分客户端会被丢弃，
   * 后端同时接受 query 兜底，这里用 body 与其它高危操作保持一致的写法。
   */
  forceUnbind: (id: number, reason: string, appId?: number) =>
    api<{ binding: BindingItem }>(`/bindings/${id}`, {
      method: 'DELETE',
      body: JSON.stringify({ reason, app_id: appId }),
    }),
  /** transfer 旁路：把 identity 从旧账号转到新账号，旧账号保留 */
  transfer: (id: number, targetUserID: string, reason: string, appId?: number) =>
    api<{ binding: BindingItem }>(`/bindings/${id}/transfer`, {
      method: 'POST',
      body: JSON.stringify({ target_user_id: targetUserID, reason, app_id: appId }),
    }),
}

// --- D 组：合并运维 ---

export const MergesApi = {
  list: (q: {
    app_id?: number
    status?: string
    user_id?: string
    page?: number
    page_size?: number
  }) => api<MergeListOutput>(`/merge-operations${qs(q)}`),
  get: (id: number) => api<{ merge_operation: MergeOperation }>(`/merge-operations/${id}`),
  impact: (id: number) => api<{ impact: MergeImpact }>(`/merge-operations/${id}/impact`),
  /**
   * 人工重试。⚠️ 后端复用原幂等键，这里不需要传任何键——
   * 换新键会让用户中心当成一次新合并，可能重复迁移数据。
   */
  retry: (id: number, reason: string) =>
    api<{ ok: true }>(`/merge-operations/${id}/retry`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  /** 标记人工已核对处理，停止补偿重试（置 dead，不是 done） */
  resolve: (id: number, reason: string) =>
    api<{ ok: true }>(`/merge-operations/${id}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
}

// --- E 组：会话与令牌 ---

export const SessionsApi = {
  list: (q: {
    app_id?: number
    external_user_id?: string
    device_id?: string
    active?: string
    page?: number
    page_size?: number
  }) => api<SessionListOutput>(`/tokens${qs(q)}`),
  /** 强制下线：撤全部 refresh_token + 写账号撤销水位 */
  forceOffline: (appId: number, externalUserID: string, reason: string) =>
    api<ForceOfflineOutput>('/tokens/revoke', {
      method: 'POST',
      body: JSON.stringify({
        app_id: appId,
        external_user_id: externalUserID,
        reason,
      }),
    }),
  revocation: (appId: number, externalUserID?: string, jti?: string) =>
    api<RevocationView>(
      `/revoked-jti${qs({ app_id: appId, external_user_id: externalUserID, jti })}`,
    ),
}

// --- F 组：签名密钥 ---

export const SigningKeysApi = {
  list: () => api<{ items: SigningKeyInfo[] }>('/signing-keys'),
  jwksPreview: () => api<{ keys: Array<Record<string, unknown>> }>('/signing-keys/jwks-preview'),
  /** 轮换第 1·2 步：新密钥开始签名，旧密钥继续发布在 JWKS */
  rotate: (reason: string) =>
    api<RotateKeyOutput>('/signing-keys/rotate', {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  /** 轮换第 3·4 步：下线旧密钥（后端强制"旧 token 已过期"前置校验） */
  retire: (kid: string, reason: string) =>
    api<{ ok: true }>(`/signing-keys/${encodeURIComponent(kid)}/retire`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
}

// --- H 组：审计 ---

export const AuditApi = {
  /** 业务审计（跨应用，可按 app_id 过滤） */
  business: (q: {
    app_id?: number
    action?: string
    result?: string
    external_user_id?: string
    platform?: string
    trace_id?: string
    from?: string
    to?: string
    page?: number
    page_size?: number
  }) => api<AuditListOutput<AuditRecord>>(`/audit-logs${qs(q)}`),
  /** 管理端审计 */
  admin: (q: {
    action?: string
    result?: string
    subject_id?: string
    target_type?: string
    target_id?: string
    from?: string
    to?: string
    page?: number
    page_size?: number
  }) => api<AuditListOutput<AdminAuditRecord>>(`/audit-logs/admin${qs(q)}`),
  exports: (q?: { page?: number; page_size?: number }) =>
    api<AuditListOutput<ExportTask>>(`/audit-logs/exports${qs(q ?? {})}`),
  submitExport: (inp: {
    app_id?: number
    action?: string
    result?: string
    from?: string
    to?: string
    reason: string
  }) =>
    api<ExportTask>('/audit-logs/export', {
      method: 'POST',
      body: JSON.stringify(inp),
    }),
  getExport: (taskId: string) => api<ExportTask>(`/audit-logs/export/${taskId}`),
  /**
   * 下载导出文件。
   *
   * 用 fetch + blob 而不是 <a href>：下载走鉴权接口，直链没有 Authorization
   * 头会被 401。审计含 openid/IP/UA，不能做成公开直链。
   */
  download: async (taskId: string): Promise<Blob> => {
    const token = getToken()
    const res = await fetch(`/admin/v1/audit-logs/export/${taskId}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) {
      throw await toApiError(res)
    }
    return await res.blob()
  },
}

// --- K 组：管理员授权 ---

export const GrantsApi = {
  list: (q?: {
    subject_id?: string
    include_revoked?: boolean
    page?: number
    page_size?: number
  }) => api<GrantListOutput>(`/admin-grants${qs(q ?? {})}`),
  grant: (inp: {
    subject_id: string
    role: string
    scope_app_id?: number
    expires_at?: string
    reason: string
  }) =>
    api<{ grant: AdminGrant }>('/admin-grants', {
      method: 'POST',
      body: JSON.stringify(inp),
    }),
  revoke: (id: number, reason: string) =>
    api<{ ok: true }>(`/admin-grants/${id}`, {
      method: 'DELETE',
      body: JSON.stringify({ reason }),
    }),
}

/** qs 把查询参数拼成 `?a=1&b=2`，自动跳过空值。 */
function qs(q: Record<string, unknown>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue
    p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}
