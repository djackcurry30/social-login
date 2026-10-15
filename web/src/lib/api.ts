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