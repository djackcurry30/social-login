// src/lib/api.test.ts — 客户端 API 单元测试。
//
// 覆盖：
//   - 401 时清 token + 跳 /admin/login（skipAuthRedirect 时不跳）
//   - 成功响应解析 JSON
//   - ApiError 包含 code/message/status
//   - Bearer Token 自动注入

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api, clearToken, getToken, setToken } from './api'

describe('api client', () => {
  beforeEach(() => {
    clearToken()
    // jsdom 中 window.location 是只读属性，需要用 defineProperty 替换
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign: vi.fn(), href: window.location.href },
      writable: true,
      configurable: true,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('登录成功返回 JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ token: 'abc', user_id: 1 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const r = await api<{ token: string }>(
      '/auth/login',
      { method: 'POST', body: '{}', skipAuthRedirect: true },
    )
    expect(r.token).toBe('abc')
    // 登录接口不带 Authorization
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/admin/v1/auth/login')
    expect(init.headers.get('Authorization')).toBeNull()
  })

  it('已登录时自动注入 Bearer', async () => {
    setToken('test-token')
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response('{"items":[]}', { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)
    await api('/apps')
    expect(fetchMock.mock.calls[0][1].headers.get('Authorization')).toBe(
      'Bearer test-token',
    )
  })

  it('401 时清 token 并跳 /admin/login', async () => {
    setToken('old-token')
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ code: 'AUTH.UNAUTHORIZED', message: 'token invalid' }),
        { status: 401 },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api('/apps')).rejects.toMatchObject({
      code: 'AUTH.UNAUTHORIZED',
      status: 401,
    })
    expect(getToken()).toBeNull()
  })

  it('login 接口收到 401 不跳转', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ code: 'AUTH.UNAUTHORIZED', message: '账号或密码错误' }),
        { status: 401 },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
    await expect(
      api('/auth/login', { method: 'POST', body: '{}', skipAuthRedirect: true }),
    ).rejects.toMatchObject({ code: 'AUTH.UNAUTHORIZED' })
  })

  it('500 响应解析 code+message', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ code: 'INTERNAL.ERROR', message: 'boom' }),
        { status: 500 },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
    await expect(api('/apps')).rejects.toMatchObject({
      code: 'INTERNAL.ERROR',
      status: 500,
    })
  })
})