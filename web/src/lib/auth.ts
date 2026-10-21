// src/lib/auth.ts — 当前管理员的身份与权限（前端侧）。
//
// 为什么权限要从后端拿而不是前端内置一份 role→perm 表：
// 两份表必然漂移——后端加了一个权限、忘了改前端，按钮就一直灰着，
// 而没人会想到是前端的问题。所以 /auth/me 直接返回有效权限集
// （基础角色 ∪ grants，super_admin 为 ["*"]）。
//
// 请求做了模块级缓存：Layout 与各页面都要用，重复拉 me 没有意义。

import { useEffect, useState } from 'react'

import { AuthApi, clearToken } from '@/lib/api'
import type { MeOutput } from '@/lib/types'

let cached: Promise<MeOutput> | null = null

/** loadMe 拉取当前管理员信息（带模块级缓存）。 */
export function loadMe(): Promise<MeOutput> {
  if (!cached) {
    cached = AuthApi.me().catch((e) => {
      // 失败的 Promise 不能留在缓存里，否则下一次进来还是同一个拒绝。
      cached = null
      throw e
    })
  }
  return cached
}

/** resetMeCache 在登出/换账号时清缓存。 */
export function resetMeCache() {
  cached = null
}

/** useMe 订阅当前管理员信息。 */
export function useMe() {
  const [me, setMe] = useState<MeOutput | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    loadMe()
      .then((m) => {
        if (alive) setMe(m)
      })
      .catch(() => {
        /* api() 已处理 401 跳登录 */
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [])

  return { me, loading }
}

/**
 * can 判断是否拥有某项权限。
 *
 * me 还没加载完时返回 true（乐观）：先让按钮可点，点了后端会拦。
 * 反过来（默认禁用）会让页面在首屏闪一下"全部不可用"，体验更差。
 */
export function can(me: MeOutput | null, perm: string): boolean {
  if (!me) return true
  const perms = me.permissions ?? []
  return perms.includes('*') || perms.includes(perm)
}

/** logoutAndClear 登出并清掉本地状态。 */
export async function logoutAndClear() {
  try {
    await AuthApi.logout()
  } catch {
    /* 即使后端报错也清掉本地 token */
  }
  clearToken()
  resetMeCache()
  window.location.assign('/admin/login')
}
