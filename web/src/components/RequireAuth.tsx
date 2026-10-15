// src/components/RequireAuth.tsx — 路由守卫：未登录跳 /login。
//
// 设计依据：架构 §15.6 第 3 项"鉴权失败时统一跳登录"；
// 这里只检查 localStorage 是否有 token——后端 401 会被 api() 拦截再次跳。

import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'

import { getToken } from '@/lib/api'

export default function RequireAuth({ children }: { children: ReactNode }) {
  if (!getToken()) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}