// src/components/Layout.tsx — 整体布局：左侧导航 + 顶部用户条 + 内容区。
//
// 设计依据：
//   - §15.6 第 6 项要求"操作记录在主操作页内一键可见"，因此右上保留用户名+登出
//   - 路由：左侧导航列三组入口（A / B / I），点击切换右侧
//   - 当前激活项用 useLocation() 判断

import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { LogOut } from 'lucide-react'

import { AuthApi, clearToken } from '@/lib/api'
import { Button } from '@/components/ui/button'

const NAV = [
  {
    title: '应用与策略',
    items: [
      { label: '应用列表', to: '/apps' },
      { label: '新建应用', to: '/apps/new' },
    ],
  },
  {
    title: '渠道配置',
    items: [
      { label: '渠道列表', to: '/channels' },
      { label: '观测看板', to: '/observability' },
    ],
  },
  {
    title: '身份与账号',
    items: [
      { label: '身份与绑定', to: '/identities' },
      { label: '会话与令牌', to: '/sessions' },
      { label: '合并运维', to: '/merges' },
    ],
  },
  {
    title: '审计与系统',
    items: [
      { label: '审计日志', to: '/audit' },
      { label: '签名密钥', to: '/signing-keys' },
      { label: '管理员授权', to: '/admin-grants' },
    ],
  },
]

export default function Layout() {
  const location = useLocation()
  const onLogout = async () => {
    try {
      await AuthApi.logout()
    } catch {
      /* 即使后端报错也清掉本地 token */
    }
    clearToken()
    window.location.assign('/admin/login')
  }

  return (
    <div className="flex h-screen bg-muted/30">
      {/* 左侧导航 */}
      <aside className="w-56 border-r bg-background flex flex-col">
        <div className="p-4 border-b">
          <div className="text-base font-semibold">social-login 管理端</div>
          <div className="text-xs text-muted-foreground mt-0.5">
            {location.pathname}
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto p-2 space-y-4">
          {NAV.map((group) => (
            <div key={group.title}>
              <div className="px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                {group.title}
              </div>
              <div className="space-y-0.5">
                {group.items.map((it) => (
                  <NavLink
                    key={it.to}
                    to={it.to}
                    className={({ isActive }) =>
                      [
                        'block rounded px-2 py-1.5 text-sm',
                        isActive
                          ? 'bg-primary text-primary-foreground'
                          : 'hover:bg-accent hover:text-accent-foreground',
                      ].join(' ')
                    }
                  >
                    {it.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="p-3 border-t text-xs text-muted-foreground">
          v0.1 · 第一期
        </div>
      </aside>

      {/* 右侧主区 */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* 顶部条 */}
        <header className="h-12 border-b bg-background flex items-center justify-between px-4 shrink-0">
          <Link to="/apps" className="text-sm text-muted-foreground hover:text-foreground">
            首页
          </Link>
          <Button
            variant="ghost"
            size="sm"
            onClick={onLogout}
            className="gap-1.5"
          >
            <LogOut className="h-4 w-4" />
            登出
          </Button>
        </header>

        {/* 内容 */}
        <div className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}