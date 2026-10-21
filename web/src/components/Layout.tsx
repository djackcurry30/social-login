// src/components/Layout.tsx — 整体布局：左侧导航 + 顶部用户条 + 内容区。
//
// 导航分组的原则是【使用场景】，不是按接口分组（A/B/C…）：
//
//	接入配置   上线前做一次，之后很少动
//	账号运营   日常高频：查身份、踢会话、推进合并
//	运行与审计 出问题时去的地方：看健康度、翻审计
//	系统设置   低频高危：密钥、授权
//
// 几个刻意的处理：
//   - "新建应用"不占导航位：它是列表页里的动作，不是独立页面。
//     放导航里会出现"点了新建、返回却找不到自己在哪"的问题。
//   - "观测看板"不在"渠道配置"下：它看的是全局健康度与汇总指标，
//     与"配置某个渠道"不是一件事。
//   - 菜单按角色过滤：viewer / operator / config_admin 看不到"管理员授权"，
//     免得点进去吃 403。
//   - 左下显示"这是谁、什么角色"：权限异常时第一件事就是确认我是谁。

import { Link, NavLink, Outlet } from 'react-router-dom'
import { LogOut } from 'lucide-react'

import { logoutAndClear, useMe } from '@/lib/auth'
import type { Role } from '@/lib/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

interface NavItem {
  label: string
  to: string
  /** 为空表示所有角色可见 */
  roles?: Role[]
}

interface NavGroup {
  title: string
  items: NavItem[]
}

const NAV: NavGroup[] = [
  {
    title: '接入配置',
    items: [
      { label: '应用列表', to: '/apps' },
      { label: '渠道配置', to: '/channels' },
    ],
  },
  {
    title: '账号运营',
    items: [
      { label: '身份与绑定', to: '/identities' },
      { label: '会话与令牌', to: '/sessions' },
      { label: '合并运维', to: '/merges' },
    ],
  },
  {
    title: '运行与审计',
    items: [
      { label: '观测看板', to: '/observability' },
      { label: '审计日志', to: '/audit' },
    ],
  },
  {
    title: '系统设置',
    items: [
      { label: '签名密钥', to: '/signing-keys' },
      // admin:grant 只有 super_admin 拥有（见 domain/admin.Permissions）
      { label: '管理员授权', to: '/admin-grants', roles: ['super_admin'] },
    ],
  },
]

const ROLE_LABEL: Record<Role, string> = {
  super_admin: '超级管理员',
  config_admin: '配置管理员',
  operator: '运营',
  viewer: '只读',
}

export default function Layout() {
  // 与各页面共用同一份缓存，避免每次进页面都拉一次 /auth/me。
  const { me } = useMe()

  const onLogout = logoutAndClear

  const visible = (item: NavItem) =>
    !item.roles || (!!me?.role && item.roles.includes(me.role))

  return (
    <div className="flex h-screen bg-muted/30">
      {/* 左侧导航 */}
      <aside className="w-56 border-r bg-background flex flex-col">
        <div className="p-4 border-b">
          <div className="text-base font-semibold">social-login 管理端</div>
          <div className="text-xs text-muted-foreground mt-0.5">三方登录统一接入</div>
        </div>
        <nav className="flex-1 overflow-y-auto p-2 space-y-4">
          {NAV.map((group) => {
            const items = group.items.filter(visible)
            if (items.length === 0) return null
            return (
              <div key={group.title}>
                <div className="px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  {group.title}
                </div>
                <div className="space-y-0.5">
                  {items.map((it) => (
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
            )
          })}
        </nav>
        <div className="p-3 border-t text-xs text-muted-foreground">
          {me ? (
            <div className="flex items-center gap-1.5">
              <span className="truncate" title={me.username}>
                {me.display_name || me.username}
              </span>
              <Badge variant="outline" className="shrink-0">
                {ROLE_LABEL[me.role] ?? me.role}
              </Badge>
            </div>
          ) : (
            '未登录'
          )}
        </div>
      </aside>

      {/* 右侧主区 */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* 顶部条 */}
        <header className="h-12 border-b bg-background flex items-center justify-between px-4 shrink-0">
          <Link to="/apps" className="text-sm text-muted-foreground hover:text-foreground">
            首页
          </Link>
          <Button variant="ghost" size="sm" onClick={onLogout} className="gap-1.5">
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
