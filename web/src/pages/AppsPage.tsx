// src/pages/AppsPage.tsx — 应用列表（A 组）。
//
// 列表 + 顶部"新建应用"按钮；状态用 Badge 显示（启用 / 停用）；
// 点击行进入 /apps/:id 编辑页（policy、secret rotate、删除）。

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Plus } from 'lucide-react'

import { AppsApi } from '@/lib/api'
import type { Application } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

/**
 * SyncBadge 显示该应用是否已注册到用户中心。
 *
 * 用户中心按 app_key 隔离账号空间，未注册的应用在其侧一律 400 APP.UNKNOWN
 * ——也就是说"未同步"不是配置瑕疵，而是这个应用的登录全部不可用。
 * 三个状态刻意区分开：
 *   已同步（有成功时间） / 未同步（有失败原因） / 未知（从未尝试，例如 stub 模式）
 */
function SyncBadge({ app }: { app: Application }) {
  const sync = app.AccountSync
  const syncedAt = sync?.SyncedAt
  const lastError = sync?.LastError

  if (syncedAt) {
    return (
      <Badge
        variant="success"
        title={`上次同步：${new Date(syncedAt).toLocaleString()}`}
      >
        已同步
      </Badge>
    )
  }
  if (lastError) {
    return (
      <Badge variant="destructive" title={lastError}>
        未同步
      </Badge>
    )
  }
  return (
    <Badge
      variant="secondary"
      title="尚未同步过。若当前账号体系为内存桩（未接用户中心），可忽略"
    >
      —
    </Badge>
  )
}

export default function AppsPage() {
  const [items, setItems] = useState<Application[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    setErr(null)
    try {
      const out = await AppsApi.list()
      setItems(out.items ?? [])
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">应用与策略</h1>
          <p className="text-sm text-muted-foreground">
            接入方的 app 与 redirect_uri 白名单、合并策略等。
          </p>
        </div>
        <Button asChild>
          <Link to="/apps/new" className="gap-1.5">
            <Plus className="h-4 w-4" />新建应用
          </Link>
        </Button>
      </div>

      {err ? (
        <Card className="border-destructive">
          <CardContent className="text-sm text-destructive py-3">
            {err}
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">全部应用（{items.length}）</CardTitle>
          <CardDescription>
            点击行进入编辑页；新建会返回一次明文 app_secret。
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">加载中…</div>
          ) : items.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">
              暂无应用，点右上"新建应用"创建第一个。
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead>名称</TableHead>
                  <TableHead>AppCode</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>账号模式</TableHead>
                  <TableHead>用户中心</TableHead>
                  <TableHead>更新时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((a) => (
                  <TableRow key={a.ID}>
                    <TableCell className="font-mono">{a.ID}</TableCell>
                    <TableCell>
                      <Link
                        to={`/apps/${a.ID}`}
                        className="text-primary hover:underline"
                      >
                        {a.Name}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.AppCode}
                    </TableCell>
                    <TableCell>
                      <Badge variant={a.Status === 1 ? 'success' : 'secondary'}>
                        {a.Status === 1 ? '启用' : '停用'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">
                      {a.AccountMode}
                    </TableCell>
                    <TableCell>
                      <SyncBadge app={a} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(a.UpdatedAt).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}