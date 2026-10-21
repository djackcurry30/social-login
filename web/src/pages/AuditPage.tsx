// src/pages/AuditPage.tsx — H 组：审计查询与异步导出。
//
// 三个视图：
//   业务审计   用户行为（登录/绑定/合并），按 app_id 隔离
//   管理端审计 管理员行为（谁改了策略、谁强制下线），面向合规追溯
//   导出任务   异步导出（202 + task_id），完成后走鉴权接口下载
//
// 为什么导出是异步的：审计表可上千万行，同步等待会占死连接。
// 这里提交后轮询任务状态，而不是让用户盯着 loading。

import { useEffect, useState } from 'react'

import { AppsApi, AuditApi } from '@/lib/api'
import type {
  AdminAuditRecord,
  Application,
  AuditRecord,
  ExportTask,
} from '@/lib/types'
import { fmtBytes, fmtTime } from '@/lib/utils'
import FormDialog from '@/components/FormDialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

type Tab = 'business' | 'admin' | 'exports'

function resultBadge(r: string) {
  return r === 'success' ? (
    <Badge variant="success">成功</Badge>
  ) : (
    <Badge variant="destructive">{r}</Badge>
  )
}

export default function AuditPage() {
  const [tab, setTab] = useState<Tab>('business')
  const [apps, setApps] = useState<Application[]>([])

  // 业务审计
  const [appId, setAppId] = useState<number | ''>('')
  const [action, setAction] = useState('')
  const [result, setResult] = useState('')
  const [externalUserId, setExternalUserId] = useState('')
  const [traceId, setTraceId] = useState('')
  const [bizRows, setBizRows] = useState<AuditRecord[]>([])
  const [bizTotal, setBizTotal] = useState(0)

  // 管理端审计
  const [subjectId, setSubjectId] = useState('')
  const [adminAction, setAdminAction] = useState('')
  const [adminRows, setAdminRows] = useState<AdminAuditRecord[]>([])
  const [adminTotal, setAdminTotal] = useState(0)

  // 导出
  const [tasks, setTasks] = useState<ExportTask[]>([])
  const [exportOpen, setExportOpen] = useState(false)

  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const PAGE_SIZE = 50

  useEffect(() => {
    AppsApi.list()
      .then((r) => setApps(r.items ?? []))
      .catch(() => {
        /* 忽略 */
      })
  }, [])

  const loadBusiness = async (p = 1) => {
    setLoading(true)
    setErr(null)
    try {
      const r = await AuditApi.business({
        app_id: appId === '' ? undefined : Number(appId),
        action: action || undefined,
        result: result || undefined,
        external_user_id: externalUserId || undefined,
        trace_id: traceId || undefined,
        page: p,
        page_size: PAGE_SIZE,
      })
      setBizRows(r.items ?? [])
      setBizTotal(r.total ?? 0)
      setPage(p)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const loadAdmin = async (p = 1) => {
    setLoading(true)
    setErr(null)
    try {
      const r = await AuditApi.admin({
        subject_id: subjectId || undefined,
        action: adminAction || undefined,
        page: p,
        page_size: PAGE_SIZE,
      })
      setAdminRows(r.items ?? [])
      setAdminTotal(r.total ?? 0)
      setPage(p)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const loadExports = async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await AuditApi.exports({ page_size: PAGE_SIZE })
      setTasks(r.items ?? [])
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (tab === 'business') loadBusiness(1)
    if (tab === 'admin') loadAdmin(1)
    if (tab === 'exports') loadExports()
  }, [tab]) // eslint-disable-line react-hooks/exhaustive-deps

  // 有未完成的任务时轮询：导出是异步的，不给用户一个"手动刷新"的负担。
  useEffect(() => {
    if (tab !== 'exports') return
    const pending = tasks.some((t) => t.status === 'pending' || t.status === 'running')
    if (!pending) return
    const timer = setTimeout(loadExports, 2000)
    return () => clearTimeout(timer)
  }, [tab, tasks]) // eslint-disable-line react-hooks/exhaustive-deps

  const download = async (t: ExportTask) => {
    setErr(null)
    try {
      const blob = await AuditApi.download(t.task_id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-${t.task_id}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const tabBtn = (k: Tab, label: string) => (
    <Button
      key={k}
      variant={tab === k ? 'default' : 'ghost'}
      size="sm"
      onClick={() => {
        setTab(k)
        setPage(1)
      }}
    >
      {label}
    </Button>
  )

  const pager = (total: number, reload: (p: number) => void) => {
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
    return (
      <div className="flex items-center justify-between pt-3">
        <div className="text-xs text-muted-foreground">
          共 {total} 条 · 第 {page}/{pages} 页
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={page <= 1 || loading}
            onClick={() => reload(page - 1)}
          >
            上一页
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={page >= pages || loading}
            onClick={() => reload(page + 1)}
          >
            下一页
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">审计日志</h1>
          <p className="text-sm text-muted-foreground">
            业务审计按应用隔离，管理端审计面向合规追溯。导出为异步任务，
            完成后走鉴权接口下载（含 openid/IP，不做公开直链）。
          </p>
        </div>
        {tab === 'exports' ? (
          <Button onClick={() => setExportOpen(true)}>新建导出</Button>
        ) : null}
      </div>

      <div className="flex gap-1 rounded-lg border bg-background p-1 w-fit">
        {tabBtn('business', '业务审计')}
        {tabBtn('admin', '管理端审计')}
        {tabBtn('exports', '导出任务')}
      </div>

      {err ? <div className="text-sm text-destructive">{err}</div> : null}
      {notice ? <div className="text-sm text-green-600">{notice}</div> : null}

      {tab === 'business' ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">业务审计</CardTitle>
            <CardDescription>用户行为：登录、绑定、合并、解绑</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-6 gap-3 mb-4">
              <div className="space-y-1.5">
                <Label>应用</Label>
                <select
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                  value={appId}
                  onChange={(e) => setAppId(e.target.value ? Number(e.target.value) : '')}
                >
                  <option value="">全部</option>
                  {apps.map((a) => (
                    <option key={a.ID} value={a.ID}>
                      {a.Name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <Label>动作</Label>
                <Input
                  placeholder="login / bind / merge"
                  value={action}
                  onChange={(e) => setAction(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>结果</Label>
                <select
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                  value={result}
                  onChange={(e) => setResult(e.target.value)}
                >
                  <option value="">全部</option>
                  <option value="success">success</option>
                  <option value="failure">failure</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <Label>账号</Label>
                <Input value={externalUserId} onChange={(e) => setExternalUserId(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label>Trace ID</Label>
                <Input value={traceId} onChange={(e) => setTraceId(e.target.value)} />
              </div>
              <div className="flex items-end">
                <Button className="w-full" onClick={() => loadBusiness(1)} disabled={loading}>
                  查询
                </Button>
              </div>
            </div>

            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>应用</TableHead>
                  <TableHead>动作</TableHead>
                  <TableHead>结果</TableHead>
                  <TableHead>账号</TableHead>
                  <TableHead>平台</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Trace</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bizRows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
                      没有匹配的记录
                    </TableCell>
                  </TableRow>
                ) : (
                  bizRows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="text-xs whitespace-nowrap">
                        {fmtTime(r.created_at)}
                      </TableCell>
                      <TableCell>{r.app_id ?? '—'}</TableCell>
                      <TableCell className="text-xs">{r.action}</TableCell>
                      <TableCell>
                        {resultBadge(r.result)}
                        {r.error_code ? (
                          <div className="text-xs text-muted-foreground mt-0.5">
                            {r.error_code}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {r.external_user_id ?? '—'}
                      </TableCell>
                      <TableCell className="text-xs">{r.platform ?? '—'}</TableCell>
                      <TableCell className="text-xs">{r.client_ip ?? '—'}</TableCell>
                      <TableCell className="font-mono text-xs max-w-[140px] truncate">
                        {r.trace_id ?? '—'}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {pager(bizTotal, loadBusiness)}
          </CardContent>
        </Card>
      ) : null}

      {tab === 'admin' ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">管理端审计</CardTitle>
            <CardDescription>管理员行为：谁改了什么、为什么改</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
              <div className="space-y-1.5">
                <Label>操作人</Label>
                <Input
                  placeholder="admin:1"
                  value={subjectId}
                  onChange={(e) => setSubjectId(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>动作</Label>
                <Input
                  placeholder="app.create / token.force_offline"
                  value={adminAction}
                  onChange={(e) => setAdminAction(e.target.value)}
                />
              </div>
              <div className="flex items-end">
                <Button className="w-full" onClick={() => loadAdmin(1)} disabled={loading}>
                  查询
                </Button>
              </div>
            </div>

            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>操作人</TableHead>
                  <TableHead>动作</TableHead>
                  <TableHead>对象</TableHead>
                  <TableHead>原因</TableHead>
                  <TableHead>结果</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {adminRows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                      没有匹配的记录
                    </TableCell>
                  </TableRow>
                ) : (
                  adminRows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="text-xs whitespace-nowrap">
                        {fmtTime(r.created_at)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{r.subject_id}</TableCell>
                      <TableCell className="text-xs">{r.action}</TableCell>
                      <TableCell className="text-xs">
                        {r.target_type}:{r.target_id}
                      </TableCell>
                      <TableCell className="text-xs max-w-[240px] truncate" title={r.reason}>
                        {r.reason || '—'}
                      </TableCell>
                      <TableCell>{resultBadge(r.result)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {pager(adminTotal, loadAdmin)}
          </CardContent>
        </Card>
      ) : null}

      {tab === 'exports' ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">导出任务</CardTitle>
            <CardDescription>
              未完成的任务会自动轮询；文件保留 7 天
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>任务</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>行数</TableHead>
                  <TableHead>大小</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead>过期时间</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tasks.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                      还没有导出任务
                    </TableCell>
                  </TableRow>
                ) : (
                  tasks.map((t) => (
                    <TableRow key={t.task_id}>
                      <TableCell className="font-mono text-xs">{t.task_id}</TableCell>
                      <TableCell>
                        {t.status === 'succeeded' ? (
                          <Badge variant="success">完成</Badge>
                        ) : t.status === 'failed' ? (
                          <Badge variant="destructive">失败</Badge>
                        ) : (
                          <Badge variant="secondary">{t.status}</Badge>
                        )}
                        {t.error_message ? (
                          <div className="text-xs text-muted-foreground mt-0.5 max-w-[240px] truncate">
                            {t.error_message}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell>{t.row_count}</TableCell>
                      <TableCell className="text-xs">{fmtBytes(t.file_size)}</TableCell>
                      <TableCell className="text-xs">{fmtTime(t.created_at)}</TableCell>
                      <TableCell className="text-xs">{fmtTime(t.expires_at)}</TableCell>
                      <TableCell className="text-right">
                        {t.status === 'succeeded' ? (
                          <Button size="sm" variant="outline" onClick={() => download(t)}>
                            下载
                          </Button>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : null}

      <FormDialog
        open={exportOpen}
        onOpenChange={setExportOpen}
        title="新建审计导出"
        description="导出在后台执行，完成后在任务列表里下载。大表导出不占用请求连接。"
        fields={[
          {
            name: 'app_id',
            label: '应用 ID',
            placeholder: '留空表示全部应用',
            hint: '填数字，例如 1',
          },
          { name: 'action', label: '动作（可选）', placeholder: 'login' },
          {
            name: 'result',
            label: '结果（可选）',
            options: [
              { label: 'success', value: 'success' },
              { label: 'failure', value: 'failure' },
            ],
          },
          { name: 'from', label: '起始时间', type: 'datetime-local' },
          { name: 'to', label: '结束时间', type: 'datetime-local' },
        ]}
        submitLabel="提交导出"
        onSubmit={async (v, reason) => {
          const task = await AuditApi.submitExport({
            app_id: v.app_id ? Number(v.app_id) : undefined,
            action: v.action || undefined,
            result: v.result || undefined,
            from: v.from || undefined,
            to: v.to || undefined,
            reason,
          })
          setNotice(`导出已受理：${task.task_id}`)
          setExportOpen(false)
          setTab('exports')
          await loadExports()
        }}
      />
    </div>
  )
}
