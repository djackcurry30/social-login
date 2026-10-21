// src/pages/MergesPage.tsx — D 组：账号合并运维。
//
// 合并是高风险不可逆操作：远端合并成功后本地可能失败，靠补偿任务重放。
// 这一页的价值是"能看见并推动卡住的合并"：
//   - 默认按 status=failed/pending 筛，先看需要处理的那批
//   - retry 复用原幂等键（后端保证），不会重复迁移数据
//   - resolve 是"人工核对完毕"的出口，置 dead 而不是 done——
//     置 done 会被下游当成"合并成功"，那是谎报

import { useEffect, useState } from 'react'

import { AppsApi, MergesApi } from '@/lib/api'
import type { Application, MergeImpact, MergeOperation } from '@/lib/types'
import { fmtTime } from '@/lib/utils'
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

const STATUS_LABEL: Record<string, string> = {
  pending: '待推进',
  done: '已完成',
  failed: '失败（可补偿）',
  dead: '需人工处理',
  rejected: '策略拒绝',
}

function statusBadge(s: string) {
  switch (s) {
    case 'done':
      return <Badge variant="success">已完成</Badge>
    case 'failed':
    case 'pending':
      return <Badge variant="destructive">{STATUS_LABEL[s]}</Badge>
    case 'dead':
      return <Badge variant="secondary">{STATUS_LABEL[s]}</Badge>
    default:
      return <Badge variant="outline">{STATUS_LABEL[s] ?? s}</Badge>
  }
}

type Dialog =
  | { kind: 'retry' | 'resolve'; op: MergeOperation }
  | { kind: 'impact'; op: MergeOperation }
  | null

export default function MergesPage() {
  const [apps, setApps] = useState<Application[]>([])
  const [appId, setAppId] = useState<number | ''>('')
  const [status, setStatus] = useState('')
  const [userId, setUserId] = useState('')

  const [rows, setRows] = useState<MergeOperation[]>([])
  const [total, setTotal] = useState(0)
  const [impact, setImpact] = useState<MergeImpact | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  useEffect(() => {
    AppsApi.list()
      .then((r) => setApps(r.items ?? []))
      .catch(() => {
        /* 拉不到应用列表时仍可按 user_id 查 */
      })
  }, [])

  const load = async () => {
    setLoading(true)
    setErr(null)
    setNotice(null)
    try {
      const r = await MergesApi.list({
        app_id: appId === '' ? undefined : Number(appId),
        status: status || undefined,
        user_id: userId || undefined,
        page_size: 50,
      })
      setRows(r.items ?? [])
      setTotal(r.total ?? 0)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const openImpact = async (op: MergeOperation) => {
    setImpact(null)
    setDialog({ kind: 'impact', op })
    try {
      const r = await MergesApi.impact(op.id)
      setImpact(r.impact)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">合并运维</h1>
        <p className="text-sm text-muted-foreground">
          跨服务合并的三次事务落在这里。retry 会复用原幂等键重放第 2~3 步，
          不会让用户中心重复迁移数据。
        </p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
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
                    {a.Name}（{a.AppCode}）
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label>状态</Label>
              <select
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              >
                <option value="">全部</option>
                <option value="pending">待推进</option>
                <option value="failed">失败（可补偿）</option>
                <option value="dead">需人工处理</option>
                <option value="done">已完成</option>
                <option value="rejected">策略拒绝</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <Label>账号（任一侧）</Label>
              <Input
                placeholder="external_user_id"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <Button className="w-full" onClick={load} disabled={loading}>
                {loading ? '查询中…' : '查询'}
              </Button>
            </div>
          </div>
          {err ? <div className="mt-3 text-sm text-destructive">{err}</div> : null}
          {notice ? <div className="mt-3 text-sm text-green-600">{notice}</div> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">合并操作</CardTitle>
          <CardDescription>共 {total} 条（最多展示 50 条）</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>目标账号</TableHead>
                <TableHead>源账号</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>尝试</TableHead>
                <TableHead>更新时间</TableHead>
                <TableHead>失败原因</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
                    没有合并记录
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell className="font-mono">{m.id}</TableCell>
                    <TableCell className="font-mono text-xs">{m.target_user_id}</TableCell>
                    <TableCell className="font-mono text-xs">{m.source_user_id}</TableCell>
                    <TableCell>{statusBadge(m.status)}</TableCell>
                    <TableCell>{m.attempts}</TableCell>
                    <TableCell className="text-xs">{fmtTime(m.updated_at)}</TableCell>
                    <TableCell className="text-xs max-w-[240px] truncate" title={m.last_error}>
                      {m.last_error || '—'}
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap space-x-1">
                      <Button size="sm" variant="ghost" onClick={() => openImpact(m)}>
                        影响面
                      </Button>
                      {m.status === 'done' ? null : (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setDialog({ kind: 'retry', op: m })}
                          >
                            重试
                          </Button>
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => setDialog({ kind: 'resolve', op: m })}
                          >
                            人工收尾
                          </Button>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <FormDialog
        open={dialog?.kind === 'retry'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="重放合并"
        description={`合并 #${dialog?.kind === 'retry' ? dialog.op.id : ''}：会复用原幂等键重放远端调用与本地收敛。用户中心若已合并过，会幂等命中不会重复迁移。`}
        submitLabel="确认重试"
        onSubmit={async (_v, reason) => {
          if (dialog?.kind !== 'retry') return
          await MergesApi.retry(dialog.op.id, reason)
          setNotice(`合并 #${dialog.op.id} 已重试`)
          setDialog(null)
          await load()
        }}
      />

      <FormDialog
        open={dialog?.kind === 'resolve'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="标记人工已处理"
        description="置为 dead（停止自动补偿），而不是 done——done 会被下游当成「合并成功」，那是谎报。"
        submitLabel="确认收尾"
        onSubmit={async (_v, reason) => {
          if (dialog?.kind !== 'resolve') return
          await MergesApi.resolve(dialog.op.id, reason)
          setNotice(`合并 #${dialog.op.id} 已标记人工处理`)
          setDialog(null)
          await load()
        }}
      />

      <FormDialog
        open={dialog?.kind === 'impact'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="影响面预估"
        description="执行前先看清会动多少数据，供二次确认。"
        requireReason={false}
        submitLabel="关闭"
        onSubmit={() => setDialog(null)}
      >
        {impact ? (
          <div className="rounded-md border p-3 text-sm space-y-1">
            <div>
              将改挂绑定：<span className="font-semibold">{impact.Bindings}</span> 条
            </div>
            <div>
              将撤销令牌：<span className="font-semibold">{impact.Tokens}</span> 条
            </div>
            <div>
              涉及平台：
              {impact.Identities.length === 0
                ? ' —'
                : impact.Identities.map((x) => (
                    <Badge key={x} variant="outline" className="ml-1">
                      {x}
                    </Badge>
                  ))}
            </div>
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">加载中…</div>
        )}
      </FormDialog>
    </div>
  )
}
