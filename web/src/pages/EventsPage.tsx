// src/pages/EventsPage.tsx — G 组：事件投递与死信。
//
// 这一页要回答的问题只有一个："我到底有没有通知到业务方？"
//
// 文案刻意不写成"outbox / dead letter"就完事：进来的不只后端，还有客服、
// 测试、运营。他们需要的是"这东西为什么会停在这、停下来意味着什么、
// 我该点哪个按钮"，而不是术语。
//
// 默认筛选 = dead：这一页的真实用途就是"看有没有卡住的通知"。
// 但统计条把 pending / skipped 也摆出来，避免有人以为"死信 0 就万事大吉"。

import { useEffect, useState, type ReactNode } from 'react'

import { AppsApi, EventsApi } from '@/lib/api'
import { can, useMe } from '@/lib/auth'
import type { Application, EventOutboxItem, EventStatus } from '@/lib/types'
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

type BadgeVariant = 'secondary' | 'success' | 'destructive' | 'outline'

/**
 * 状态字典。
 *
 * hint 会作为 title 悬浮提示：状态名本身不足以让人判断"要不要管"，
 * 而列表里又不能为了解释铺开一列。
 */
const STATUS_META: Record<
  EventStatus,
  { label: string; variant: BadgeVariant; hint: string }
> = {
  pending: {
    label: '待投递',
    variant: 'secondary',
    hint: '排队中，或在等下一次重试。不需要处理，通常在几分钟内走完。',
  },
  sent: { label: '已送达', variant: 'success', hint: '业务方已确认收到。' },
  dead: {
    label: '死信',
    variant: 'destructive',
    hint: '重试耗尽或被对方明确拒收，已停止自动重试。需要人工判断重投还是丢弃。',
  },
  skipped: {
    label: '已跳过',
    variant: 'outline',
    hint: '应用没有配置 webhook_url。这是配置状态、不是故障；配好地址后可重投。',
  },
  discarded: {
    label: '已丢弃',
    variant: 'outline',
    hint: '人工丢弃，理由已记入审计。不会再投递。',
  },
}

/** 可以重投的状态：与后端 adminevent.Retry 的白名单保持一致。 */
const RETRYABLE: EventStatus[] = ['dead', 'skipped', 'discarded']

interface Filters {
  appId: number | ''
  status: string
  eventType: string
  from: string
  to: string
}

const EMPTY: Filters = { appId: '', status: 'dead', eventType: '', from: '', to: '' }

export default function EventsPage() {
  const { me } = useMe()
  const canWrite = can(me, 'event:write')

  const [apps, setApps] = useState<Application[]>([])
  const [filters, setFilters] = useState<Filters>(EMPTY)
  const [rows, setRows] = useState<EventOutboxItem[]>([])
  const [total, setTotal] = useState(0)
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const [detail, setDetail] = useState<EventOutboxItem | null>(null)
  const [dialog, setDialog] = useState<{
    kind: 'retry' | 'discard'
    item: EventOutboxItem
  } | null>(null)

  useEffect(() => {
    AppsApi.list()
      .then((r) => setApps(r.items ?? []))
      .catch(() => {
        /* 应用列表拉不到不阻塞查询：也支持按全部应用查 */
      })
  }, [])

  /** 三档计数：让"死信 0 条"与"根本没投递过"能区分开。 */
  const refreshCounts = async (appId: number | '') => {
    const one = async (status: string) => {
      try {
        const r = await EventsApi.list({
          app_id: appId === '' ? undefined : appId,
          status,
          page_size: 1,
        })
        return r.total ?? 0
      } catch {
        // 计数失败不该让主列表跟着报错：它是辅助信息。
        return 0
      }
    }
    const [pending, dead, skipped] = await Promise.all([
      one('pending'),
      one('dead'),
      one('skipped'),
    ])
    setCounts({ pending, dead, skipped })
  }

  const load = async (f: Filters) => {
    setLoading(true)
    setErr(null)
    setNotice(null)
    try {
      const r = await EventsApi.list({
        app_id: f.appId === '' ? undefined : f.appId,
        status: f.status || undefined,
        event_type: f.eventType || undefined,
        // 后端按 RFC3339 解析。日期选择器给的是 YYYY-MM-DD，
        // 直接传会 400，这里换算成本地时区的整天边界。
        from: f.from ? new Date(`${f.from}T00:00:00`).toISOString() : undefined,
        to: f.to ? new Date(`${f.to}T23:59:59`).toISOString() : undefined,
        page_size: 50,
      })
      setRows(r.items ?? [])
      setTotal(r.total ?? 0)
      void refreshCounts(f.appId)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load(filters)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /** 点统计卡片直接切状态：查死信是这一页最常用的动作。 */
  const jumpTo = (status: string) => {
    const next = { ...filters, status }
    setFilters(next)
    void load(next)
  }

  const openDetail = async (id: number) => {
    try {
      const r = await EventsApi.get(id)
      setDetail(r.event)
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">事件投递</h1>
        <p className="text-sm text-muted-foreground">
          用户登录、绑定、合并之后，本服务要把"发生了什么"通知给你的业务系统。
          这一页查的就是这些通知送出去了没有。
        </p>
      </div>

      {/* ---------------- 概念说明 ---------------- */}
      <Card className="bg-muted/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">一次通知的四个阶段</CardTitle>
          <CardDescription>
            「死信」不是一个额外的功能，它是投递失败之后的最后一站。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <Step
              n="1"
              title="产生"
              desc="用户登录成功，本服务要把“这个用户是谁、从哪个渠道来”告诉你自己的业务系统——你的系统靠它建用户、发新人券、记登录日志。"
            />
            <Step
              n="2"
              title="排队"
              desc="不会当场调你的接口。你的系统正在发版、超时 30 秒，总不能让用户跟着登录失败。所以先写进待投递表，后台循环去送。"
            />
            <Step
              n="3"
              title="重试"
              desc="送不出去会自动重试 5 次，间隔 1 秒 / 10 秒 / 1 分钟 / 10 分钟 / 1 小时。发版、限流、瞬断这类抖动基本都能自愈。"
            />
            <Step
              n="4"
              title="成为死信"
              desc="5 次全失败，或对方明确拒收（返回 4xx，比如签名校验不过、地址写错），就停止重试，状态停在「死信」，等人来看。"
            />
          </div>

          <div className="rounded-md border border-amber-300/70 bg-amber-50 px-3 py-2.5 text-sm text-amber-900">
            <span className="font-medium">为什么要有人管它：因为失败是静默的。</span>
            登录本身成功了，用户拿到了令牌，你的系统却没收到通知——用户能进 App，
            但在你的用户表里查不到他。本服务这边一切正常，用户也感知不到任何错误。
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <div className="rounded-md border p-3">
              <div className="font-medium mb-1">重投（对方修好了）</div>
              <p className="text-muted-foreground">
                接口恢复了、白名单加上了、密钥换对了——原样再送一次。
                <span className="text-foreground">事件 ID 不变</span>，
                你的系统按它去重，所以重投不会让同一条通知被处理两次。
              </p>
            </div>
            <div className="rounded-md border p-3">
              <div className="font-medium mb-1">丢弃（这条不该处理）</div>
              <p className="text-muted-foreground">
                对方不关心这个事件类型，或已经通过别的方式补过了。
                <span className="text-foreground">必须写理由</span>，会进管理端审计。
                丢弃不等于删除，记录还留着。
              </p>
            </div>
          </div>

          <p className="text-xs text-muted-foreground">
            死信数量应该长期接近 0。持续有死信说明对方的 webhook
            配置或接口契约有问题，那要修根因，而不是每天进来点一遍重投。
          </p>
        </CardContent>
      </Card>

      {/* ---------------- 统计 ---------------- */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <CountCard
          label="待投递"
          hint="排队中或等重试"
          value={counts.pending ?? 0}
          onClick={() => jumpTo('pending')}
        />
        <CountCard
          label="死信"
          hint="需要人工处理"
          value={counts.dead ?? 0}
          tone={(counts.dead ?? 0) > 0 ? 'danger' : 'normal'}
          onClick={() => jumpTo('dead')}
        />
        <CountCard
          label="已跳过"
          hint="应用未配 webhook"
          value={counts.skipped ?? 0}
          onClick={() => jumpTo('skipped')}
        />
      </div>

      {/* ---------------- 筛选 ---------------- */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
            <div className="space-y-1.5">
              <Label>应用</Label>
              <select
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                value={filters.appId}
                onChange={(e) =>
                  setFilters((f) => ({
                    ...f,
                    appId: e.target.value ? Number(e.target.value) : '',
                  }))
                }
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
                value={filters.status}
                onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}
              >
                <option value="">全部</option>
                {(Object.keys(STATUS_META) as EventStatus[]).map((s) => (
                  <option key={s} value={s}>
                    {STATUS_META[s].label}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label>事件类型</Label>
              <Input
                placeholder="如 auth.login.succeeded"
                value={filters.eventType}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, eventType: e.target.value }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label>起始日期</Label>
              <Input
                type="date"
                value={filters.from}
                onChange={(e) => setFilters((f) => ({ ...f, from: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label>截止日期</Label>
              <Input
                type="date"
                value={filters.to}
                onChange={(e) => setFilters((f) => ({ ...f, to: e.target.value }))}
              />
            </div>
            <div className="flex items-end gap-2">
              <Button className="flex-1" onClick={() => load(filters)} disabled={loading}>
                {loading ? '查询中…' : '查询'}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  // 重置回默认视图（只看死信）：这是这一页最常用的落点。
                  setFilters(EMPTY)
                  void load(EMPTY)
                }}
              >
                重置
              </Button>
            </div>
          </div>

          {err ? <div className="mt-3 text-sm text-destructive">{err}</div> : null}
          {notice ? <div className="mt-3 text-sm text-green-600">{notice}</div> : null}
        </CardContent>
      </Card>

      {/* ---------------- 列表 ---------------- */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">投递记录</CardTitle>
          <CardDescription>
            共 {total} 条（最多展示 50 条）。列表不带事件内容——单条事件体可能很大，
            点「详情」按需加载。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>事件类型 / 事件 ID</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>尝试</TableHead>
                <TableHead>最后错误</TableHead>
                <TableHead>创建时间</TableHead>
                <TableHead className="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-center text-muted-foreground py-10"
                  >
                    {loading ? '查询中…' : '没有匹配的记录'}
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((e) => {
                  const meta = STATUS_META[e.status]
                  return (
                    <TableRow key={e.id}>
                      <TableCell>
                        <div className="font-mono text-xs">{e.event_type}</div>
                        <div className="font-mono text-[11px] text-muted-foreground">
                          {e.event_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={meta.variant} title={meta.hint}>
                          {meta.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {e.attempts} / 5
                        {e.next_retry_at && e.status === 'pending' ? (
                          <div className="text-[11px] text-muted-foreground">
                            下次 {fmtTime(e.next_retry_at)}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell
                        className="text-xs max-w-[280px] truncate text-muted-foreground"
                        title={e.last_error}
                      >
                        {e.last_error || '—'}
                      </TableCell>
                      <TableCell className="text-xs">{fmtTime(e.created_at)}</TableCell>
                      <TableCell className="text-right space-x-1 whitespace-nowrap">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => openDetail(e.id)}
                        >
                          详情
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={!canWrite || !RETRYABLE.includes(e.status)}
                          title={
                            !canWrite
                              ? '需要 event:write 权限（config_admin 及以上）'
                              : RETRYABLE.includes(e.status)
                                ? '原样再送一次，事件 ID 不变'
                                : '只有死信 / 已跳过 / 已丢弃可以重投'
                          }
                          onClick={() => setDialog({ kind: 'retry', item: e })}
                        >
                          重投
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={
                            !canWrite || e.status === 'sent' || e.status === 'discarded'
                          }
                          title={
                            !canWrite
                              ? '需要 event:write 权限（config_admin 及以上）'
                              : '不再投递这条通知（必须写理由）'
                          }
                          onClick={() => setDialog({ kind: 'discard', item: e })}
                        >
                          丢弃
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* ---------------- 详情 ---------------- */}
      {detail ? (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4"
          onClick={() => setDetail(null)}
        >
          <Card className="w-full max-w-2xl" onClick={(ev) => ev.stopPropagation()}>
            <CardHeader>
              <CardTitle className="text-lg">事件详情</CardTitle>
              <CardDescription>
                <span className="font-mono">{detail.event_id}</span>
                <span className="mx-1.5">·</span>
                {detail.event_type}
                <span className="mx-1.5">·</span>
                schema v{detail.schema_version}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 max-h-[70vh] overflow-y-auto">
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <Field label="状态">
                  <Badge variant={STATUS_META[detail.status].variant}>
                    {STATUS_META[detail.status].label}
                  </Badge>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {STATUS_META[detail.status].hint}
                  </span>
                </Field>
                <Field label="尝试次数">{detail.attempts} / 5</Field>
                <Field label="应用">#{detail.app_id}</Field>
                <Field label="创建时间">{fmtTime(detail.created_at)}</Field>
                <Field label="送达时间">{fmtTime(detail.sent_at)}</Field>
                <Field label="下次重试">{fmtTime(detail.next_retry_at)}</Field>
              </div>

              {detail.last_error ? (
                <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
                  <div className="font-medium mb-1 text-destructive">最后一次失败原因</div>
                  <div className="font-mono text-xs whitespace-pre-wrap break-all">
                    {detail.last_error}
                  </div>
                </div>
              ) : null}

              <div>
                <div className="text-sm font-medium mb-1">事件内容（payload）</div>
                <pre className="rounded-md border bg-muted/40 p-3 text-xs overflow-x-auto">
                  {JSON.stringify(detail.payload ?? {}, null, 2)}
                </pre>
                <p className="text-xs text-muted-foreground mt-1">
                  这就是发给业务方的请求体。字段含义见《事件契约》；schema_version
                  变了说明契约有演进，业务方需要知道怎么解析。
                </p>
              </div>
            </CardContent>
            <div className="flex justify-end gap-2 p-4 pt-0">
              <Button variant="ghost" onClick={() => setDetail(null)}>
                关闭
              </Button>
            </div>
          </Card>
        </div>
      ) : null}

      {/* ---------------- 重投 ---------------- */}
      <FormDialog
        open={dialog?.kind === 'retry'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="重投事件"
        description={
          dialog
            ? `事件 ${dialog.item.event_id} 会原样再送一次：事件 ID 不变，业务方按它去重，不会重复处理。重试次数清零，重新按 1 秒 / 10 秒 / 1 分钟…退避。`
            : ''
        }
        reasonOptional
        submitLabel="确认重投"
        onSubmit={async (_v, reason) => {
          if (!dialog) return
          await EventsApi.retry(dialog.item.id, reason)
          setDialog(null)
          setNotice(
            `已重新排队：${dialog.item.event_type}（${dialog.item.event_id}）。稍后刷新可见结果。`,
          )
          await load(filters)
        }}
      >
        <div className="rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
          重投前先确认对方已经修好。如果对方仍然拒收，这条会立刻重新变成死信——
          那就该去查它的 webhook 配置，而不是反复点重投。
        </div>
      </FormDialog>

      {/* ---------------- 丢弃 ---------------- */}
      <FormDialog
        open={dialog?.kind === 'discard'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="丢弃事件"
        description={
          dialog
            ? `事件 ${dialog.item.event_id}（${dialog.item.event_type}）将不再投递。记录保留，理由进审计。`
            : ''
        }
        destructive
        submitLabel="确认丢弃"
        onSubmit={async (_v, reason) => {
          if (!dialog) return
          await EventsApi.discard(dialog.item.id, reason)
          setDialog(null)
          setNotice(`已丢弃：${dialog.item.event_type}（${dialog.item.event_id}）`)
          await load(filters)
        }}
      >
        <div className="rounded-md border border-amber-300/70 bg-amber-50 p-3 text-xs text-amber-900">
          丢弃意味着业务方永远收不到这条通知。如果只是"暂时不想让它一直失败"，
          更好的做法是让对方修好配置后重投。
        </div>
      </FormDialog>
    </div>
  )
}

function Step({ n, title, desc }: { n: string; title: string; desc: string }) {
  return (
    <div className="rounded-md border bg-background p-3">
      <div className="flex items-center gap-2 mb-1">
        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-[11px] font-medium text-primary-foreground">
          {n}
        </span>
        <span className="text-sm font-medium">{title}</span>
      </div>
      <p className="text-xs text-muted-foreground leading-relaxed">{desc}</p>
    </div>
  )
}

function CountCard({
  label,
  hint,
  value,
  tone = 'normal',
  onClick,
}: {
  label: string
  hint: string
  value: number
  tone?: 'normal' | 'danger'
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'rounded-lg border bg-background p-3 text-left transition-colors hover:bg-accent/50',
        tone === 'danger' ? 'border-destructive/50' : '',
      ].join(' ')}
    >
      <div className="text-xs text-muted-foreground">{label}</div>
      <div
        className={[
          'text-2xl font-semibold tabular-nums',
          tone === 'danger' ? 'text-destructive' : '',
        ].join(' ')}
      >
        {value}
      </div>
      <div className="text-[11px] text-muted-foreground">{hint}</div>
    </button>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm">{children}</div>
    </div>
  )
}
