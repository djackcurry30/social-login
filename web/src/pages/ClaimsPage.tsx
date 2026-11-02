// src/pages/ClaimsPage.tsx — J 组：凭证一致性。
//
// 这一页解决的用户申诉很具体：「我换了手机号，为什么新号还提示已被占用？」
// 或者在运营侧：「这个人明明两个渠道都是同一个手机号，怎么没合并？」
//
// 背后是两个不同的表在打架：
//
//   identity_claims   "某次授权中，某平台证明过这个身份拥有该手机号"
//                      —— 本服务的记录，平台不会主动撤销
//   用户中心           "这个手机号现在属于哪个账号"
//                      —— 权威源，可能已经变了
//
// 归并时会回源核对（宁可漏归并、不可错归并），核对不一致就拒绝、
// 并在这里留下一条「漂移」。所以：
//
//   漂移 = 有人本该被归并进来，但因为数据不一致被拦住了。
//   数字不为 0 不代表系统出错，代表有一批用户需要人工看一眼。
//
// 页面分两个视图：默认「漂移待处理」（这是要干活的），另一个「全部凭证」
// （这是要查证的）。撤销凭证会顺带闭环它名下的漂移。

import { useEffect, useState } from 'react'

import { AppsApi, ClaimsApi } from '@/lib/api'
import { can, useMe } from '@/lib/auth'
import type {
  Application,
  ClaimItem,
  ClaimMismatch,
  ClaimStatus,
  MismatchKind,
} from '@/lib/types'
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

type Tab = 'drift' | 'claims'

/**
 * 漂移类型字典。
 *
 * label 直说"两边怎么对不上"，hint 说"该怎么办"——
 * 运营看到的不能只是 account_mismatch 这种字符串，也不能只看到中文名却
 * 不知道要做什么。hint 用 title 悬浮展示，避免列表里铺开一列长文案。
 */
const KIND_META: Record<MismatchKind, { label: string; variant: BadgeVariant; hint: string }> = {
  account_not_found: {
    label: '用户中心查无此号',
    variant: 'destructive',
    hint:
      '用户中心说没有任何账号持有这个手机号/邮箱——通常是用户在那里换了号或解绑了。' +
      '本服务的旧记录还在，等于占着号码不让别人用。确认后可撤销该凭证，号码即被释放。',
  },
  account_mismatch: {
    label: '账号归属不一致',
    variant: 'destructive',
    hint:
      '左边的账号是本地绑定认为该凭证属于谁，右边是用户中心说它属于谁。' +
      '两边已经分叉，最需要人工判断：先跟业务方确认真实归属，再决定是撤销凭证还是走合并/转移。',
  },
  multiple_accounts: {
    label: '命中多个账号',
    variant: 'destructive',
    hint:
      '同一个手机号/邮箱在用户中心被两个以上账号占用，属于业务侧脏数据。' +
      '本服务无法判断该归给谁，需要业务方先清理，清理后这条记录可随之闭环。',
  },
  identity_missing: {
    label: '身份已删除',
    variant: 'secondary',
    hint:
      '这条凭证指向的三方身份已经不存在（数据清理或人工删除留下的孤儿）。' +
      '凭证本身已无法用于任何归并，撤销即可。',
  },
}

const CLAIM_STATUS_META: Record<ClaimStatus, { label: string; variant: BadgeVariant }> = {
  verified: { label: '已验证', variant: 'success' },
  unverified: { label: '未验证', variant: 'secondary' },
  revoked: { label: '已撤销', variant: 'outline' },
}

const CLAIM_SOURCE_LABEL: Record<string, string> = {
  wechat_phone: '微信手机号',
  alipay_phone: '支付宝手机号',
  sms_verified: '短信验证',
  apple_email: 'Apple 邮箱',
  manual: '用户手填',
}

type Dialog = { kind: 'revoke'; claimID: number; appId: number; label: string } | null

export default function ClaimsPage() {
  const { me } = useMe()
  // 撤销凭证的权限单独判定：它决定"下次登录会被归并到哪个账号"。
  const canRevoke = can(me, 'identity:write')

  const [apps, setApps] = useState<Application[]>([])
  const [appId, setAppId] = useState<number | ''>('')
  const [claimType, setClaimType] = useState('')
  const [identityId, setIdentityId] = useState('')

  const [tab, setTab] = useState<Tab>('drift')
  const [driftStatus, setDriftStatus] = useState<'open' | 'resolved' | ''>('open')

  const [drift, setDrift] = useState<ClaimMismatch[]>([])
  const [driftTotal, setDriftTotal] = useState(0)
  const [openTotal, setOpenTotal] = useState(0)

  const [claims, setClaims] = useState<ClaimItem[]>([])
  const [claimsTotal, setClaimsTotal] = useState(0)
  const [claimStatus, setClaimStatus] = useState<ClaimStatus | ''>('')

  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  useEffect(() => {
    AppsApi.list()
      .then((r) => setApps(r.items ?? []))
      .catch(() => {
        /* 应用列表拉不到不影响查询：仍可按全部应用查看 */
      })
  }, [])

  const baseQuery = () => ({
    app_id: appId === '' ? undefined : Number(appId),
    claim_type: claimType || undefined,
    identity_id: identityId ? Number(identityId) : undefined,
  })

  const loadDrift = async (status = driftStatus) => {
    setLoading(true)
    setErr(null)
    try {
      const r = await ClaimsApi.mismatches({
        ...baseQuery(),
        status: status || undefined,
        page_size: 50,
      })
      setDrift(r.items ?? [])
      setDriftTotal(r.total ?? 0)
      setOpenTotal(r.open_total ?? 0)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const loadClaims = async (status = claimStatus) => {
    setLoading(true)
    setErr(null)
    try {
      const r = await ClaimsApi.list({
        ...baseQuery(),
        status: status || undefined,
        page_size: 50,
      })
      setClaims(r.items ?? [])
      setClaimsTotal(r.total ?? 0)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const reload = () => (tab === 'drift' ? loadDrift() : loadClaims())

  useEffect(() => {
    // 首屏直接看"有没有要处理的"，这是进这页的唯一理由。
    void loadDrift('open')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const switchTab = (t: Tab) => {
    setTab(t)
    setErr(null)
    setNotice(null)
    if (t === 'drift') void loadDrift()
    else void loadClaims()
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">凭证一致性</h1>
        <p className="text-sm text-muted-foreground">
          查看用于「同一人跨渠道识别」的手机号 / 邮箱凭证，以及登录时回源核对失败的记录。
          核对不一致时系统会拒绝自动归并（宁可漏归并，不可错归并），留下的记录需要人工确认。
        </p>
      </div>

      {/* 未闭环总数是这一页最重要的数字：0 = 没事，非 0 = 有人需要看一眼。 */}
      <div
        className={[
          'rounded-md border px-4 py-3 text-sm',
          openTotal > 0
            ? 'border-destructive/40 bg-destructive/5 text-destructive'
            : 'border-border bg-muted/40 text-muted-foreground',
        ].join(' ')}
      >
        {openTotal > 0 ? (
          <>
            <span className="font-medium">当前有 {openTotal} 条未闭环的凭证漂移。</span>{' '}
            这些用户本该被自动归并到既有账号，但因为本地记录与用户中心对不上被拦住了。
            在下方「漂移待处理」中逐条确认后撤销对应凭证即可释放号码。
          </>
        ) : (
          <>
            <span className="font-medium">暂未发现未闭环的凭证漂移。</span>{' '}
            这只说明本次核对都一致；反过来，长期为 0 而业务侧一直有「同手机号没合并」的反馈时，
            要先确认应用是否开启了 <code className="font-mono">on_login = claim_verified</code>，
            否则核对根本不会发生。
          </>
        )}
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">筛选</CardTitle>
        </CardHeader>
        <CardContent>
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
              <Label>凭证类型</Label>
              <select
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                value={claimType}
                onChange={(e) => setClaimType(e.target.value)}
              >
                <option value="">全部</option>
                <option value="phone">手机号</option>
                <option value="email">邮箱</option>
                <option value="union_id">union_id</option>
                <option value="custom">自定义</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <Label>身份 ID</Label>
              <Input
                placeholder="identity_id"
                value={identityId}
                onChange={(e) => setIdentityId(e.target.value.replace(/[^0-9]/g, ''))}
              />
            </div>
            <div className="space-y-1.5">
              <Label>{tab === 'drift' ? '处理状态' : '凭证状态'}</Label>
              {tab === 'drift' ? (
                <select
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                  value={driftStatus}
                  onChange={(e) => setDriftStatus(e.target.value as 'open' | 'resolved' | '')}
                >
                  <option value="open">未闭环</option>
                  <option value="resolved">已闭环</option>
                  <option value="">全部</option>
                </select>
              ) : (
                <select
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                  value={claimStatus}
                  onChange={(e) => setClaimStatus(e.target.value as ClaimStatus | '')}
                >
                  <option value="">全部</option>
                  <option value="verified">已验证</option>
                  <option value="unverified">未验证</option>
                  <option value="revoked">已撤销</option>
                </select>
              )}
            </div>
            <div className="flex items-end">
              <Button className="w-full" onClick={reload} disabled={loading}>
                {loading ? '查询中…' : '查询'}
              </Button>
            </div>
          </div>
          {err ? <div className="mt-3 text-sm text-destructive">{err}</div> : null}
          {notice ? <div className="mt-3 text-sm text-green-600">{notice}</div> : null}
        </CardContent>
      </Card>

      <div className="flex gap-2">
        <Button
          variant={tab === 'drift' ? 'default' : 'outline'}
          size="sm"
          onClick={() => switchTab('drift')}
        >
          漂移待处理
          {openTotal > 0 ? <span className="ml-1.5 text-xs">（{openTotal}）</span> : null}
        </Button>
        <Button
          variant={tab === 'claims' ? 'default' : 'outline'}
          size="sm"
          onClick={() => switchTab('claims')}
        >
          全部凭证
        </Button>
      </div>

      {tab === 'drift' ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">凭证漂移记录</CardTitle>
            <CardDescription>
              共 {driftTotal} 条（最多展示 50 条）。撤销凭证会同时把该凭证名下的漂移标记为已闭环。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>类型</TableHead>
                  <TableHead>应用</TableHead>
                  <TableHead>凭证</TableHead>
                  <TableHead>本地绑定认为属于</TableHead>
                  <TableHead>用户中心说属于</TableHead>
                  <TableHead>命中</TableHead>
                  <TableHead>最近一次</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {drift.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                      {driftStatus === 'open' ? '没有待处理的漂移' : '没有匹配的记录'}
                    </TableCell>
                  </TableRow>
                ) : (
                  drift.map((m) => {
                    const meta = KIND_META[m.kind] ?? {
                      label: m.kind,
                      variant: 'outline' as BadgeVariant,
                      hint: '',
                    }
                    return (
                      <TableRow key={m.id}>
                        <TableCell>
                          <span title={meta.hint} className="cursor-help">
                            <Badge variant={meta.variant}>{meta.label}</Badge>
                          </span>
                          {m.detail ? (
                            <div className="text-[11px] text-muted-foreground mt-1 max-w-[240px]">
                              {m.detail}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell>{m.app_id}</TableCell>
                        <TableCell className="text-xs">
                          <div>{m.claim_type}</div>
                          <div className="font-mono text-muted-foreground">
                            {m.value_hash_prefix ?? '—'}
                          </div>
                          <div className="text-muted-foreground">
                            来源 {CLAIM_SOURCE_LABEL[m.claim_source] ?? m.claim_source}
                            {m.platform ? ` · ${m.platform}` : ''}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {m.expected_user_id || '—'}
                          <div className="text-muted-foreground">身份 #{m.identity_id}</div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {m.actual_user_id || '—'}
                        </TableCell>
                        <TableCell className="text-xs">
                          {m.occurrences > 1 ? (
                            <span title="每次登录命中都会累加，数值大说明这处漂移长期存在">
                              {m.occurrences} 次
                            </span>
                          ) : (
                            '1 次'
                          )}
                        </TableCell>
                        <TableCell className="text-xs">{fmtTime(m.last_seen_at)}</TableCell>
                        <TableCell>
                          {m.status === 'open' ? (
                            <Badge variant="destructive">未闭环</Badge>
                          ) : (
                            <span title={m.resolution ?? ''}>
                              <Badge variant="outline">已闭环</Badge>
                            </span>
                          )}
                          {m.resolved_by ? (
                            <div className="text-[11px] text-muted-foreground mt-1">
                              {m.resolved_by}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell className="text-right">
                          {m.status === 'open' ? (
                            <Button
                              size="sm"
                              variant="destructive"
                              disabled={!canRevoke}
                              title={
                                canRevoke
                                  ? '撤销这条凭证，号码即被释放；同时闭环该漂移'
                                  : '需要 identity:write 权限（operator 及以上）'
                              }
                              onClick={() =>
                                setDialog({
                                  kind: 'revoke',
                                  claimID: m.claim_id,
                                  appId: m.app_id,
                                  label: `${m.claim_type} ${m.value_hash_prefix ?? ''}`,
                                })
                              }
                            >
                              撤销凭证
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">凭证列表</CardTitle>
            <CardDescription>
              共 {claimsTotal} 条（最多展示 50 条）。只显示哈希前缀——库里本来就不存明文。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>应用</TableHead>
                  <TableHead>身份</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>哈希前缀</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead>撤销时间</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {claims.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={10} className="text-center text-muted-foreground py-8">
                      没有匹配的凭证
                    </TableCell>
                  </TableRow>
                ) : (
                  claims.map((c) => {
                    const st = CLAIM_STATUS_META[c.status] ?? {
                      label: c.status,
                      variant: 'outline' as BadgeVariant,
                    }
                    return (
                      <TableRow key={c.id}>
                        <TableCell className="font-mono">{c.id}</TableCell>
                        <TableCell>{c.app_id}</TableCell>
                        <TableCell className="font-mono text-xs">#{c.identity_id}</TableCell>
                        <TableCell>{c.claim_type}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {c.value_hash_prefix ?? '—'}
                        </TableCell>
                        <TableCell className="text-xs">
                          {CLAIM_SOURCE_LABEL[c.source] ?? c.source}
                        </TableCell>
                        <TableCell>
                          <Badge variant={st.variant}>{st.label}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{fmtTime(c.created_at)}</TableCell>
                        <TableCell className="text-xs">{fmtTime(c.revoked_at)}</TableCell>
                        <TableCell className="text-right">
                          {c.status !== 'revoked' ? (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={!canRevoke}
                              title={canRevoke ? '' : '需要 identity:write 权限（operator 及以上）'}
                              onClick={() =>
                                setDialog({
                                  kind: 'revoke',
                                  claimID: c.id,
                                  appId: c.app_id,
                                  label: `${c.claim_type} ${c.value_hash_prefix ?? ''}`,
                                })
                              }
                            >
                              撤销
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <FormDialog
        open={dialog?.kind === 'revoke'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="撤销凭证"
        description={
          dialog
            ? `凭证：${dialog.label}。撤销后该手机号/邮箱不再作为归并依据，号码可被其他身份重新验证占用；` +
              '该凭证名下的漂移记录会一并标记为已闭环。此操作写审计，不可撤销。'
            : ''
        }
        destructive
        submitLabel="确认撤销"
        onSubmit={async (_v, reason) => {
          if (dialog?.kind !== 'revoke') return
          const r = await ClaimsApi.revoke(dialog.claimID, dialog.appId, reason)
          setNotice(
            r.already_revoked
              ? `凭证 #${dialog.claimID} 此前已被撤销，本次未做改动（已闭环 ${r.resolved_mismatches} 条漂移）`
              : `已撤销凭证 #${dialog.claimID}，闭环 ${r.resolved_mismatches} 条漂移`,
          )
          setDialog(null)
          await reload()
        }}
      />
    </div>
  )
}
