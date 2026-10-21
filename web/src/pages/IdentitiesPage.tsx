// src/pages/IdentitiesPage.tsx — C 组：身份与绑定。
//
// 这一页解决的运维问题：合并过后最常见的一句是"到底谁绑了谁"。
// 没有查询入口时只能连库；没有强制解绑，一次错误的自动合并就只能等下次合并盖住。
//
// 布局：上方查询条件 + 身份列表，选中一行后在下方展开详情
// （基本信息 / claims / 绑定历史），高危操作都在详情里。

import { useEffect, useState } from 'react'

import { AppsApi, IdentitiesApi } from '@/lib/api'
import type {
  Application,
  BindingItem,
  IdentityDetail,
  IdentityItem,
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

type Dialog =
  | { kind: 'unbind'; binding: BindingItem }
  | { kind: 'transfer'; binding: BindingItem }
  | null

export default function IdentitiesPage() {
  const [apps, setApps] = useState<Application[]>([])
  const [appId, setAppId] = useState<number | ''>('')
  const [platform, setPlatform] = useState('')
  const [openId, setOpenId] = useState('')
  const [externalUserId, setExternalUserId] = useState('')

  const [rows, setRows] = useState<IdentityItem[]>([])
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState<IdentityDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  useEffect(() => {
    AppsApi.list()
      .then((r) => {
        setApps(r.items ?? [])
        if (r.items?.length && appId === '') setAppId(r.items[0].ID)
      })
      .catch(() => {
        /* 应用列表拉不到不影响查询：用户仍可手填 app_id */
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const search = async () => {
    setLoading(true)
    setErr(null)
    setNotice(null)
    try {
      const r = await IdentitiesApi.list({
        app_id: appId === '' ? undefined : Number(appId),
        platform: platform || undefined,
        open_id: openId || undefined,
        external_user_id: externalUserId || undefined,
        page_size: 50,
      })
      setRows(r.items ?? [])
      setTotal(r.total ?? 0)
      setSelected(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const openDetail = async (idn: IdentityItem) => {
    setErr(null)
    try {
      setSelected(await IdentitiesApi.get(idn.id, idn.app_id))
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const reloadDetail = async () => {
    if (!selected) return
    try {
      setSelected(await IdentitiesApi.get(selected.identity.id, selected.identity.app_id))
      await search()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">身份与绑定</h1>
        <p className="text-sm text-muted-foreground">
          按应用 / 平台 / openid / 账号多维查询三方身份，查看其 claims 与绑定历史。
          强制解绑与 transfer 都会通知业务方（写 binding.removed 事件）。
        </p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">查询条件</CardTitle>
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
              <Label>平台</Label>
              <Input
                placeholder="wechat / alipay / apple"
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>OpenID</Label>
              <Input value={openId} onChange={(e) => setOpenId(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>业务账号</Label>
              <Input
                placeholder="external_user_id"
                value={externalUserId}
                onChange={(e) => setExternalUserId(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <Button className="w-full" onClick={search} disabled={loading}>
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
          <CardTitle className="text-base">身份列表</CardTitle>
          <CardDescription>共 {total} 条（最多展示 50 条）</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>应用</TableHead>
                <TableHead>平台</TableHead>
                <TableHead>OpenID</TableHead>
                <TableHead>归并键</TableHead>
                <TableHead>最近登录</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    没有匹配的身份
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-mono">{r.id}</TableCell>
                    <TableCell>{r.app_id}</TableCell>
                    <TableCell>{r.platform}</TableCell>
                    <TableCell className="font-mono text-xs max-w-[220px] truncate">
                      {r.open_id}
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-[160px] truncate">
                      {r.identity_key}
                    </TableCell>
                    <TableCell className="text-xs">{fmtTime(r.last_login_at)}</TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="outline" onClick={() => openDetail(r)}>
                        详情
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {selected ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">
              身份 #{selected.identity.id} 详情
            </CardTitle>
            <CardDescription>
              {selected.identity.platform} · openid {selected.identity.open_id}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="text-sm font-medium mb-2">Claims（仅展示哈希前缀）</div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>类型</TableHead>
                    <TableHead>哈希前缀</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>已验证</TableHead>
                    <TableHead>创建时间</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {selected.claims.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground py-4">
                        该身份没有可用凭证
                      </TableCell>
                    </TableRow>
                  ) : (
                    selected.claims.map((c) => (
                      <TableRow key={c.id}>
                        <TableCell>{c.claim_type}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {c.value_hash_prefix ?? '—'}
                        </TableCell>
                        <TableCell className="text-xs">{c.source}</TableCell>
                        <TableCell>
                          {c.verified ? (
                            <Badge variant="success">已验证</Badge>
                          ) : (
                            <Badge variant="secondary">未验证</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">{fmtTime(c.created_at)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            <div>
              <div className="text-sm font-medium mb-2">绑定历史</div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>账号</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>绑定时间</TableHead>
                    <TableHead>解绑时间</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {selected.bindings.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center text-muted-foreground py-4">
                        该身份没有绑定记录
                      </TableCell>
                    </TableRow>
                  ) : (
                    selected.bindings.map((b) => (
                      <TableRow key={b.id}>
                        <TableCell className="font-mono">{b.id}</TableCell>
                        <TableCell className="font-mono text-xs">{b.external_user_id}</TableCell>
                        <TableCell>
                          {b.status === 'active' ? (
                            <Badge variant="success">生效</Badge>
                          ) : (
                            <Badge variant="secondary">已解绑</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">{b.bind_source}</TableCell>
                        <TableCell className="text-xs">{fmtTime(b.bound_at)}</TableCell>
                        <TableCell className="text-xs">{fmtTime(b.unbound_at)}</TableCell>
                        <TableCell className="text-right space-x-2">
                          {b.status === 'active' ? (
                            <>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => setDialog({ kind: 'transfer', binding: b })}
                              >
                                转移
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => setDialog({ kind: 'unbind', binding: b })}
                              >
                                强制解绑
                              </Button>
                            </>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <FormDialog
        open={dialog?.kind === 'unbind'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="强制解绑"
        description="解绑后该渠道无法再用于登录该账号。会同时写入 binding.removed 事件通知业务方。"
        destructive
        submitLabel="确认解绑"
        onSubmit={async (_v, reason) => {
          if (dialog?.kind !== 'unbind') return
          await IdentitiesApi.forceUnbind(
            dialog.binding.id,
            reason,
            dialog.binding.app_id,
          )
          setNotice(`已解绑绑定 #${dialog.binding.id}`)
          setDialog(null)
          await reloadDetail()
        }}
      />

      <FormDialog
        open={dialog?.kind === 'transfer'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="转移绑定（transfer 旁路）"
        description="把该身份从当前账号转到目标账号，原账号保留。与合并不同：不迁移账号数据、不撤销令牌。"
        fields={[
          {
            name: 'target_user_id',
            label: '目标账号',
            required: true,
            placeholder: 'external_user_id',
            hint: '转移后该渠道登录会落到这个账号',
          },
        ]}
        submitLabel="确认转移"
        destructive
        onSubmit={async (v, reason) => {
          if (dialog?.kind !== 'transfer') return
          await IdentitiesApi.transfer(
            dialog.binding.id,
            v.target_user_id,
            reason,
            dialog.binding.app_id,
          )
          setNotice(`绑定 #${dialog.binding.id} 已转到 ${v.target_user_id}`)
          setDialog(null)
          await reloadDetail()
        }}
      />
    </div>
  )
}
