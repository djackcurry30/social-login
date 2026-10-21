// src/pages/SessionsPage.tsx — E 组：会话与令牌。
//
// 这一页的典型使用场景是安全事件响应：客服/运维收到"账号被盗"，
// 需要 ① 看清该账号有几条会话 ② 一键踢下线 ③ 事后能证明踢过。
//
// 强制下线返回 effective_window_seconds 必须显示出来：
// 未开启 check_revocation 的调用方仍可能接受旧 access_token 到自然过期，
// 运营对用户说"已下线"时要清楚这句话的准确含义。

import { useEffect, useState } from 'react'

import { AppsApi, SessionsApi } from '@/lib/api'
import type {
  Application,
  RevocationView,
  SessionTokenItem,
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

export default function SessionsPage() {
  const [apps, setApps] = useState<Application[]>([])
  const [appId, setAppId] = useState<number | ''>('')
  const [userId, setUserId] = useState('')
  const [active, setActive] = useState('true')

  const [rows, setRows] = useState<SessionTokenItem[]>([])
  const [total, setTotal] = useState(0)
  const [revocation, setRevocation] = useState<RevocationView | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [offlineOpen, setOfflineOpen] = useState(false)

  useEffect(() => {
    AppsApi.list()
      .then((r) => {
        setApps(r.items ?? [])
        if (r.items?.length && appId === '') setAppId(r.items[0].ID)
      })
      .catch(() => {
        /* 忽略 */
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const load = async () => {
    setLoading(true)
    setErr(null)
    setNotice(null)
    setRevocation(null)
    try {
      const r = await SessionsApi.list({
        app_id: appId === '' ? undefined : Number(appId),
        external_user_id: userId || undefined,
        active: active || undefined,
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

  const checkRevocation = async () => {
    if (appId === '' || !userId) {
      setErr('查询撤销状态需要同时给出应用与账号')
      return
    }
    setErr(null)
    try {
      setRevocation(await SessionsApi.revocation(Number(appId), userId))
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">会话与令牌</h1>
        <p className="text-sm text-muted-foreground">
          按账号查 refresh_token 会话。强制下线会撤销全部 refresh_token
          并写入账号撤销水位，让已签发的 access_token 在强校验下立即失效。
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
            <div className="space-y-1.5 md:col-span-2">
              <Label>账号</Label>
              <Input
                placeholder="external_user_id（查询与下线都以此为入口）"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>状态</Label>
              <select
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                value={active}
                onChange={(e) => setActive(e.target.value)}
              >
                <option value="">全部</option>
                <option value="true">生效中</option>
                <option value="false">已失效</option>
              </select>
            </div>
            <div className="flex items-end gap-2">
              <Button className="flex-1" onClick={load} disabled={loading}>
                {loading ? '查询中…' : '查询'}
              </Button>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button
              variant="destructive"
              size="sm"
              disabled={appId === '' || !userId}
              onClick={() => setOfflineOpen(true)}
            >
              强制下线
            </Button>
            <Button variant="outline" size="sm" onClick={checkRevocation}>
              查撤销状态
            </Button>
            <span className="text-xs text-muted-foreground">
              强制下线与查撤销都作用于「应用 + 账号」整体，不是单条会话
            </span>
          </div>

          {revocation ? (
            <div className="mt-3 rounded-md border p-3 text-sm">
              账号 <span className="font-mono">{revocation.external_user_id}</span>：
              {revocation.revoked_at ? (
                <>
                  当前有撤销水位 <span className="font-semibold">{fmtTime(revocation.revoked_at)}</span>
                  ，该时刻之前签发的 access_token 在强校验下无效。
                </>
              ) : (
                <span className="text-muted-foreground">没有撤销水位（可能已过 TTL 或从未被撤销）</span>
              )}
            </div>
          ) : null}

          {err ? <div className="mt-3 text-sm text-destructive">{err}</div> : null}
          {notice ? <div className="mt-3 text-sm text-green-600">{notice}</div> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">会话列表</CardTitle>
          <CardDescription>
            共 {total} 条（最多展示 50 条）。列表不返回 token_hash——它是「持有即可换令牌」的凭据。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>账号</TableHead>
                <TableHead>设备</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>签发时间</TableHead>
                <TableHead>到期时间</TableHead>
                <TableHead>撤销原因</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    没有匹配的会话
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-mono">{s.id}</TableCell>
                    <TableCell className="font-mono text-xs">{s.external_user_id}</TableCell>
                    <TableCell className="text-xs">{s.device_id || '—'}</TableCell>
                    <TableCell>
                      {s.active ? (
                        <Badge variant="success">生效中</Badge>
                      ) : (
                        <Badge variant="secondary">已失效</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">{fmtTime(s.created_at)}</TableCell>
                    <TableCell className="text-xs">{fmtTime(s.expires_at)}</TableCell>
                    <TableCell className="text-xs">{s.revoked_reason || '—'}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <FormDialog
        open={offlineOpen}
        onOpenChange={setOfflineOpen}
        title="强制下线"
        description={`应用 #${appId} 的账号「${userId}」将撤销全部 refresh_token，并写入撤销水位。已签发的 access_token 在调用方开启 check_revocation 时立即失效。`}
        destructive
        submitLabel="确认下线"
        onSubmit={async (_v, reason) => {
          const r = await SessionsApi.forceOffline(Number(appId), userId, reason)
          // 如实展示生效窗口：不要让运营以为"瞬时全站踢出"。
          setNotice(
            `已撤销 ${r.revoked_tokens} 条会话。未开启强校验的调用方最长仍有 ` +
              `${Math.round(r.effective_window_seconds / 60)} 分钟窗口。`,
          )
          setOfflineOpen(false)
          await load()
        }}
      />
    </div>
  )
}
