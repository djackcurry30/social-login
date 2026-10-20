// src/pages/ChannelsPage.tsx — 渠道列表（B 组）。
//
// 第一期先用 /apps 列表 + appId 选择器的方式（避免再加一层 /apps/:id/channels）。
// 也可以直接从 URL ?app_id=:id 解析——下面两种都支持。

import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { AppsApi, ChannelsApi } from '@/lib/api'
import type { Application, ProviderConfig } from '@/lib/types'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import ReasonDialog from '@/components/ReasonDialog'

export default function ChannelsPage() {
  const [search] = useSearchParams()
  const [apps, setApps] = useState<Application[]>([])
  const [appId, setAppId] = useState<number | null>(
    Number(search.get('app_id')) || null,
  )
  const [items, setItems] = useState<ProviderConfig[]>([])
  const [err, setErr] = useState<string | null>(null)

  // 列表 + 新建 + 启停 dialog
  const [createOpen, setCreateOpen] = useState(false)
  const [dialog, setDialog] = useState<
    | { kind: 'enable' | 'disable' | 'verify' | 'rotate' | 'finalize' | 'delete'; id: number }
    | null
  >(null)
  const [verifyResult, setVerifyResult] = useState<{
    id: number
    ok: boolean
    latency_ms: number
    error?: string
  } | null>(null)

  useEffect(() => {
    AppsApi.list().then((r) => setApps(r.items ?? [])).catch(() => setApps([]))
  }, [])

  const load = async () => {
    if (!appId) return
    setErr(null)
    try {
      const out = await ChannelsApi.list(appId)
      setItems(out.items ?? [])
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  useEffect(() => {
    load()
  }, [appId])

  const sortedItems = useMemo(
    () => [...items].sort((a, b) => b.ID - a.ID),
    [items],
  )

  const onCreate = async (reason: string, body?: string) => {
    setErr(null)
    try {
      // 简化：dialog 直接传 client_secret；body 即 new_client_secret
      if (!body) {
        setErr('请输入 client_secret')
        throw new Error('client_secret required')
      }
      await ChannelsApi.create(appId!, {
        app_id: appId!,
        platform: 'generic_oauth2',
        scene: 'web',
        provider_app_id: 'web-client',
        client_secret: body,
        reason,
      })
      await load()
    } catch (e) {
      setErr((e as Error).message)
      throw e
    }
  }

  const onAction = async (kind: string, id: number, reason: string, body?: string) => {
    setErr(null)
    try {
      switch (kind) {
        case 'enable':
          await ChannelsApi.enable(appId!, id, reason)
          break
        case 'disable':
          await ChannelsApi.disable(appId!, id, reason)
          break
        case 'verify': {
          const out = await ChannelsApi.verify(appId!, id, reason)
          setVerifyResult({
            id,
            ok: out.ok,
            latency_ms: out.latency_ms,
            error: out.error,
          })
          break
        }
        case 'rotate':
          if (!body) {
            setErr('请输入新 client_secret')
            throw new Error('client_secret required')
          }
          await ChannelsApi.rotateSecret(appId!, id, body, reason)
          break
        case 'finalize':
          await ChannelsApi.finalizeSecret(appId!, id, reason)
          break
        case 'delete':
          await ChannelsApi.delete(appId!, id, reason)
          break
      }
      await load()
    } catch (e) {
      setErr((e as Error).message)
      throw e
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">渠道配置</h1>
          <p className="text-sm text-muted-foreground">
            选择应用后查看 / 管理其渠道凭据与状态。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select
            value={appId ? String(appId) : ''}
            onValueChange={(v: string) => setAppId(Number(v))}
          >
            <SelectTrigger className="w-56">
              <SelectValue placeholder="选择应用" />
            </SelectTrigger>
            <SelectContent>
              {apps.map((a) => (
                <SelectItem key={a.ID} value={String(a.ID)}>
                  {a.Name} (#{a.ID})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            disabled={!appId}
            onClick={() => setCreateOpen(true)}
          >
            新建渠道
          </Button>
        </div>
      </div>

      {err ? (
        <Card className="border-destructive">
          <CardContent className="text-sm text-destructive py-3">{err}</CardContent>
        </Card>
      ) : null}

      {verifyResult ? (
        <Card
          className={
            verifyResult.ok
              ? 'border-green-300 bg-green-50'
              : 'border-amber-300 bg-amber-50'
          }
        >
          <CardContent className="text-sm py-3">
            <span className="font-medium">
              渠道 #{verifyResult.id} 连通性：
            </span>{' '}
            {verifyResult.ok ? 'OK' : '失败'}（{verifyResult.latency_ms}ms）
            {verifyResult.error ? ` · ${verifyResult.error}` : ''}
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {appId ? `应用 #${appId} 的渠道（${items.length}）` : '请选择应用'}
          </CardTitle>
          <CardDescription>
            凭据在数据库中是密文；secret_cipher_prev 非空表示在轮换过渡期。
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!appId ? (
            <div className="p-6 text-sm text-muted-foreground">尚未选择应用</div>
          ) : sortedItems.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">暂无渠道</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead>平台/场景</TableHead>
                  <TableHead>ProviderAppID</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>轮换过渡</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedItems.map((c) => (
                  <TableRow key={c.ID}>
                    <TableCell className="font-mono">{c.ID}</TableCell>
                    <TableCell className="text-xs">
                      {c.Platform} / {c.Scene}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {c.ProviderAppID}
                    </TableCell>
                    <TableCell>
                      <Badge variant={c.Status === 1 ? 'success' : 'secondary'}>
                        {c.Status === 1 ? '启用' : '停用'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">
                      {c.SecretRotationInProgress ? '过渡中' : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setDialog({ kind: 'verify', id: c.ID })}
                        >
                          校验
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setDialog({ kind: 'rotate', id: c.ID })}
                        >
                          轮换
                        </Button>
                        {c.SecretRotationInProgress ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setDialog({ kind: 'finalize', id: c.ID })}
                          >
                            收尾
                          </Button>
                        ) : null}
                        {c.Status === 1 ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setDialog({ kind: 'disable', id: c.ID })}
                          >
                            停用
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setDialog({ kind: 'enable', id: c.ID })}
                          >
                            启用
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive"
                          onClick={() => setDialog({ kind: 'delete', id: c.ID })}
                        >
                          删除
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ReasonDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="新建渠道配置（generic_oauth2 / web）"
        description="client_secret 仅在创建时入加密库。"
        body={{ label: 'client_secret（明文）', multiline: true }}
        submitLabel="创建"
        onSubmit={onCreate}
      />

      <ReasonDialog
        open={!!dialog && dialog.kind === 'rotate'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="轮换 client_secret"
        description="新 secret 入加密库，旧 secret 移到 prev（过渡期可用）。"
        body={{ label: 'new_client_secret' }}
        submitLabel="轮换"
        onSubmit={(reason, body) => onAction('rotate', dialog!.id, reason, body)}
      />
      <ReasonDialog
        open={!!dialog && dialog.kind === 'finalize'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="收尾：清空 prev"
        destructive
        submitLabel="确认收尾"
        onSubmit={(reason) => onAction('finalize', dialog!.id, reason)}
      />
      <ReasonDialog
        open={!!dialog && dialog.kind === 'verify'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="连通性校验"
        description="调一次 token_url 的 client_credentials。"
        submitLabel="开始校验"
        onSubmit={(reason) => onAction('verify', dialog!.id, reason)}
      />
      <ReasonDialog
        open={!!dialog && dialog.kind === 'enable'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="启用渠道"
        onSubmit={(reason) => onAction('enable', dialog!.id, reason)}
      />
      <ReasonDialog
        open={!!dialog && dialog.kind === 'disable'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="停用渠道"
        destructive
        submitLabel="确认停用"
        onSubmit={(reason) => onAction('disable', dialog!.id, reason)}
      />
      <ReasonDialog
        open={!!dialog && dialog.kind === 'delete'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="删除渠道"
        description="这是软删（status=0 + 不可见）；但仍会写入审计。"
        destructive
        submitLabel="确认删除"
        onSubmit={(reason) => onAction('delete', dialog!.id, reason)}
      />
    </div>
  )
}