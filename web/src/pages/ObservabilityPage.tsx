// src/pages/ObservabilityPage.tsx — I 组观测看板。

import { useEffect, useState } from 'react'

import { ProvidersApi } from '@/lib/api'
import type {
  OverviewStats,
  ProviderHealth,
  ProviderMetadata,
} from '@/lib/types'
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

export default function ObservabilityPage() {
  const [providers, setProviders] = useState<ProviderMetadata[]>([])
  const [health, setHealth] = useState<ProviderHealth[]>([])
  const [overview, setOverview] = useState<OverviewStats | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    setErr(null)
    try {
      const [p, h, o] = await Promise.all([
        ProvidersApi.list(),
        ProvidersApi.health(),
        ProvidersApi.overview(),
      ])
      setProviders(p.items ?? [])
      setHealth(h.items ?? [])
      setOverview(o)
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
          <h1 className="text-2xl font-semibold">观测看板</h1>
          <p className="text-sm text-muted-foreground">
            渠道健康度与摘要指标。
          </p>
        </div>
        <Button variant="outline" onClick={load} disabled={loading}>
          {loading ? '刷新中…' : '刷新'}
        </Button>
      </div>

      {err ? (
        <Card className="border-destructive">
          <CardContent className="text-sm text-destructive py-3">{err}</CardContent>
        </Card>
      ) : null}

      {overview ? (
        <div className="grid grid-cols-4 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>渠道总数</CardDescription>
              <CardTitle className="text-2xl">{overview.provider_count}</CardTitle>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>应用总数</CardDescription>
              <CardTitle className="text-2xl">{overview.apps_count}</CardTitle>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>健康渠道</CardDescription>
              <CardTitle className="text-2xl text-green-600">
                {overview.healthy_providers}
              </CardTitle>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>异常渠道</CardDescription>
              <CardTitle className="text-2xl text-amber-600">
                {overview.unhealthy_providers}
              </CardTitle>
            </CardHeader>
          </Card>
        </div>
      ) : null}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">已注册渠道（{providers.length}）</CardTitle>
          <CardDescription>
            来自 provider.Global().List()；不含运行时凭据信息。
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>平台</TableHead>
                <TableHead>场景</TableHead>
                <TableHead>名称</TableHead>
                <TableHead>API 版本</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {providers.map((p) => (
                <TableRow key={`${p.Platform}-${p.Scene}`}>
                  <TableCell className="font-mono text-xs">{p.Platform}</TableCell>
                  <TableCell className="text-xs">{p.Scene}</TableCell>
                  <TableCell>{p.DisplayName}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {p.APIVersion}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">健康探测（{health.length}）</CardTitle>
          <CardDescription>
            实际 ping 各渠道的 token_url；本期待 generic_oauth2 默认 SKIP。
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {health.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">无数据</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>平台 / 场景</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>延迟</TableHead>
                  <TableHead>错误</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {health.map((h, i) => (
                  <TableRow key={`${h.platform}-${h.scene}-${i}`}>
                    <TableCell className="text-xs">
                      {h.platform} / {h.scene}
                    </TableCell>
                    <TableCell>
                      <Badge variant={h.ok ? 'success' : 'destructive'}>
                        {h.ok ? 'OK' : '失败'}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {h.latency_ms}ms
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {h.error ?? '—'}
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