// src/pages/AppDetailPage.tsx — 应用详情（A 组 EditApp + Policy）。
//
// 含三个 tab：
//   - 基本信息：name、status（启用/停用）、rotate secret
//   - 策略：policy JSON 编辑 + validate dry-run + 保存
//   - 渠道列表：跳转到 /channels?app_id=:id（占位：直接渲染子列表）

import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'

import { AppsApi } from '@/lib/api'
import type { Application, Policy } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import ReasonDialog from '@/components/ReasonDialog'

type DialogKind = 'rotate' | 'update' | 'save-policy' | null

export default function AppDetailPage() {
  const { id } = useParams()
  const appId = Number(id)

  const [app, setApp] = useState<Application | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const [policyText, setPolicyText] = useState('')
  const [warns, setWarns] = useState<string[] | null>(null)
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null)

  const [dialog, setDialog] = useState<DialogKind>(null)

  const load = async () => {
    if (!appId) return
    setLoading(true)
    setErr(null)
    try {
      const out = await AppsApi.get(appId)
      setApp(out.app)
      setPolicyText(JSON.stringify(out.app.Policy, null, 2))
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [appId])

  // 校验策略（dry-run）
  const onValidate = async () => {
    setErr(null)
    try {
      const p = JSON.parse(policyText) as Policy
      const out = await AppsApi.validatePolicy(p)
      setWarns(out.warnings ?? null)
      setPolicyText(JSON.stringify(out.normalized, null, 2))
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const onRotate = async (reason: string) => {
    setErr(null)
    try {
      const out = await AppsApi.rotateSecret(appId, reason)
      setRotatedSecret(out.app_secret)
    } catch (e) {
      setErr((e as Error).message)
      throw e
    }
  }

  const onSavePolicy = async (reason: string) => {
    setErr(null)
    try {
      const p = JSON.parse(policyText) as Policy
      const out = await AppsApi.savePolicy(appId, p, reason)
      setPolicyText(JSON.stringify(out.policy, null, 2))
      setWarns(null)
    } catch (e) {
      setErr((e as Error).message)
      throw e
    }
  }

  if (loading || !app) {
    return <div className="text-sm text-muted-foreground">加载中…</div>
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-2xl font-semibold flex items-center gap-2">
            {app.Name}
            <Badge variant={app.Status === 1 ? 'success' : 'secondary'}>
              {app.Status === 1 ? '启用' : '停用'}
            </Badge>
          </div>
          <div className="text-sm text-muted-foreground font-mono">
            {app.AppCode} · ID={app.ID}
          </div>
        </div>
        <Button variant="destructive" onClick={() => setDialog('rotate')}>
          轮换 app_secret
        </Button>
      </div>

      {rotatedSecret ? (
        <Card className="border-amber-300 bg-amber-50">
          <CardContent className="py-3">
            <div className="text-sm text-amber-900 font-medium">
              新 app_secret（请立即保存，不会再显示）：
            </div>
            <code className="block bg-white p-2 rounded font-mono text-xs mt-1 break-all">
              {rotatedSecret}
            </code>
          </CardContent>
        </Card>
      ) : null}

      {err ? (
        <Card className="border-destructive">
          <CardContent className="text-sm text-destructive py-3">
            {err}
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">策略 policy</CardTitle>
          <CardDescription>
            修改后先"校验"看 warnings，再保存。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            rows={16}
            className="font-mono text-xs"
            value={policyText}
            onChange={(e) => setPolicyText(e.target.value)}
          />
          {warns && warns.length > 0 ? (
            <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm">
              <div className="font-medium text-amber-900">校验告警：</div>
              <ul className="list-disc pl-5 text-amber-800">
                {warns.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onValidate}>
              校验（dry-run）
            </Button>
            <Button onClick={() => setDialog('save-policy')}>保存</Button>
          </div>
        </CardContent>
      </Card>

      <ReasonDialog
        open={dialog === 'rotate'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="轮换 app_secret"
        description="旧 secret 立刻失效，请确认客户端已具备切换能力。"
        destructive
        submitLabel="确认轮换"
        onSubmit={onRotate}
      />

      <ReasonDialog
        open={dialog === 'save-policy'}
        onOpenChange={(o) => !o && setDialog(null)}
        title="保存策略"
        submitLabel="保存"
        onSubmit={onSavePolicy}
      />
    </div>
  )
}