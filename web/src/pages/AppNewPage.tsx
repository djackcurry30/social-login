// src/pages/AppNewPage.tsx — 新建应用页（A 组 CreateApp）。
//
// 简化版表单：
//   - name（必填）
//   - reason（必填，≥4 字符，由 dialog 输入）
//   - policy：用前端的默认 policy，可在保存时调 validate 预览警告
//
// 成功后跳到 AppDetailPage 并把明文 app_secret 显示一次（"复制保存"提示）。

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { AppsApi } from '@/lib/api'
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
import ReasonDialog from '@/components/ReasonDialog'

export default function AppNewPage() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [createdSecret, setCreatedSecret] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const submit = async (reason: string) => {
    setErr(null)
    try {
      const out = await AppsApi.create({
        name: name.trim(),
        reason,
      })
      setCreatedSecret(out.app_secret)
      // 跳转到详情页（用 replace，避免 back 又回到这里）
      setTimeout(() => navigate(`/apps/${out.app.ID}`, { replace: true }), 100)
    } catch (e) {
      setErr((e as Error).message)
      throw e // 让 dialog 不关闭（让用户能看到错误）
    }
  }

  return (
    <div className="space-y-4 max-w-xl">
      <div>
        <h1 className="text-2xl font-semibold">新建应用</h1>
        <p className="text-sm text-muted-foreground">
          创建后立即返回明文 app_secret，请妥善保存（仅显示一次）。
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">基本信息</CardTitle>
          <CardDescription>
            name 用于管理端列表展示，可与对接方不同的内部名。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="name">应用名称</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例：物流后台"
            />
          </div>
          {err ? (
            <div className="text-sm text-destructive">{err}</div>
          ) : null}

          {createdSecret ? (
            <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm">
              <div className="font-medium text-amber-900 mb-1">
                创建成功，请立即保存 app_secret：
              </div>
              <code className="block bg-white p-2 rounded font-mono text-xs break-all">
                {createdSecret}
              </code>
            </div>
          ) : null}

          <div className="flex justify-end">
            <Button
              onClick={() => setDialogOpen(true)}
              disabled={!name.trim()}
            >
              创建并填写原因
            </Button>
          </div>
        </CardContent>
      </Card>

      <ReasonDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title="新建应用"
        description="所有写操作都会写入 admin_audit_logs，reason 用于追溯操作背景。"
        submitLabel="创建"
        onSubmit={submit}
      />
    </div>
  )
}