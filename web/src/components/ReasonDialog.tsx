// src/components/ReasonDialog.tsx — 高危操作的 reason 输入对话框。
//
// 任何 A/B 组写操作都必须填 reason ≥4 字符（后端强制）。
// 这里用受控 form + 客户端校验，把校验失败挡在请求之前，
// 减少无效请求往返。
//
// 用法：
//
//   const [open, setOpen] = useState(false)
//   <Button onClick={() => setOpen(true)}>新建</Button>
//   <ReasonDialog open={open} onOpenChange={setOpen}
//     title="新建应用" require="提交"
//     onSubmit={async (reason) => { await create(reason); }} />

import { useState } from 'react'
import { Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'

interface ReasonDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  /**
   * 多行 body（可选）。例如 secret/rotate 要求输入 new_client_secret。
   * 文本框的提交会以 (reason, body) 形式传给 onSubmit。
   */
  body?: { label: string; placeholder?: string; multiline?: boolean }
  submitLabel?: string
  onSubmit: (reason: string, body?: string) => Promise<void> | void
  destructive?: boolean
}

const MIN_REASON = 4

export default function ReasonDialog(props: ReasonDialogProps) {
  const [reason, setReason] = useState('')
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  if (!props.open) return null

  const reasonOk = reason.trim().length >= MIN_REASON
  const bodyRequired = !!props.body
  const bodyOk = !bodyRequired || body.trim().length > 0
  const canSubmit = reasonOk && bodyOk && !busy

  const handleSubmit = async () => {
    if (!canSubmit) return
    setBusy(true)
    setErr(null)
    try {
      await props.onSubmit(reason.trim(), bodyRequired ? body.trim() : undefined)
      // 成功后关闭
      setReason('')
      setBody('')
      props.onOpenChange(false)
    } catch (e) {
      setErr((e as Error).message ?? '操作失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4"
      onClick={() => props.onOpenChange(false)}
    >
      <Card
        className="w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        <CardHeader>
          <CardTitle className="text-lg">{props.title}</CardTitle>
          {props.description ? (
            <CardDescription>{props.description}</CardDescription>
          ) : null}
        </CardHeader>
        <CardContent className="space-y-3">
          {props.body ? (
            <div className="space-y-1.5">
              <Label htmlFor="reason-dialog-body">{props.body.label}</Label>
              {props.body.multiline ? (
                <Textarea
                  id="reason-dialog-body"
                  rows={3}
                  placeholder={props.body.placeholder}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              ) : (
                <Textarea
                  id="reason-dialog-body"
                  rows={1}
                  placeholder={props.body.placeholder}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              )}
            </div>
          ) : null}

          <div className="space-y-1.5">
            <Label htmlFor="reason-dialog-reason">
              操作原因（≥{MIN_REASON} 字符）
            </Label>
            <Textarea
              id="reason-dialog-reason"
              rows={2}
              placeholder="例：客户验收前准备 / 安全审计整改 / 业务对接"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            {!reasonOk && reason.length > 0 ? (
              <div className="text-xs text-destructive">
                reason 至少 {MIN_REASON} 字符
              </div>
            ) : null}
          </div>

          {err ? (
            <div className="text-sm text-destructive">{err}</div>
          ) : null}
        </CardContent>
        <CardFooter className="justify-end gap-2">
          <Button
            variant="ghost"
            onClick={() => props.onOpenChange(false)}
            disabled={busy}
          >
            取消
          </Button>
          <Button
            variant={props.destructive ? 'destructive' : 'default'}
            disabled={!canSubmit}
            onClick={handleSubmit}
          >
            {busy ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
                处理中
              </>
            ) : (
              (props.submitLabel ?? '提交')
            )}
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}