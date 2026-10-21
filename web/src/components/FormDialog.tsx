// src/components/FormDialog.tsx — 通用表单对话框（高危写操作用）。
//
// 与 ReasonDialog 的分工：
//   ReasonDialog  只收一个 reason（A/B 组写操作）
//   FormDialog    收若干业务字段 + reason（C/D/E/F/K 组）
//
// 为什么统一要求 reason：后端对高危操作强制 reason ≥4 字符（§15.5）。
// 在前端先挡一次，避免"填完一堆字段才被 400 打回"。
//
// 用法：
//   <FormDialog open={open} onOpenChange={setOpen} title="转移绑定"
//     fields={[{ name: 'target_user_id', label: '目标账号', required: true }]}
//     onSubmit={async (v, reason) => { await api.transfer(id, v.target_user_id, reason) }} />

import { useEffect, useState, type ReactNode } from 'react'
import { Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

export interface FieldDef {
  name: string
  label: string
  /** select 的选项；给出即为下拉框 */
  options?: { label: string; value: string }[]
  /** datetime-local 提交时会被转成 RFC3339（后端统一按 RFC3339 解析） */
  type?: 'text' | 'datetime-local' | 'number'
  placeholder?: string
  required?: boolean
  defaultValue?: string
  hint?: string
}

interface FormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  fields?: FieldDef[]
  /** 是否需要 reason 输入（默认 true） */
  requireReason?: boolean
  submitLabel?: string
  destructive?: boolean
  /** 额外的只读内容，例如影响面预估 */
  children?: ReactNode
  onSubmit: (values: Record<string, string>, reason: string) => Promise<void> | void
}

const MIN_REASON = 4

export default function FormDialog(props: FormDialogProps) {
  const { open, onOpenChange, fields = [], requireReason = true } = props
  const [values, setValues] = useState<Record<string, string>>({})
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  // 每次打开重置：否则上一次的输入会残留，容易误提交。
  useEffect(() => {
    if (!open) return
    const init: Record<string, string> = {}
    for (const f of fields) init[f.name] = f.defaultValue ?? ''
    setValues(init)
    setReason('')
    setErr(null)
    setBusy(false)
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!open) return null

  const fieldsOk = fields.every((f) => !f.required || (values[f.name] ?? '').trim() !== '')
  const reasonOk = !requireReason || reason.trim().length >= MIN_REASON
  const canSubmit = fieldsOk && reasonOk && !busy

  const submit = async () => {
    if (!canSubmit) return
    setBusy(true)
    setErr(null)
    try {
      // datetime-local 给的是本地时间字符串，转成 RFC3339 再交给后端。
      const payload: Record<string, string> = {}
      for (const f of fields) {
        const raw = (values[f.name] ?? '').trim()
        if (raw === '') continue
        payload[f.name] =
          f.type === 'datetime-local' ? new Date(raw).toISOString() : raw
      }
      await props.onSubmit(payload, reason.trim())
      onOpenChange(false)
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
      onClick={() => onOpenChange(false)}
    >
      <Card className="w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
        <CardHeader>
          <CardTitle className="text-lg">{props.title}</CardTitle>
          {props.description ? <CardDescription>{props.description}</CardDescription> : null}
        </CardHeader>
        <CardContent className="space-y-3 max-h-[60vh] overflow-y-auto">
          {fields.map((f) => (
            <div key={f.name} className="space-y-1.5">
              <Label htmlFor={`fd-${f.name}`}>
                {f.label}
                {f.required ? <span className="text-destructive ml-0.5">*</span> : null}
              </Label>
              {f.options ? (
                <select
                  id={`fd-${f.name}`}
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm"
                  value={values[f.name] ?? ''}
                  onChange={(e) =>
                    setValues((v) => ({ ...v, [f.name]: e.target.value }))
                  }
                >
                  <option value="">请选择</option>
                  {f.options.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              ) : (
                <Input
                  id={`fd-${f.name}`}
                  type={f.type === 'number' ? 'number' : f.type === 'datetime-local' ? 'datetime-local' : 'text'}
                  placeholder={f.placeholder}
                  value={values[f.name] ?? ''}
                  onChange={(e) =>
                    setValues((v) => ({ ...v, [f.name]: e.target.value }))
                  }
                />
              )}
              {f.hint ? (
                <div className="text-xs text-muted-foreground">{f.hint}</div>
              ) : null}
            </div>
          ))}

          {props.children}

          {requireReason ? (
            <div className="space-y-1.5">
              <Label htmlFor="fd-reason">
                操作原因（≥{MIN_REASON} 字符）
                <span className="text-destructive ml-0.5">*</span>
              </Label>
              <Textarea
                id="fd-reason"
                rows={2}
                placeholder="例：用户申诉该渠道非本人绑定 / 安全审计整改"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
              {!reasonOk && reason.length > 0 ? (
                <div className="text-xs text-destructive">reason 至少 {MIN_REASON} 字符</div>
              ) : null}
            </div>
          ) : null}

          {err ? <div className="text-sm text-destructive whitespace-pre-wrap">{err}</div> : null}
        </CardContent>
        <CardFooter className="justify-end gap-2">
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            取消
          </Button>
          <Button
            variant={props.destructive ? 'destructive' : 'default'}
            disabled={!canSubmit}
            onClick={submit}
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
