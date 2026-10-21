// src/pages/SigningKeysPage.tsx — F 组：签名密钥轮换。
//
// 把 §8.3 的四步轮换变成两个按钮：
//   rotate  新密钥开始签名，旧密钥继续发布在 JWKS（第 1·2 步）
//   retire  下线旧密钥（第 3·4 步，后端强制"旧 token 已过期"前置校验）
//
// 界面上必须让"为什么现在不能下线"可见：retire 被拒时后端返回
// retirable_at 与 wait_seconds，直接展示，不要让运维反复点。

import { useEffect, useState } from 'react'

import { SigningKeysApi } from '@/lib/api'
import type { SigningKeyInfo } from '@/lib/types'
import { fmtTime } from '@/lib/utils'
import FormDialog from '@/components/FormDialog'
import { Alert } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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

type Dialog =
  | { kind: 'rotate' }
  | { kind: 'retire'; kid: string }
  | { kind: 'jwks' }
  | null

export default function SigningKeysPage() {
  const [rows, setRows] = useState<SigningKeyInfo[]>([])
  const [jwks, setJwks] = useState<unknown>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  const load = async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await SigningKeysApi.list()
      setRows(r.items ?? [])
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const openJwks = async () => {
    setDialog({ kind: 'jwks' })
    setJwks(null)
    try {
      setJwks(await SigningKeysApi.jwksPreview())
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">签名密钥</h1>
          <p className="text-sm text-muted-foreground">
            业务方用 JWKS 公钥本地验签。轮换分两步：先 rotate（新旧公钥并存），
            等旧 token 过期后再 retire。
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={openJwks}>
            预览 JWKS
          </Button>
          <Button onClick={() => setDialog({ kind: 'rotate' })}>轮换密钥</Button>
        </div>
      </div>

      <Alert>
        提前下线旧密钥会让所有用它签发的 token 立刻验签失败。因此 retire
        由服务端强制校验「旧 token 已过期」，被拒时会给出可下线时间。
      </Alert>

      {err ? <div className="text-sm text-destructive">{err}</div> : null}
      {notice ? <div className="text-sm text-green-600">{notice}</div> : null}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">密钥列表</CardTitle>
          <CardDescription>共 {rows.length} 把（含仅发布公钥的旧密钥）</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>KID</TableHead>
                <TableHead>算法</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>创建时间</TableHead>
                <TableHead>停止签名</TableHead>
                <TableHead>可下线时间</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    {loading ? '加载中…' : '暂无密钥'}
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((k) => (
                  <TableRow key={k.kid}>
                    <TableCell className="font-mono text-xs">{k.kid}</TableCell>
                    <TableCell className="text-xs">{k.algorithm}</TableCell>
                    <TableCell>
                      {k.status === 'signing' ? (
                        <Badge variant="success">当前签名</Badge>
                      ) : (
                        <Badge variant="secondary">仅发布</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">{fmtTime(k.created_at)}</TableCell>
                    <TableCell className="text-xs">{fmtTime(k.demoted_at)}</TableCell>
                    <TableCell className="text-xs">{fmtTime(k.retirable_at)}</TableCell>
                    <TableCell className="text-right">
                      {k.status === 'published' ? (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setDialog({ kind: 'retire', kid: k.kid })}
                        >
                          下线
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground">轮换后可下线</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <FormDialog
        open={dialog?.kind === 'rotate'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="轮换签名密钥"
        description="生成新密钥并立即用于签名；旧密钥继续发布在 JWKS，直到你执行下线。业务方若实现「kid 未命中时刷新一次 JWKS」，切换是无感的。"
        submitLabel="确认轮换"
        onSubmit={async (_v, reason) => {
          const r = await SigningKeysApi.rotate(reason)
          setNotice(
            `已切换到新密钥 ${r.new_kid}；JWKS 当前发布 ${r.published_keys} 把公钥。` +
              (r.retirable_at ? ` 旧密钥最早可于 ${fmtTime(r.retirable_at)} 下线。` : ''),
          )
          setDialog(null)
          await load()
        }}
      />

      <FormDialog
        open={dialog?.kind === 'retire'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="下线旧密钥"
        description="从 JWKS 移除该公钥。此后用它签发的 token 将验签失败——请确认已过 retirable_at。"
        destructive
        submitLabel="确认下线"
        onSubmit={async (_v, reason) => {
          if (dialog?.kind !== 'retire') return
          try {
            await SigningKeysApi.retire(dialog.kid, reason)
            setNotice(`已下线密钥 ${dialog.kid}`)
            setDialog(null)
            await load()
          } catch (e) {
            // 后端在"旧 token 未过期"时会返回 retirable_at / wait_seconds，
            // 原样展示比"操作失败"有用得多。
            setErr((e as Error).message)
            throw e
          }
        }}
      />

      <FormDialog
        open={dialog?.kind === 'jwks'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="JWKS 预览"
        description="与 GET /v1/jwks 完全一致，轮换后用来核对新旧公钥是否都在。"
        requireReason={false}
        submitLabel="关闭"
        onSubmit={() => setDialog(null)}
      >
        <pre className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
          {jwks ? JSON.stringify(jwks, null, 2) : '加载中…'}
        </pre>
      </FormDialog>
    </div>
  )
}
