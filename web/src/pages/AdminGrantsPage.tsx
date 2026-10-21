// src/pages/AdminGrantsPage.tsx — K 组：管理员授权。
//
// 这一页只对 super_admin 可见（admin:grant）。它管的是"谁能进管理端、能做什么"，
// 因此界面上刻意把两件事说清楚：
//   1. grants 是 admin_users.role 之外的【附加授权】，两者取并集
//   2. 撤销立即生效（鉴权每请求都从库读 User+Grants），不需要对方重新登录

import { useEffect, useState } from 'react'

import { GrantsApi } from '@/lib/api'
import { can, useMe } from '@/lib/auth'
import type { AdminGrant } from '@/lib/types'
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
  | { kind: 'grant' }
  | { kind: 'revoke'; grant: AdminGrant }
  | null

const ROLES = [
  { label: 'viewer（只读）', value: 'viewer' },
  { label: 'operator（只读 + 会话/绑定运维 + 合并重试）', value: 'operator' },
  { label: 'config_admin（只读 + 应用/渠道/密钥/事件写）', value: 'config_admin' },
  { label: 'super_admin（全部，含授权）', value: 'super_admin' },
]

export default function AdminGrantsPage() {
  const { me } = useMe()
  const canGrant = can(me, 'admin:grant')
  const [subjectId, setSubjectId] = useState('')
  const [includeRevoked, setIncludeRevoked] = useState(false)
  const [rows, setRows] = useState<AdminGrant[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  const load = async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await GrantsApi.list({
        subject_id: subjectId || undefined,
        include_revoked: includeRevoked || undefined,
        page_size: 100,
      })
      setRows(r.items ?? [])
      setTotal(r.total ?? 0)
    } catch (e) {
      // 403 时说明当前账号不是 super_admin，提示要直白。
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">管理员授权</h1>
          <p className="text-sm text-muted-foreground">
            在基础角色之外追加授权，支持临时授权（到期自动失效）与按应用限定。
            与 admin_users.role 取并集，不会削减原有权限。
          </p>
        </div>
        <Button
          onClick={() => setDialog({ kind: 'grant' })}
          disabled={!canGrant}
          title={canGrant ? '' : '需要 admin:grant（仅 super_admin）'}
        >
          授予角色
        </Button>
      </div>

      <Alert>
        grants 只做「加法」：判定权限时取 <span className="font-mono">role ∪ grants</span>。
        撤销 grant 立即生效——鉴权中间件每个请求都从库读 User 与 Grants，
        不需要对方重新登录。本页需要 <span className="font-mono">admin:grant</span>，
        通常只有 super_admin 拥有。
      </Alert>

      {!canGrant ? (
        <Alert variant="destructive">
          当前角色没有 admin:grant 权限，本页只能查看。授权入口仅对 super_admin 开放。
        </Alert>
      ) : null}

      {err ? <div className="text-sm text-destructive">{err}</div> : null}
      {notice ? <div className="text-sm text-green-600">{notice}</div> : null}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">授权列表</CardTitle>
          <CardDescription>共 {total} 条</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
            <div className="space-y-1.5">
              <Label>主体（subject_id）</Label>
              <Input
                placeholder="admin:1"
                value={subjectId}
                onChange={(e) => setSubjectId(e.target.value)}
              />
            </div>
            <div className="flex items-end gap-2">
              <label className="flex items-center gap-2 text-sm h-9">
                <input
                  type="checkbox"
                  checked={includeRevoked}
                  onChange={(e) => setIncludeRevoked(e.target.checked)}
                />
                含已撤销
              </label>
            </div>
            <div className="flex items-end">
              <Button className="w-full" onClick={load} disabled={loading}>
                {loading ? '查询中…' : '查询'}
              </Button>
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>主体</TableHead>
                <TableHead>角色</TableHead>
                <TableHead>限定应用</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>授予人</TableHead>
                <TableHead>授予时间</TableHead>
                <TableHead>到期</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                    没有授权记录（所有管理员当前只按 admin_users.role 判定）
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell className="font-mono">{g.id}</TableCell>
                    <TableCell className="font-mono text-xs">{g.subject_id}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{g.role}</Badge>
                    </TableCell>
                    <TableCell className="text-xs">
                      {g.scope_app_id ?? '全局'}
                    </TableCell>
                    <TableCell>
                      {g.revoked_at ? (
                        <Badge variant="secondary">已撤销</Badge>
                      ) : g.effective ? (
                        <Badge variant="success">生效中</Badge>
                      ) : (
                        <Badge variant="secondary">已过期</Badge>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{g.granted_by}</TableCell>
                    <TableCell className="text-xs">{fmtTime(g.granted_at)}</TableCell>
                    <TableCell className="text-xs">
                      {g.expires_at ? fmtTime(g.expires_at) : '长期'}
                    </TableCell>
                    <TableCell className="text-right">
                      {g.revoked_at ? null : (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setDialog({ kind: 'revoke', grant: g })}
                        >
                          撤销
                        </Button>
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
        open={dialog?.kind === 'grant'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="授予角色"
        description="受授主体必须是已存在的本地管理员账号（形如 admin:<id>）。留空到期时间为长期授权。"
        fields={[
          {
            name: 'subject_id',
            label: '主体',
            required: true,
            placeholder: 'admin:2',
            hint: 'admin_users.id 的字符串形式',
          },
          {
            name: 'role',
            label: '角色',
            required: true,
            options: ROLES,
          },
          {
            name: 'expires_at',
            label: '到期时间（可选）',
            type: 'datetime-local',
            hint: '临时授权填未来时间；留空为长期',
          },
        ]}
        submitLabel="确认授予"
        onSubmit={async (v, reason) => {
          const r = await GrantsApi.grant({
            subject_id: v.subject_id,
            role: v.role,
            expires_at: v.expires_at || undefined,
            reason,
          })
          setNotice(`已授予 ${r.grant.subject_id} 角色 ${r.grant.role}`)
          setDialog(null)
          await load()
        }}
      />

      <FormDialog
        open={dialog?.kind === 'revoke'}
        onOpenChange={(v) => !v && setDialog(null)}
        title="撤销授权"
        description={
          dialog?.kind === 'revoke'
            ? `${dialog.grant.subject_id} 的 ${dialog.grant.role} 授权将被撤销，立即生效。`
            : ''
        }
        destructive
        submitLabel="确认撤销"
        onSubmit={async (_v, reason) => {
          if (dialog?.kind !== 'revoke') return
          await GrantsApi.revoke(dialog.grant.id, reason)
          setNotice(`已撤销授权 #${dialog.grant.id}`)
          setDialog(null)
          await load()
        }}
      />
    </div>
  )
}
