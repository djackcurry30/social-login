// src/pages/LoginPage.tsx — 登录页。
//
// 设计要点：
//   - 简洁：账号 + 密码 + 提交按钮
//   - 失败按 ApiError.message 显示；防枚举文案由后端固定为"账号或密码错误"
//   - 成功后：setToken + 跳 /apps

import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'

import { AuthApi, setToken } from '@/lib/api'
import { Alert, AlertDescription } from '@/components/ui/alert'
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

export default function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setErr(null)
    if (!username.trim() || !password) {
      setErr('请输入账号和密码')
      return
    }
    setBusy(true)
    try {
      const out = await AuthApi.login({
        username: username.trim(),
        password,
      })
      setToken(out.token)
      navigate('/apps', { replace: true })
    } catch (e) {
      setErr((e as Error).message ?? '登录失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-xl">social-login 管理端</CardTitle>
          <CardDescription>使用本地账号登录</CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="username">账号</Label>
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={busy}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">密码</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={busy}
              />
            </div>
            {err ? (
              <Alert variant="destructive">
                <AlertDescription>{err}</AlertDescription>
              </Alert>
            ) : null}
          </CardContent>
          <CardFooter>
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
                  登录中
                </>
              ) : (
                '登录'
              )}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}