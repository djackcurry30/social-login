// src/lib/utils.ts — cn() 与 shadcn/ui 通用 helper。
//
// 来自 shadcn 模板的官方写法（class-variance-authority + tailwind-merge）：
//
//   cn(...inputs) 会把 falsy 过滤掉 + 对 tailwind class 做去重与合并
//
// 这是 shadcn 推荐的 className 合并方式；不要换成 classnames/dedupe，
// 后两者不会自动解 tailwind 的覆盖关系。

import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
/**
 * fmtTime 把 RFC3339 时间格式化成 `YYYY-MM-DD HH:mm:ss`（本地时区）。
 *
 * 管理端所有时间列都用它：直接显示后端原始字符串会带 `T` 与 `Z`，
 * 运维在列表里扫读时很费眼。
 */
export function fmtTime(v?: string | null): string {
  if (!v) return '—'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return v
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** fmtBytes 把字节数转成易读单位（导出文件大小用）。 */
export function fmtBytes(n?: number | null): string {
  if (!n || n <= 0) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}
