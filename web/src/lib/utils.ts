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