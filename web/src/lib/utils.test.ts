// src/lib/utils.test.ts — cn() helper 测试。

import { describe, expect, it } from 'vitest'

import { cn } from './utils'

describe('cn', () => {
  it('合并多个 class', () => {
    expect(cn('a', 'b')).toBe('a b')
  })

  it('过滤 falsy', () => {
    expect(cn('a', undefined, false, null, '', 'b')).toBe('a b')
  })

  it('去重 tailwind', () => {
    expect(cn('p-2', 'p-4')).toBe('p-4')
  })
})