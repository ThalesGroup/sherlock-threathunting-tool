/** Formatting helpers shared by the screens. Pure functions, no DOM except downloads. */

import type { HuntStatus } from '@/lib/api'

export function formatDate(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
}

export function formatShort(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' })
}

export function formatDay(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' })
}

export function formatTime(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleTimeString('en-GB')
}

export function formatWindow(window: string | null): string {
  if (!window) return 'default window'
  const ends = window.split('->').map((part) => part.trim())
  if (ends.length !== 2) return window
  return `${formatDay(ends[0])} to ${formatDay(ends[1])}`
}

export function formatDuration(seconds: number): string {
  const minutes = Math.floor(seconds / 60)
  const rest = Math.round(seconds % 60)
  return minutes > 0 ? `${minutes} min ${rest} s` : `${rest} s`
}

const SOURCE_LABELS: Record<string, string> = {
  sentinel: 'Sentinel',
  defender: 'Defender',
  secops: 'SecOps',
}

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source
}

export function firstLine(text: string): string {
  return (
    text
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.length > 0) ?? ''
  )
}

/** "m.dubois" -> "MD", "robin" -> "R". */
export function initials(name: string): string {
  const parts = name.split(/[._\s-]+/).filter(Boolean)
  if (parts.length === 0) return '?'
  if (parts.length === 1) return parts[0].slice(0, 1).toUpperCase()
  return (parts[0].slice(0, 1) + parts[parts.length - 1].slice(0, 1)).toUpperCase()
}

const AVATAR_TONES = ['#0d1e33', '#a8560b', '#1f6f5c', '#0a5f9e', '#5b6b7c']

/** Stable colour per analyst name, from the palette. */
export function avatarTone(name: string): string {
  let hash = 0
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return AVATAR_TONES[hash % AVATAR_TONES.length]
}

export const WAITING_STATUSES: HuntStatus[] = [
  'awaiting_ioc_validation',
  'awaiting_plan_validation',
  'awaiting_review',
]

export function isWaiting(hunt: { status: HuntStatus }): boolean {
  return WAITING_STATUSES.includes(hunt.status)
}


export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return count === 1 ? singular : pluralForm
}

export function downloadText(filename: string, content: string): void {
  downloadBlob(filename, new Blob([content], { type: 'text/markdown;charset=utf-8' }))
}

export function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
