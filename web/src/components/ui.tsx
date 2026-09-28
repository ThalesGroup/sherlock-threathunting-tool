/**
 * Display primitives.
 *
 * Single non-negotiable rule: anything coming from a SIEM or a threat
 * intel source is rendered as inert text. No `dangerouslySetInnerHTML`, no Markdown.
 */

import { useState, type ButtonHTMLAttributes, type ReactNode } from 'react'

import type {
  AnonymizationInfo,
  Confidence,
  HuntStatus,
  Severity,
  Verdict,
} from '@/lib/api'

import { avatarTone, initials } from '@/components/format'
import { IconAlert, IconCheck, IconChevronRight, IconInfo } from '@/components/icons'

/* ------------------------------------------------------------------ surfaces */

export function Glass({
  children,
  className = '',
}: {
  children: ReactNode
  className?: string
}) {
  return <section className={`glass ${className}`}>{children}</section>
}

export function Inner({
  children,
  className = '',
  solid = false,
  id,
}: {
  children: ReactNode
  className?: string
  solid?: boolean
  id?: string
}) {
  return (
    <div id={id} className={`${solid ? 'inner-solid' : 'inner'} ${className}`}>
      {children}
    </div>
  )
}

/* --------------------------------------------------------------------- chips */

type ChipTone = 'default' | 'navy' | 'amber' | 'garnet' | 'mint' | 'indigo' | 'soft' | 'olive'

export function Chip({
  children,
  tone = 'default',
  small = false,
  className = '',
  title,
}: {
  children: ReactNode
  tone?: ChipTone
  small?: boolean
  className?: string
  title?: string
}) {
  const toneClass = tone === 'default' ? '' : `chip-${tone}`
  return (
    <span className={`chip ${toneClass} ${small ? 'chip-sm' : ''} ${className}`} title={title}>
      {children}
    </span>
  )
}

const STATUS_LABELS: Record<HuntStatus, string> = {
  draft: 'Ready to launch',
  awaiting_ioc_validation: 'Indicators to validate',
  awaiting_plan_validation: 'Playbook to validate',
  running: 'Running',
  awaiting_review: 'To review',
  closed: 'Closed',
  interrupted: 'Interrupted',
}

const STATUS_TONES: Record<HuntStatus, ChipTone> = {
  draft: 'indigo',
  awaiting_ioc_validation: 'amber',
  awaiting_plan_validation: 'amber',
  running: 'indigo',
  awaiting_review: 'amber',
  closed: 'soft',
  interrupted: 'garnet',
}

export function statusLabel(status: HuntStatus): string {
  return STATUS_LABELS[status]
}

export function StatusChip({
  status,
  verdict = null,
  small = false,
}: {
  status: HuntStatus
  verdict?: Verdict | null
  small?: boolean
}) {
  if (status === 'closed' && verdict) {
    return (
      <Chip tone="soft" small={small}>
        Closed
        <span style={{ color: VERDICT_COLORS[verdict] }}>{VERDICT_LABELS[verdict]}</span>
      </Chip>
    )
  }
  return (
    <Chip tone={STATUS_TONES[status]} small={small}>
      {STATUS_LABELS[status]}
    </Chip>
  )
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#8f1d1d',
  high: '#a8560b',
  medium: '#7d6510',
  low: '#1f6f5c',
  info: '#5b6b7c',
}

const SEVERITY_TONES: Record<Severity, ChipTone> = {
  critical: 'garnet',
  high: 'amber',
  medium: 'olive',
  low: 'mint',
  info: 'soft',
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function SeverityChip({ severity, small = false }: { severity: Severity; small?: boolean }) {
  return (
    <Chip tone={SEVERITY_TONES[severity]} small={small}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </Chip>
  )
}

/** Round severity marker with the initial letter, used in findings lists. */
export function SeverityMark({ severity }: { severity: Severity }) {
  const tones: Record<Severity, string> = {
    critical: '#f6e1df',
    high: '#f8ebd9',
    medium: '#f3efd8',
    low: '#e0efea',
    info: '#eaeef2',
  }
  return (
    <span
      className="mono inline-flex h-10 w-10 flex-none items-center justify-center rounded-full text-[12px] font-semibold"
      style={{ background: tones[severity], color: SEVERITY_COLORS[severity] }}
      title={severity}
    >
      {severity === 'info' ? 'i' : severity.charAt(0).toUpperCase()}
    </span>
  )
}

export const VERDICT_LABELS: Record<Verdict, string> = {
  benign: 'benign',
  suspicious: 'suspicious',
  escalate: 'escalate',
  inconclusive: 'inconclusive',
}

export const VERDICT_TITLES: Record<Verdict, string> = {
  benign: 'Benign',
  suspicious: 'Suspicious',
  escalate: 'Escalate',
  inconclusive: 'Inconclusive',
}

export const VERDICT_COLORS: Record<Verdict, string> = {
  benign: '#1f6f5c',
  suspicious: '#a8560b',
  escalate: '#8f1d1d',
  inconclusive: '#12212f',
}

const VERDICT_TONES: Record<Verdict, ChipTone> = {
  benign: 'mint',
  suspicious: 'amber',
  escalate: 'garnet',
  inconclusive: 'soft',
}

export function VerdictChip({ verdict, small = false }: { verdict: Verdict; small?: boolean }) {
  return (
    <Chip tone={VERDICT_TONES[verdict]} small={small}>
      {VERDICT_TITLES[verdict]}
    </Chip>
  )
}

export function ConfidenceText({ confidence }: { confidence: Confidence }) {
  return <span className="tech">{confidence} confidence</span>
}

/* -------------------------------------------------------------------- people */

export function Avatar({
  name,
  badge,
  small = false,
  className = '',
}: {
  name: string
  badge?: number
  small?: boolean
  className?: string
}) {
  return (
    <span
      className={`av ${small ? 'av-sm' : ''} ${className}`}
      style={{ background: avatarTone(name) }}
      title={name}
      aria-label={name}
    >
      {initials(name)}
      {badge ? <b>{badge}</b> : null}
    </span>
  )
}

/* ------------------------------------------------------------------- stepper */

export type StepState = 'done' | 'now' | 'todo'

export function Stepper({ steps }: { steps: { label: string; state: StepState }[] }) {
  return (
    <div className="stepper" aria-label="Progress">
      {steps.map((step, index) => (
        <span key={step.label} className="contents">
          {index > 0 ? <span className="step-sep" aria-hidden="true" /> : null}
          <span className={`step ${step.state}`} aria-current={step.state === 'now' ? 'step' : undefined}>
            <span className="n">
              {step.state === 'done' ? <IconCheck size={16} /> : index + 1}
            </span>
            {step.label}
          </span>
        </span>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------- buttons */

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'dark' | 'light' | 'ghost'
  size?: 'md' | 'sm' | 'xs'
  end?: ReactNode
}

export function Btn({ variant = 'dark', size = 'md', end, className = '', children, ...rest }: BtnProps) {
  const sizeClass = size === 'sm' ? 'btn-sm' : size === 'xs' ? 'btn-xs' : ''
  return (
    <button type="button" className={`btn btn-${variant} ${sizeClass} ${className}`} {...rest}>
      {children}
      {end ? <span className="end">{end}</span> : null}
    </button>
  )
}

export function IconBtn({
  label,
  className = '',
  size = 'sm',
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; size?: 'sm' | 'ic' | 'ic-dark' }) {
  const sizeClass = size === 'sm' ? 'sm' : size === 'ic' ? 'ic' : 'ic ic-dark'
  return (
    <button type="button" className={`${sizeClass} ${className}`} aria-label={label} title={label} {...rest}>
      {children}
    </button>
  )
}

/* -------------------------------------------------------------------- blocks */

export function Stat({
  value,
  label,
  tone = 'ink',
}: {
  value: ReactNode
  label: ReactNode
  tone?: 'ink' | 'amber' | 'garnet' | 'mint'
}) {
  const colors = { ink: 'var(--ink)', amber: 'var(--amber)', garnet: 'var(--garnet)', mint: 'var(--mint)' }
  return (
    <div className="flex items-center gap-2.5">
      <span className="text-[30px] font-medium leading-none tracking-tight" style={{ color: colors[tone] }}>
        {value}
      </span>
      <span className="text-[12px] leading-[1.15] text-[var(--slate)]">{label}</span>
    </div>
  )
}

export function Tile({ label, children, className = '' }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={`tile ${className}`}>
      <span className="lbl">{label}</span>
      <div className="mt-2 text-[14px] font-medium">{children}</div>
    </div>
  )
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`mono text-[0.92em] ${className}`}>{children}</span>
}

export function QueryBlock({ query, label }: { query: string; label?: string }) {
  return (
    <div>
      {label ? <div className="tech mb-1.5 uppercase tracking-wide">{label}</div> : null}
      <pre className="code">{query}</pre>
    </div>
  )
}

export function Notice({
  tone = 'soft',
  children,
  role,
}: {
  tone?: 'amber' | 'garnet' | 'mint' | 'soft'
  children: ReactNode
  role?: 'alert' | 'status'
}) {
  const icon =
    tone === 'garnet' || tone === 'amber' ? <IconAlert size={18} /> : <IconInfo size={18} />
  return (
    <div className={`notice notice-${tone}`} role={role}>
      <span className="mt-px flex-none">{icon}</span>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}

export function ErrorNotice({ message, hint }: { message: string; hint?: string | null }) {
  return (
    <Notice tone="garnet" role="alert">
      <p className="font-medium">{message}</p>
      {hint ? <p className="mt-1 text-[13px] text-[var(--slate)]">{hint}</p> : null}
    </Notice>
  )
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string
  children?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className="inner px-8 py-12 text-center">
      <h3>{title}</h3>
      {children ? <p className="mx-auto mt-2 max-w-md text-[var(--slate)]">{children}</p> : null}
      {action ? <div className="mt-5 flex justify-center">{action}</div> : null}
    </div>
  )
}

export function SectionHead({
  title,
  aside,
  className = '',
}: {
  title: ReactNode
  aside?: ReactNode
  className?: string
}) {
  return (
    <div className={`flex flex-wrap items-center justify-between gap-3 ${className}`}>
      <h2>{title}</h2>
      {aside ? <div className="flex items-center gap-2">{aside}</div> : null}
    </div>
  )
}

export function Bar({
  value,
  max,
  tone = 'navy',
  className = '',
}: {
  value: number
  max: number
  tone?: 'navy' | 'accent' | 'amber' | 'garnet'
  className?: string
}) {
  const colors = { navy: 'var(--navy)', accent: 'var(--accent)', amber: 'var(--amber)', garnet: 'var(--garnet)' }
  const ratio = max > 0 ? Math.min(1, value / max) : 0
  return (
    <div className={`bar ${className}`} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max}>
      <span style={{ width: `${Math.round(ratio * 100)}%`, background: colors[tone] }} />
    </div>
  )
}

export function Dots({ value, max, count = 12 }: { value: number; max: number; count?: number }) {
  const lit = max > 0 ? Math.round((Math.min(value, max) / max) * count) : 0
  return (
    <div className="dots" aria-hidden="true">
      {Array.from({ length: count }, (_, index) => (
        <i key={index} className={index < lit ? 'on' : ''} />
      ))}
    </div>
  )
}

/** Ring chart for the coverage by source. */
export function Ring({
  value,
  max,
  label,
  color,
  size = 128,
}: {
  value: number
  max: number
  label: string
  color: string
  size?: number
}) {
  const stroke = Math.round(size / 9)
  const radius = size / 2 - stroke
  const circumference = 2 * Math.PI * radius
  const ratio = max > 0 ? Math.max(0.04, value / max) : 0
  const compact = size < 110
  return (
    <div className="relative flex flex-none items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#ffffff" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${circumference * ratio} ${circumference}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <span className={`absolute font-semibold ${compact ? 'mono text-[15px]' : size > 140 ? 'text-[17px]' : 'text-[14px]'}`}>{compact ? value : label}</span>
      {compact ? null : (
        <span className="absolute -left-1 -top-1 flex h-10 w-10 items-center justify-center rounded-full border border-[var(--rule)] bg-white text-[14px] font-semibold">
          {value}
        </span>
      )}
    </div>
  )
}

export function Disclosure({
  summary,
  children,
  defaultOpen = false,
}: {
  summary: ReactNode
  children: ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div>
      <button
        type="button"
        className="link inline-flex items-center gap-1 text-[13px]"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <IconChevronRight size={14} className={open ? 'rotate-90' : ''} />
        {summary}
      </button>
      {open ? <div className="mt-2">{children}</div> : null}
    </div>
  )
}

/* ---------------------------------------------------------------- data views */

const TOKEN_LABELS: [keyof AnonymizationInfo['tokens'], string][] = [
  ['HOST', 'host(s)'],
  ['USER', 'account(s)'],
  ['IP-INT', 'internal IP(s)'],
  ['DATA', 'free-text fragment(s)'],
]

export function AnonymizationLine({ info }: { info: AnonymizationInfo | null | undefined }) {
  if (!info || !info.tokens) return null
  const parts = TOKEN_LABELS.filter(([key]) => info.tokens[key] > 0).map(
    ([key, label]) => `${info.tokens[key]} ${label}`,
  )
  const semantic =
    info.semantic === 'active'
      ? 'semantic pass active'
      : info.semantic === 'degraded'
        ? 'semantic pass degraded, free text masked'
        : 'semantic pass disabled'
  const color =
    info.semantic === 'degraded' || !info.tokenization
      ? 'var(--amber)'
      : info.semantic === 'active'
        ? 'var(--mint)'
        : 'var(--slate)'
  return (
    <p className="tech" style={{ color }}>
      Sent to the model:{' '}
      {parts.length > 0 ? `${parts.join(' · ')} pseudonymized` : 'no internal identifier'} ·{' '}
      {semantic}
      {info.masked_fields > 0 ? ` · ${info.masked_fields} masked field(s)` : ''}
      {!info.tokenization ? ' · tokenization disabled' : ''}
    </p>
  )
}

const MAX_CELL = 160

function cell(value: unknown): string {
  if (value === null || value === undefined) return ''
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  return text.length > MAX_CELL ? `${text.slice(0, MAX_CELL)}…` : text
}

export function ResultSample({
  columns,
  rows,
  modelRows = [],
  sourceRows,
  defaultOpen = false,
}: {
  columns: string[]
  rows: Record<string, unknown>[]
  modelRows?: Record<string, unknown>[]
  sourceRows: number
  defaultOpen?: boolean
}) {
  const [view, setView] = useState<'analyst' | 'model'>('analyst')
  if (rows.length === 0 || columns.length === 0) return null
  const label =
    rows.length < sourceRows
      ? `View ${rows.length} row(s) of ${sourceRows}`
      : `View ${rows.length === 1 ? 'the row' : `the ${rows.length} rows`}`
  const shown = view === 'model' && modelRows.length > 0 ? modelRows : rows
  return (
    <Disclosure summary={label} defaultOpen={defaultOpen}>
      {modelRows.length > 0 ? (
        <div className="seg mb-2" role="tablist" aria-label="Results view">
          {(
            [
              ['analyst', 'Analyst view (rehydrated)'],
              ['model', 'Sent to the model (pseudonyms)'],
            ] as const
          ).map(([key, text]) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={view === key}
              className={`!h-9 !px-4 !text-[12.5px] ${view === key ? 'on' : ''}`}
              onClick={() => setView(key)}
            >
              {text}
            </button>
          ))}
        </div>
      ) : null}
      <div className="overflow-x-auto rounded-[16px] border border-[var(--rule-soft)] bg-white/90">
        <table className="tbl">
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column} className="tech whitespace-nowrap !py-2">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, index) => (
              <tr key={index}>
                {columns.map((column) => (
                  <td key={column} className="max-w-[24rem] !py-2 align-top">
                    <span className="mono whitespace-pre-wrap break-words text-[11.5px] text-[#3d4d5c]">
                      {cell(row[column])}
                    </span>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Disclosure>
  )
}

export function TruncationNotice({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-[13px] text-[var(--amber)]">
      <IconAlert size={16} className="mt-0.5 flex-none" />
      <span>{children}</span>
    </p>
  )
}
