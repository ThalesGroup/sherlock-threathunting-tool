/**
 * Display primitives.
 *
 * Single non-negotiable rule: any content coming from a SIEM or a threat intel source is
 * rendered as inert text. No component in this file uses `dangerouslySetInnerHTML`, and
 * none renders unsanitized Markdown. A log field can contain hostile code placed there on
 * purpose.
 */

import type { ReactNode } from 'react'

import type { Confidence, HuntStatus, Severity, Verdict } from '@/lib/api'

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-[#f7e4e2] text-[#8f1d1d]',
  high: 'bg-[#faeddc] text-[#a8560b]',
  medium: 'bg-[#f6f0d9] text-[#7d6510]',
  low: 'bg-[#e3f0ec] text-[#1f6f5c]',
  info: 'bg-[#eef1f4] text-[#5b6b7c]',
}

/** Accent color per severity (borders, dots), taken from the mockup. */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#8f1d1d',
  high: '#a8560b',
  medium: '#7d6510',
  low: '#1f6f5c',
  info: '#5b6b7c',
}

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
}

const VERDICT_LABELS: Record<Verdict, string> = {
  benign: 'benign',
  suspicious: 'suspicious',
  escalate: 'escalate',
  inconclusive: 'inconclusive',
}

const VERDICT_STYLES: Record<Verdict, string> = {
  benign: 'bg-[#e6f2ec] text-[#146b48]',
  suspicious: 'bg-[#faeddc] text-[#a8560b]',
  escalate: 'bg-[#f7e4e2] text-[#8f1d1d]',
  inconclusive: 'bg-[#eceff2] text-[#4a5a68]',
}

const STATUS_LABELS: Record<HuntStatus, string> = {
  draft: 'ready to launch',
  awaiting_ioc_validation: 'indicators to validate',
  awaiting_plan_validation: 'playbook to validate',
  running: 'running',
  awaiting_review: 'to review',
  closed: 'closed',
  interrupted: 'interrupted',
}

const STATUS_STYLES: Record<HuntStatus, string> = {
  draft: 'bg-[#e2eef7] text-[#0a5f9e]',
  awaiting_ioc_validation: 'bg-[#e3f0ec] text-[#1f6f5c]',
  awaiting_plan_validation: 'bg-[#e2eef7] text-[#0a5f9e]',
  running: 'bg-navy text-white',
  awaiting_review: 'bg-[#f7efdd] text-[#8a5a06]',
  closed: 'bg-[#eceff2] text-[#4a5a68]',
  interrupted: 'bg-[#f7e4e2] text-[#8f1d1d]',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge ${SEVERITY_STYLES[severity]}`}>{SEVERITY_LABELS[severity]}</span>
  )
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <span className={`badge ${VERDICT_STYLES[verdict]}`}>{VERDICT_LABELS[verdict]}</span>
}

export function StatusBadge({ status }: { status: HuntStatus }) {
  return <span className={`badge ${STATUS_STYLES[status]}`}>{STATUS_LABELS[status]}</span>
}

export function ConfidenceLabel({ confidence }: { confidence: Confidence }) {
  const labels: Record<Confidence, string> = {
    low: 'low confidence',
    medium: 'medium confidence',
    high: 'high confidence',
  }
  return <span className="meta-text">{labels[confidence]}</span>
}

/** Machine-produced data: hash, query, address, identifier. */
export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono text-[0.9em] ${className}`}>{children}</span>
}

/** Query block. Rendered as plain text, never interpreted. */
export function QueryBlock({ query, label }: { query: string; label?: string }) {
  return (
    <div className="overflow-hidden rounded border border-rule">
      {label ? (
        <div className="border-b border-rule bg-paper px-3 py-1.5 text-xs text-slate">
          {label}
        </div>
      ) : null}
      <pre className="overflow-x-auto whitespace-pre-wrap break-words bg-white p-3 font-mono text-xs leading-relaxed text-ink">
        {query}
      </pre>
    </div>
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
    <div className="card px-6 py-10 text-center">
      <h3 className="text-lg font-semibold text-ink">{title}</h3>
      {children ? <p className="mx-auto mt-2 max-w-md text-slate">{children}</p> : null}
      {action ? <div className="mt-5 flex justify-center">{action}</div> : null}
    </div>
  )
}

export function ErrorNotice({ message, hint }: { message: string; hint?: string | null }) {
  return (
    <div className="rounded-xl border border-[#e8c5c1] bg-[#f7e4e2]/60 px-4 py-3" role="alert">
      <p className="font-medium text-garnet">{message}</p>
      {hint ? <p className="mt-1 text-sm text-slate">{hint}</p> : null}
    </div>
  )
}

export function TruncationNotice({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-sm text-amber">
      <span aria-hidden="true">▲</span>
      <span>{children}</span>
    </p>
  )
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="text-[15px] font-semibold text-ink">{children}</h2>
}
