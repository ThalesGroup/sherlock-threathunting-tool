/**
 * Hunt pipeline (dashboard). The hunts are laid out by the human checkpoint they are
 * waiting for; each card is an entry point to the relevant screen. The consolidated
 * findings, coverage by source and most affected entities come from the dashboard
 * endpoint.
 */

import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'

import { huntPath, api, type HuntStatus, type HuntSummary, type Severity, type Verdict } from '@/lib/api'

import { isWaiting, plural, sourceLabel } from '@/components/format'
import { IconArrowRight, IconCheck, IconChevronRight, IconMore, IconSpinner } from '@/components/icons'
import {
  Avatar,
  Btn,
  Chip,
  EmptyState,
  Glass,
  Ring,
  SEVERITY_COLORS,
  SEVERITY_ORDER,
  Stat,
  VERDICT_COLORS,
} from '@/components/ui'

const COLUMNS: { key: string; title: string; statuses: HuntStatus[]; hint: string }[] = [
  {
    key: 'iocs',
    title: 'Indicators to validate',
    statuses: ['awaiting_ioc_validation'],
    hint: 'Drop a CTI report to extract indicators',
  },
  {
    key: 'plan',
    title: 'Playbook to validate',
    statuses: ['awaiting_plan_validation', 'draft'],
    hint: 'Plans appear here once indicators are validated',
  },
  { key: 'run', title: 'Running', statuses: ['running'], hint: 'Read-only queries, results minimized before analysis' },
  { key: 'review', title: 'Report to review', statuses: ['awaiting_review'], hint: 'A proposed verdict awaits your decision' },
]

const RING_COLORS: Record<string, string> = {
  sentinel: '#2b8fd6',
  defender: '#0d1e33',
  secops: '#a8560b',
}

export function DashboardScreen() {
  const navigate = useNavigate()
  const dashboard = useQuery({ queryKey: ['dashboard'], queryFn: api.dashboard })
  const hunts = useQuery({ queryKey: ['hunts', { limit: 100 }], queryFn: () => api.listHunts({ limit: 100 }) })
  const config = useQuery({ queryKey: ['config'], queryFn: api.config })

  if (dashboard.isLoading || hunts.isLoading) return <p className="muted">Loading…</p>
  const data = dashboard.data
  const all = hunts.data ?? []

  if (!data || all.length === 0) {
    return (
      <EmptyState
        title="Nothing to consolidate yet"
        action={
          <Link to="/new" className="btn btn-dark">
            Launch a first hunt
          </Link>
        }
      >
        The pipeline fills up as investigations run.
      </EmptyState>
    )
  }

  const totalFindings = Object.values(data.findings_by_severity).reduce((sum, n) => sum + n, 0)
  const waiting = all.filter(isWaiting).length
  const totalQueries = Object.values(data.queries_by_siem).reduce((sum, n) => sum + n, 0)
  const maxQueries = Math.max(1, ...Object.values(data.queries_by_siem))
  const maxEntity = Math.max(1, ...data.top_entities.map((e) => e.count))
  const configured = config.data?.sources.filter((s) => s.configured).length ?? 0

  const closed = all.filter((h) => h.status === 'closed' || h.status === 'interrupted')
  const closedByVerdict = (verdict: Verdict) => closed.filter((h) => h.status === 'closed' && h.verdict === verdict).length
  const interrupted = closed.filter((h) => h.status === 'interrupted').length

  const analysts = Array.from(new Set(all.map((h) => h.analyst)))
  const waitingFor = (analyst: string) => all.filter((h) => h.analyst === analyst && isWaiting(h)).length

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <h1>Hunt pipeline</h1>
        <div className="flex flex-wrap items-center gap-8">
          <Stat value={totalFindings} label={<>findings<br />consolidated</>} />
          <Stat value={waiting} label={<>waiting<br />for you</>} tone={waiting > 0 ? 'amber' : 'ink'} />
          <Stat value={totalQueries} label={<>queries<br />{configured} {plural(configured, 'source')}</>} />
        </div>
      </div>

      <Glass className="p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <h2>Active hunts</h2>
            <div className="chip !h-14 !rounded-full !bg-white/70 !pl-2 !pr-2">
              <span className="flex items-center gap-1.5">
                {analysts.map((analyst) => (
                  <Avatar key={analyst} name={analyst} badge={waitingFor(analyst)} />
                ))}
                <Link to="/new" className="sm" title="New hunt">
                  <span className="text-[16px] leading-none">+</span>
                </Link>
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {SEVERITY_ORDER.map((severity) => (
              <SeverityCount key={severity} severity={severity} count={data.findings_by_severity[severity] ?? 0} />
            ))}
          </div>
        </div>

        <div className="mt-5 flex items-stretch gap-3 overflow-x-auto pb-2">
          {COLUMNS.map((column, index) => {
            const items = all.filter((hunt) => column.statuses.includes(hunt.status))
            return (
              <div key={column.key} className="contents">
                {index > 0 ? <IconChevronRight size={22} className="flow-arrow" /> : null}
                <div className="flex min-w-[200px] flex-1 flex-col">
                  <div className="inner flex flex-1 flex-col gap-3 p-3" style={{ minHeight: 168 }}>
                    {items.length === 0 ? (
                      <div className="flex flex-1 items-start gap-3 p-1 text-[13px] text-[var(--slate)]">
                        <span className="sm !cursor-default">
                          <IconMore size={16} />
                        </span>
                        <span className="pt-2 leading-snug">{column.hint}</span>
                      </div>
                    ) : (
                      items.map((hunt) => <PipelineCard key={hunt.hunt_id} hunt={hunt} onOpen={() => navigate(huntPath(hunt))} />)
                    )}
                  </div>
                  <p className={`mt-3 text-center text-[13.5px] ${column.key === 'review' && items.length > 0 ? 'font-semibold text-[var(--amber)]' : 'text-[var(--slate)]'}`}>
                    {column.title}
                  </p>
                </div>
              </div>
            )
          })}

          <IconChevronRight size={22} className="flow-arrow" />
          <div className="flex w-[280px] flex-none flex-col">
            <div className="grid flex-1 grid-cols-2 gap-2.5">
              <ClosedTile label="Escalated" count={closedByVerdict('escalate')} dark />
              <ClosedTile label="Benign" count={closedByVerdict('benign')} color={VERDICT_COLORS.benign} />
              <ClosedTile label="Suspicious" count={closedByVerdict('suspicious')} color={VERDICT_COLORS.suspicious} />
              <ClosedTile label="Inconclusive" count={closedByVerdict('inconclusive')} />
              <ClosedTile label="Interrupted" count={interrupted} color={VERDICT_COLORS.escalate} />
              <ClosedTile label="Awaiting verdict" count={closed.filter((h) => h.status === 'closed' && !h.verdict).length} />
            </div>
            <p className="mt-3 text-center text-[13.5px] text-[var(--slate)]">Closed</p>
          </div>
        </div>
      </Glass>

      <div className="grid gap-6 xl:grid-cols-[1fr_1.25fr]">
        <Glass className="p-6">
          <div className="flex items-center justify-between gap-3">
            <h2>Most affected entities</h2>
            <Btn variant="light" size="xs" onClick={() => navigate('/history')}>
              Full history <IconArrowRight size={14} />
            </Btn>
          </div>
          {data.top_entities.length === 0 ? (
            <p className="muted mt-4">No consolidated entity.</p>
          ) : (
            <table className="tbl mt-3">
              <thead>
                <tr>
                  <th className="w-8" />
                  <th className="w-28">Type</th>
                  <th>Entity</th>
                  <th className="w-20 text-right">Findings</th>
                </tr>
              </thead>
              <tbody>
                {data.top_entities.map((entry) => {
                  const [type, ...rest] = entry.entity.split(':')
                  const value = rest.join(':')
                  const heavy = entry.count >= maxEntity * 0.7
                  return (
                    <tr key={entry.entity}>
                      <td>
                        <span className="block h-2.5 w-2.5 rounded-full" style={{ background: heavy ? 'var(--garnet)' : entry.count > 1 ? 'var(--amber)' : 'var(--rule)' }} aria-hidden="true" />
                      </td>
                      <td className="text-[13.5px] text-[var(--slate)]">{type}</td>
                      <td className="mono text-[13px]">{value}</td>
                      <td className="mono text-right text-[13px] font-medium">{entry.count}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </Glass>

        <Glass className="flex flex-col p-6">
          <div className="flex items-center justify-between gap-3">
            <h2>Coverage by source</h2>
            <Chip tone="mint" small>
              {configured} {plural(configured, 'source')} connected
            </Chip>
          </div>
          {Object.keys(data.queries_by_siem).length === 0 ? (
            <p className="muted mt-4">No query executed.</p>
          ) : (
            <div className="flex flex-1 flex-wrap items-center justify-around gap-8 py-8">
              {Object.entries(data.queries_by_siem)
                .sort(([, a], [, b]) => b - a)
                .map(([siem, count]) => (
                  <div key={siem} className="flex flex-col items-center gap-3">
                    <Ring value={count} max={maxQueries} label={sourceLabel(siem)} color={RING_COLORS[siem] ?? '#5b6b7c'} size={168} />
                    <span className="mono text-[13px] text-[var(--slate)]">
                      {count} {plural(count, 'query', 'queries')} · {Math.round((count / Math.max(1, totalQueries)) * 100)}%
                    </span>
                  </div>
                ))}
            </div>
          )}
          <div className="mt-auto flex flex-wrap justify-center gap-2 border-t border-[var(--rule-soft)] pt-4">
            <Chip>{totalQueries} queries executed</Chip>
            <Chip tone="soft">read-only · results minimized before analysis</Chip>
          </div>
        </Glass>
      </div>
    </div>
  )
}

function SeverityCount({ severity, count }: { severity: Severity; count: number }) {
  return (
    <span className="chip chip-sm !bg-white/70" title={`${count} ${severity}`}>
      <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_COLORS[severity] }} aria-hidden="true" />
      <span className="capitalize">{severity}</span>
      <span className={`mono ${count === 0 ? 'text-[var(--meta)]' : ''}`}>{count}</span>
    </span>
  )
}

function PipelineCard({ hunt, onOpen }: { hunt: HuntSummary; onOpen: () => void }) {
  const review = hunt.status === 'awaiting_review'
  const running = hunt.status === 'running'
  const meta = review
    ? `proposed: ${hunt.proposed_verdict ?? '?'}`
    : hunt.campaign
      ? hunt.campaign
      : hunt.interruption_reason
        ? hunt.interruption_reason
        : hunt.hunt_id
  return (
    <button
      type="button"
      onClick={onOpen}
      className={`inner-solid flex w-full flex-col gap-2 p-3.5 text-left transition-colors hover:border-[var(--rule)] ${review ? '!border-[var(--amber)]' : ''}`}
    >
      <span className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2">
          <Avatar name={hunt.analyst} small />
          <span className="text-[12.5px] text-[var(--slate)]">{hunt.analyst}</span>
        </span>
        <span className={`sm !h-8 !w-8 ${review ? '!bg-[var(--navy)] !text-white' : ''}`} aria-hidden="true">
          {running ? <IconSpinner size={16} /> : review ? <IconArrowRight size={16} /> : <IconCheck size={16} className="text-[var(--amber)]" />}
        </span>
      </span>
      <span className="line-clamp-4 text-[13.5px] font-semibold leading-snug">{hunt.hypothesis}</span>
      <span className={`tech line-clamp-2 break-words ${review ? 'text-[var(--amber)]' : ''}`}>{meta}</span>
    </button>
  )
}

function ClosedTile({ label, count, dark = false, color }: { label: string; count: number; dark?: boolean; color?: string }) {
  return (
    <div className={`tile !min-h-0 !px-4 !py-3 ${dark ? '!bg-[var(--navy)] text-white' : ''}`}>
      <span className={`text-[12.5px] ${dark ? 'text-white/80' : 'text-[var(--slate)]'}`}>{label}</span>
      <span className="mt-1 text-[26px] font-medium leading-none" style={{ color: dark ? '#fff' : count > 0 ? (color ?? 'var(--ink)') : 'var(--meta)' }}>
        {count}
      </span>
    </div>
  )
}

