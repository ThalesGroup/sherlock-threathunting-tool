/**
 * Screen 6 — History and audit.
 *
 * This is the screen shown during a compliance audit: for each hunt, the queries actually
 * executed, the volumes returned, the agent's decisions and the human validations with
 * their author and timestamp.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { EmptyState, Mono, QueryBlock, SectionTitle, StatusBadge } from '@/components/primitives'
import { api, huntPath, type AuditEntry, type HuntStatus } from '@/lib/api'

const STATUS_FILTERS: { value: HuntStatus | ''; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'awaiting_review', label: 'To review' },
  { value: 'closed', label: 'Closed' },
  { value: 'interrupted', label: 'Interrupted' },
]

const EVENT_LABELS: Record<string, string> = {
  hunt_created: 'Hunt created',
  ioc_search: 'Threat intel search',
  ioc_validation: 'Indicator validation',
  plan_proposed: 'Playbook proposed',
  plan_validated: 'Playbook validated (budgets retained)',
  query_executed: 'Query executed',
  query_rejected: 'Query rejected',
  anonymization_degraded: 'Anonymization degraded (free text masked)',
  agent_decision: 'Agent decision',
  finding_recorded: 'Finding recorded',
  budget_event: 'Budget event',
  hunt_concluded: 'Hunt concluded',
  hunt_interrupted: 'Hunt interrupted',
  hunt_resumed: 'Hunt resumed (new investigation)',
  hunt_deleted: 'Hunt deleted',
  report_validated: 'Report validated',
  account_password_changed: 'Password changed by its holder',
}

export function HistoryScreen() {
  const [status, setStatus] = useState<HuntStatus | ''>('')
  const [analyst, setAnalyst] = useState('')
  const [openHunt, setOpenHunt] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const session = useQuery({ queryKey: ['session'], queryFn: api.me, retry: false })
  const canDelete = session.data?.roles.includes('analyst') ?? false

  const hunts = useQuery({
    queryKey: ['hunts', { status, analyst }],
    queryFn: () =>
      api.listHunts({
        ...(status ? { status } : {}),
        ...(analyst.trim() ? { analyst: analyst.trim() } : {}),
        limit: 100,
      }),
  })

  const remove = useMutation({
    mutationFn: (huntId: string) => api.deleteHunt(huntId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['hunts'] }),
  })

  const rows = hunts.data ?? []

  return (
    <div>
      <header className="mb-4 flex items-baseline justify-between">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-ink">
            History and audit
          </h1>
          <p className="meta-text mt-1">
            Full log of every investigation: queries, volumes, decisions and human
            validations.
          </p>
        </div>
        <span className="meta-mono uppercase">
          {rows.length} entr{rows.length > 1 ? 'ies' : 'y'}
        </span>
      </header>

      <div className="card mb-[-1px] flex flex-wrap items-center gap-5 rounded-b-none px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="label">Status</span>
          {STATUS_FILTERS.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => setStatus(option.value)}
              className={`rounded-[7px] px-2.5 py-1.5 font-mono text-[11px] tracking-wide ${
                status === option.value
                  ? 'bg-navy font-semibold text-white'
                  : 'bg-rule-soft text-slate hover:bg-rule'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <label htmlFor="filter-analyst" className="label">
            Analyst
          </label>
          <input
            id="filter-analyst"
            value={analyst}
            onChange={(event) => setAnalyst(event.target.value)}
            className="field w-[130px] py-1.5 font-mono text-xs"
            placeholder="all"
          />
        </div>
      </div>

      {hunts.data && rows.length === 0 ? (
        <EmptyState title="No hunt matches">
          Widen the filters to find an investigation.
        </EmptyState>
      ) : (
        <div className="card rounded-t-none">
          <div className="flex border-b border-rule bg-soft-bg px-4 py-2.5">
            <span className="label w-[158px] flex-none">Reference</span>
            <span className="label flex-1">Investigation</span>
            <span className="label w-[150px] flex-none">Status</span>
            <span className="label w-[96px] flex-none">Analyst</span>
            <span className="label hidden w-[132px] flex-none xl:block">Timestamp</span>
            <span className="label w-[180px] flex-none text-right">Actions</span>
          </div>
          <ul>
            {rows.map((hunt) => (
              <li key={hunt.hunt_id} className="border-b border-rule-soft last:border-b-0">
                <div className="flex items-center px-4 py-3 transition-colors hover:bg-[#f9fafb]">
                  <Mono className="w-[158px] flex-none text-[11px] font-medium text-indigo">
                    {hunt.hunt_id}
                  </Mono>
                  <span className="min-w-0 flex-1 truncate pr-3 text-[13px] text-ink">
                    {hunt.hypothesis}
                  </span>
                  <span className="w-[150px] flex-none">
                    <StatusBadge status={hunt.status} />
                  </span>
                  <span className="w-[96px] flex-none font-mono text-[11px] text-slate">
                    {hunt.analyst}
                  </span>
                  <span className="hidden w-[132px] flex-none font-mono text-[11px] text-meta xl:block">
                    {new Date(hunt.created_at).toLocaleString('en-GB', {
                      dateStyle: 'short',
                      timeStyle: 'short',
                    })}
                  </span>
                  <span className="flex w-[180px] flex-none justify-end gap-1.5">
                    <Link
                      to={huntPath(hunt)}
                      className="btn-secondary px-2.5 py-1.5 text-[11px]"
                    >
                      {hunt.status === 'draft' || hunt.status === 'awaiting_ioc_validation'
                        ? 'Resume'
                        : hunt.status === 'running'
                          ? 'Follow'
                          : 'Report'}
                    </Link>
                    <button
                      type="button"
                      className="btn-secondary px-2.5 py-1.5 text-[11px]"
                      aria-expanded={openHunt === hunt.hunt_id}
                      onClick={() =>
                        setOpenHunt((current) =>
                          current === hunt.hunt_id ? null : hunt.hunt_id,
                        )
                      }
                    >
                      Log
                    </button>
                    {canDelete ? (
                      <button
                        type="button"
                        className="px-1.5 text-[11px] font-medium text-[#9d3b34] hover:underline disabled:opacity-50"
                        disabled={remove.isPending}
                        onClick={() => {
                          if (
                            window.confirm(
                              `Delete hunt ${hunt.hunt_id}? The investigation data ` +
                                'will be erased. The audit log is kept.',
                            )
                          ) {
                            remove.mutate(hunt.hunt_id)
                          }
                        }}
                      >
                        Delete
                      </button>
                    ) : null}
                  </span>
                </div>
                {openHunt === hunt.hunt_id ? <AuditTrail huntId={hunt.hunt_id} /> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function AuditTrail({ huntId }: { huntId: string }) {
  const trail = useQuery({ queryKey: ['audit', huntId], queryFn: () => api.audit(huntId) })

  if (trail.isLoading) return <p className="meta-text px-4 pb-4">Loading the log…</p>
  const entries = trail.data ?? []

  return (
    <div className="border-t border-rule px-4 py-4">
      <SectionTitle>Log</SectionTitle>
      <ol className="mt-4 space-y-4">
        {entries.map((entry) => (
          <li key={entry.id} className="space-y-2">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="text-sm font-medium text-ink">
                {EVENT_LABELS[entry.type] ?? entry.type}
              </span>
              <Mono className="text-slate">{entry.timestamp}</Mono>
              <span className="meta-text">{entry.actor}</span>
              {entry.error_code ? (
                <span className="badge bg-garnet/10 text-garnet">{entry.error_code}</span>
              ) : null}
            </div>
            {entry.query ? <QueryBlock query={entry.query} label={entry.siem ?? undefined} /> : null}
            <AuditMeta entry={entry} />
          </li>
        ))}
      </ol>
    </div>
  )
}

function AuditMeta({ entry }: { entry: AuditEntry }) {
  const parts: string[] = []
  if (entry.rows_returned !== null) parts.push(`${entry.rows_returned} row(s) returned`)
  if (entry.truncated) parts.push('result truncated')
  if (entry.duration_ms !== null) parts.push(`${entry.duration_ms} ms`)
  if (entry.query_id) parts.push(entry.query_id)

  const detail = Object.entries(entry.detail ?? {})

  return (
    <div className="space-y-1">
      {parts.length > 0 ? <p className="meta-text">{parts.join(' · ')}</p> : null}
      {detail.length > 0 ? (
        <dl className="meta-text flex flex-wrap gap-x-4">
          {detail.map(([key, value]) => (
            <div key={key} className="flex gap-1">
              <dt>{key}:</dt>
              <dd className="text-ink">{formatValue(value)}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </div>
  )
}

/** The detail comes from the middleware: displayed as text, never interpreted. */
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (Array.isArray(value)) return value.map((item) => String(item)).join(', ') || '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
