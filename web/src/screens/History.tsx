/**
 * History and audit. The screen shown during a compliance audit: for each hunt, the
 * queries actually executed, the volumes returned, the agent's decisions and the human
 * validations with their author and timestamp.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { huntPath, api, type AuditEntry, type HuntStatus, type HuntSummary } from '@/lib/api'

import { formatShort, isWaiting, plural } from '@/components/format'
import { IconChevronDown, IconTrash } from '@/components/icons'
import { Avatar, Btn, Chip, EmptyState, Glass, Inner, Mono, QueryBlock, Stat, StatusChip } from '@/components/ui'

type Filter = 'all' | 'running' | 'waiting' | 'closed' | 'interrupted'

const FILTERS: { value: Filter; label: string; statuses: HuntStatus[] | null }[] = [
  { value: 'all', label: 'All', statuses: null },
  { value: 'running', label: 'Running', statuses: ['running'] },
  { value: 'waiting', label: 'Waiting for you', statuses: ['awaiting_ioc_validation', 'awaiting_plan_validation', 'awaiting_review', 'draft'] },
  { value: 'closed', label: 'Closed', statuses: ['closed'] },
  { value: 'interrupted', label: 'Interrupted', statuses: ['interrupted'] },
]

const EVENT_LABELS: Record<string, string> = {
  hunt_created: 'Hunt created',
  ioc_search: 'Threat intel search',
  ioc_validation: 'Indicator validation',
  ioc_import: 'Indicators imported',
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
  hunt_continued: 'Hunt continued',
  hunt_deleted: 'Hunt deleted',
  report_validated: 'Report validated',
  account_password_changed: 'Password changed by its holder',
}

export function HistoryScreen() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filter = (searchParams.get('filter') as Filter | null) ?? 'all'
  const [analyst, setAnalyst] = useState('')
  const [openHunt, setOpenHunt] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const session = useQuery({ queryKey: ['session'], queryFn: api.me, retry: false })
  const canDelete = session.data?.roles.includes('analyst') ?? false
  const hunts = useQuery({ queryKey: ['hunts', { limit: 100 }], queryFn: () => api.listHunts({ limit: 100 }) })
  const dashboard = useQuery({ queryKey: ['dashboard'], queryFn: api.dashboard })

  const remove = useMutation({
    mutationFn: (huntId: string) => api.deleteHunt(huntId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['hunts'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  const all = hunts.data ?? []
  const analysts = Array.from(new Set(all.map((hunt) => hunt.analyst))).sort()
  const active = FILTERS.find((item) => item.value === filter) ?? FILTERS[0]
  const rows = all.filter((hunt) => (active.statuses ? active.statuses.includes(hunt.status) : true)).filter((hunt) => (analyst ? hunt.analyst === analyst : true))
  const countFor = (item: (typeof FILTERS)[number]) => all.filter((hunt) => (item.statuses ? item.statuses.includes(hunt.status) : true)).length
  const waiting = all.filter(isWaiting).length
  const queriesLogged = Object.values(dashboard.data?.queries_by_siem ?? {}).reduce((sum, n) => sum + n, 0)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <h1>History and audit</h1>
          <p className="mt-2 text-[15px] text-[var(--slate)]">Full log of every investigation: queries, volumes, decisions and human validations.</p>
        </div>
        <div className="flex flex-wrap items-center gap-8">
          <Stat value={all.length} label={<>entries<br />all time</>} />
          <Stat value={waiting} label={<>waiting<br />for a human</>} tone={waiting > 0 ? 'amber' : 'ink'} />
          <Stat value={queriesLogged} label={<>queries<br />logged</>} />
        </div>
      </div>

      <Glass className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="tabs" role="tablist" aria-label="Status">
            {FILTERS.map((item) => (
              <button key={item.value} type="button" role="tab" aria-selected={filter === item.value} className={`${filter === item.value ? 'on' : ''} ${item.value === 'waiting' && filter !== 'waiting' && waiting > 0 ? 'warn' : ''}`} onClick={() => setSearchParams(item.value === 'all' ? {} : { filter: item.value }, { replace: true })}>
                {item.label} · {countFor(item)}
              </button>
            ))}
          </div>
          <label className="chip !h-12 !gap-3 !rounded-full !pl-5 !pr-2 !font-normal">
            <span className="text-[var(--slate)]">Analyst</span>
            <select value={analyst} onChange={(event) => setAnalyst(event.target.value)} className="field field-pill mono !h-10 !w-auto !bg-transparent !pr-10 text-[13px]" aria-label="Filter by analyst">
              <option value="">all</option>
              {analysts.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>
        </div>

        {hunts.data && all.length === 0 ? (
          <div className="mt-4">
            <EmptyState
              title="No investigation yet"
              action={
                <Link to="/new" className="btn btn-dark">
                  Launch a first hunt
                </Link>
              }
            >
              The history fills up as hunts run: every query, decision and human validation is logged here.
            </EmptyState>
          </div>
        ) : hunts.data && rows.length === 0 ? (
          <div className="mt-4">
            <EmptyState title="No hunt matches">Widen the filters to find an investigation.</EmptyState>
          </div>
        ) : (
          <Inner className="mt-4 overflow-hidden">
            <div className="overflow-x-auto px-2">
              <table className="tbl">
                <thead>
                  <tr>
                    <th className="w-14" />
                    <th className="w-40">Reference</th>
                    <th>Investigation</th>
                    <th className="w-48">Status</th>
                    <th className="w-28">Analyst</th>
                    <th className="w-40">Timestamp</th>
                    <th className="w-56 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((hunt) => (
                    <HuntRow key={hunt.hunt_id} hunt={hunt} open={openHunt === hunt.hunt_id} canDelete={canDelete} deleting={remove.isPending} onToggle={() => setOpenHunt((current) => (current === hunt.hunt_id ? null : hunt.hunt_id))} onDelete={() => remove.mutate(hunt.hunt_id)} />
                  ))}
                </tbody>
              </table>
            </div>
          </Inner>
        )}
      </Glass>
    </div>
  )
}

function HuntRow({ hunt, open, canDelete, deleting, onToggle, onDelete }: { hunt: HuntSummary; open: boolean; canDelete: boolean; deleting: boolean; onToggle: () => void; onDelete: () => void }) {
  const action =
    hunt.status === 'awaiting_plan_validation' || hunt.status === 'draft'
      ? 'Validate'
      : hunt.status === 'awaiting_ioc_validation'
        ? 'Resume'
        : hunt.status === 'running'
          ? 'Follow'
          : 'Report'
  return (
    <>
      <tr className={open ? '!border-b-0' : ''}>
        <td>
          <Avatar name={hunt.analyst} />
        </td>
        <td>
          <Link to={huntPath(hunt)} className="link mono text-[12.5px]">
            {hunt.hunt_id}
          </Link>
        </td>
        <td className="max-w-[28rem]">
          <span className="line-clamp-2 text-[13.5px] leading-snug">{hunt.hypothesis}</span>
        </td>
        <td>
          <StatusChip status={hunt.status} verdict={hunt.verdict ?? null} small />
        </td>
        <td className="text-[13px] text-[var(--slate)]">{hunt.analyst}</td>
        <td className="mono text-[12px] text-[var(--slate)]">{formatShort(hunt.created_at)}</td>
        <td>
          <span className="flex items-center justify-end gap-2">
            <Link to={huntPath(hunt)} className="btn btn-light btn-xs">
              {action}
            </Link>
            <Btn variant="light" size="xs" aria-expanded={open} onClick={onToggle}>
              Log <IconChevronDown size={14} className={open ? 'rotate-180' : ''} />
            </Btn>
            {canDelete ? (
              <button
                type="button"
                className="sm !h-8 !w-8 !text-[var(--garnet)]"
                title="Delete this hunt"
                aria-label={`Delete hunt ${hunt.hunt_id}`}
                disabled={deleting}
                onClick={() => {
                  if (window.confirm(`Delete hunt ${hunt.hunt_id}? The investigation data will be erased. The audit log is kept.`)) onDelete()
                }}
              >
                <IconTrash size={15} />
              </button>
            ) : null}
          </span>
        </td>
      </tr>
      {open ? (
        <tr>
          <td colSpan={7} className="!p-0">
            <AuditTrail huntId={hunt.hunt_id} />
          </td>
        </tr>
      ) : null}
    </>
  )
}

function AuditTrail({ huntId }: { huntId: string }) {
  const trail = useQuery({ queryKey: ['audit', huntId], queryFn: () => api.audit(huntId) })
  if (trail.isLoading) return <p className="muted px-5 pb-4 text-[13px]">Loading the log…</p>
  const entries = trail.data ?? []
  return (
    <div className="mx-2 mb-3 rounded-[18px] bg-white/60 px-5 py-4">
      <div className="flex items-center gap-3">
        <h3>Log</h3>
        <Chip tone="soft" small>
          {entries.length} {plural(entries.length, 'event')}
        </Chip>
      </div>
      <ol className="mt-3 space-y-4">
        {entries.map((entry) => (
          <li key={entry.id} className="space-y-1.5">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="text-[13.5px] font-semibold">{EVENT_LABELS[entry.type] ?? entry.type}</span>
              <Mono className="text-[12px] text-[var(--slate)]">{entry.timestamp}</Mono>
              <span className="text-[13px] text-[var(--slate)]">{entry.actor}</span>
              {entry.error_code ? (
                <Chip tone="garnet" small>
                  {entry.error_code}
                </Chip>
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
    <div className="space-y-1 text-[13px] text-[var(--slate)]">
      {parts.length > 0 ? <p>{parts.join(' · ')}</p> : null}
      {detail.length > 0 ? (
        <dl className="flex flex-wrap gap-x-4 gap-y-0.5">
          {detail.map(([key, value]) => (
            <div key={key} className="flex gap-1">
              <dt>{key}:</dt>
              <dd className="text-[var(--ink)]">{formatValue(value)}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </div>
  )
}

/** The detail comes from the middleware: displayed as text, never interpreted. */
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '-'
  if (Array.isArray(value)) return value.map((item) => String(item)).join(', ') || '-'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
