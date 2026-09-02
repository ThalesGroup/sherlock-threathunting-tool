/** Screen 5 — Dashboard. Each element is an entry point to the relevant hunt. */

import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'

import { EmptyState, SEVERITY_COLORS, StatusBadge } from '@/components/primitives'
import { api, huntPath, type Severity } from '@/lib/api'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export function DashboardScreen() {
  const dashboard = useQuery({ queryKey: ['dashboard'], queryFn: api.dashboard })
  const navigate = useNavigate()

  if (dashboard.isLoading) return <p className="meta-text">Loading…</p>
  const data = dashboard.data

  if (!data || data.recent_hunts.length === 0) {
    return (
      <EmptyState
        title="Nothing to consolidate yet"
        action={
          <Link to="/" className="btn-primary">
            Launch a first hunt
          </Link>
        }
      >
        The dashboard fills up as investigations run.
      </EmptyState>
    )
  }

  const totalFindings = Object.values(data.findings_by_severity).reduce(
    (sum, n) => sum + n,
    0,
  )
  const pending = data.recent_hunts.filter((h) => h.status === 'awaiting_review').length
  const maxQueries = Math.max(1, ...Object.values(data.queries_by_siem))
  const totalQueries = Object.values(data.queries_by_siem).reduce((sum, n) => sum + n, 0)
  const maxEntity = Math.max(1, ...data.top_entities.map((e) => e.count))

  return (
    <div>
      <div className="mb-4 flex items-baseline justify-between">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-ink">
            Dashboard
          </h1>
          <p className="meta-text mt-1">
            {totalFindings} consolidated finding{totalFindings > 1 ? 's' : ''}.
            {pending > 0
              ? ` ${pending} hunt${pending > 1 ? 's' : ''} awaiting a human decision.`
              : ''}
          </p>
        </div>
      </div>

      <div className="card mb-5 flex">
        <div className="min-w-[150px] border-r border-rule bg-soft-bg px-5 py-4">
          <div className="label">Findings</div>
          <div className="mt-2.5 font-mono text-[34px] font-semibold tracking-tight">
            {totalFindings}
          </div>
        </div>
        {SEVERITY_ORDER.map((severity) => {
          const n = data.findings_by_severity[severity] ?? 0
          return (
            <div key={severity} className="flex-1 border-r border-rule-soft px-5 py-4 last:border-r-0">
              <div className="flex items-center gap-2">
                <span
                  className="h-2 w-2 flex-none rounded-full"
                  style={{ background: SEVERITY_COLORS[severity] }}
                  aria-hidden="true"
                />
                <span className="label">{SEVERITY_LABELS[severity]}</span>
              </div>
              <div
                className={`mt-2.5 font-mono text-[30px] font-semibold tracking-tight ${
                  n === 0 ? 'text-[#b8c2cb]' : 'text-ink'
                }`}
              >
                {n}
              </div>
            </div>
          )
        })}
      </div>

      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1.55fr)_minmax(320px,1fr)]">
        <section className="card">
          <div className="flex items-center justify-between border-b border-rule px-4 py-3">
            <h2 className="text-[13px] font-semibold text-ink">Recent hunts</h2>
            <Link to="/history" className="text-xs text-indigo hover:underline">
              Full history →
            </Link>
          </div>
          <ul>
            {data.recent_hunts.map((hunt) => (
              <li key={hunt.hunt_id} className="border-b border-rule-soft last:border-b-0">
                <button
                  type="button"
                  onClick={() => navigate(huntPath(hunt))}
                  className="flex w-full items-center gap-2.5 px-4 py-3 text-left transition-colors hover:bg-soft-bg"
                >
                  <span className="w-[150px] flex-none font-mono text-[11px] font-medium text-indigo">
                    {hunt.hunt_id}
                  </span>
                  <span className="min-w-0 flex-1 truncate pr-3 text-[13px] text-ink">
                    {hunt.hypothesis}
                  </span>
                  <StatusBadge status={hunt.status} />
                  <span className="w-[70px] flex-none text-right font-mono text-[11px] text-meta">
                    {hunt.analyst}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <div className="flex flex-col gap-5">
          <section className="card">
            <h2 className="card-header">Coverage by source</h2>
            <div className="p-4">
              {Object.keys(data.queries_by_siem).length === 0 ? (
                <p className="meta-text">No query executed.</p>
              ) : (
                <>
                  {Object.entries(data.queries_by_siem).map(([siem, count]) => (
                    <div key={siem} className="mb-3.5 last:mb-0">
                      <div className="mb-1.5 flex items-baseline justify-between">
                        <span className="text-xs font-medium capitalize text-ink">{siem}</span>
                        <span className="font-mono text-[11px] text-slate">
                          {count} quer{count > 1 ? 'ies' : 'y'}
                        </span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-rule-soft">
                        <div
                          className="h-full rounded-full bg-navy-active"
                          style={{ width: `${Math.round((count / maxQueries) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                  <p className="meta-mono mt-3 border-t border-rule-soft pt-2.5 uppercase">
                    {totalQueries} queries executed
                  </p>
                </>
              )}
            </div>
          </section>

          <section className="card">
            <h2 className="card-header">Most affected entities</h2>
            <div className="px-4 pb-3.5 pt-1.5">
              {data.top_entities.length === 0 ? (
                <p className="meta-text py-2">No consolidated entity.</p>
              ) : (
                data.top_entities.map((entity) => (
                  <div
                    key={entity.entity}
                    className="flex items-center gap-2.5 border-b border-rule-soft py-2 last:border-b-0"
                  >
                    <span className="min-w-0 flex-1 truncate font-mono text-xs font-medium text-ink">
                      {entity.entity}
                    </span>
                    <span className="h-[5px] w-[52px] flex-none overflow-hidden rounded-full bg-rule-soft">
                      <span
                        className="block h-full rounded-full"
                        style={{
                          width: `${Math.round((entity.count / maxEntity) * 100)}%`,
                          background: entity.count >= maxEntity * 0.7 ? '#8f1d1d' : '#a9b6c2',
                        }}
                      />
                    </span>
                    <span className="w-4 flex-none text-right font-mono text-[11px] font-medium">
                      {entity.count}
                    </span>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}
