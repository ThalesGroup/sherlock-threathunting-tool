/**
 * Screen 3 - Hunt in progress.
 *
 * Signature element of the interface: the agent's reasoning is shown instead of being
 * hidden behind a loading indicator. Trust in an autonomous agent is not decreed, it is
 * verified - the execution trace is therefore the central object of the screen, not a
 * debug detail relegated to the side.
 */

import { useMutation } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import {
  ErrorNotice,
  Mono,
  QueryBlock,
  SectionTitle,
  SeverityBadge,
  TruncationNotice,
} from '@/components/primitives'
import { api, ApiError, type Severity } from '@/lib/api'
import { AnonymizationLine, ResultSample } from '@/components/ResultSample'
import type { AnonymizationInfo } from '@/lib/api'
import { type HuntEvent, useHuntStream } from '@/lib/useHuntStream'

export function HuntLiveScreen() {
  const { huntId = '' } = useParams()
  const navigate = useNavigate()
  const stream = useHuntStream(huntId)

  const stop = useMutation({ mutationFn: () => api.stopHunt(huntId) })

  useEffect(() => {
    if (!stream.finished) return
    const timer = setTimeout(() => navigate(`/hunts/${huntId}/report`), 1200)
    return () => clearTimeout(timer)
  }, [stream.finished, huntId, navigate])

  const budgets = latestBudgets(stream.events)
  const findings = stream.events.filter((event) => event.type === 'finding_recorded')
  const entities = collectEntities(stream.events)
  const budgetPause = pendingBudgetPause(stream.events)

  return (
    <div className="grid gap-8 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
      <section>
        <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-[22px] font-semibold tracking-tight text-ink">Investigation thread</h1>
            <Mono className="text-slate">{huntId}</Mono>
          </div>
          <div className="flex items-center gap-3">
            <StreamStatus connected={stream.connected} finished={stream.finished} />
            <button
              type="button"
              className="btn-secondary"
              onClick={() => stop.mutate()}
              disabled={stream.finished || stop.isPending}
            >
              Stop the hunt
            </button>
          </div>
        </header>

        {budgetPause && !stream.finished ? (
          <BudgetCheckpoint
            key={stream.events.indexOf(budgetPause)}
            huntId={huntId}
            budget={String(budgetPause.payload.budget ?? '')}
          />
        ) : null}

        {stream.error ? <ErrorNotice message={stream.error} /> : null}

        <ol className="space-y-4">
          {stream.events.map((event) => (
            <li key={event.sequence}>
              <EventCard event={event} />
            </li>
          ))}
        </ol>

        {stream.events.length === 0 && !stream.error ? (
          <p className="meta-text">Waiting for the first step…</p>
        ) : null}
      </section>

      <aside className="space-y-6">
        <div className="card p-4">
          <SectionTitle>Budgets</SectionTitle>
          <dl className="mt-3 space-y-3">
            {Object.entries(budgets).map(([name, budget]) => (
              <BudgetBar key={name} label={budgetLabel(name)} used={budget.used} limit={budget.limit} />
            ))}
          </dl>
        </div>

        <div className="card p-4">
          <SectionTitle>Entities encountered</SectionTitle>
          {entities.length === 0 ? (
            <p className="meta-text mt-2">None yet.</p>
          ) : (
            <ul className="mt-3 space-y-1">
              {entities.map((entity) => (
                <li key={entity}>
                  <Mono className="text-ink">{entity}</Mono>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card p-4">
          <SectionTitle>Findings</SectionTitle>
          {findings.length === 0 ? (
            <p className="meta-text mt-2">No finding recorded.</p>
          ) : (
            <ul className="mt-3 space-y-3">
              {findings.map((event) => {
                const finding = event.payload.finding as
                  | { title: string; severity: Severity }
                  | undefined
                if (!finding) return null
                return (
                  <li key={event.sequence} className="space-y-1">
                    <SeverityBadge severity={finding.severity} />
                    <p className="text-sm text-ink">{finding.title}</p>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      </aside>
    </div>
  )
}

function EventCard({ event }: { event: HuntEvent }) {
  switch (event.type) {
    case 'hunt_started':
      return (
        <div className="card p-4">
          <p className="meta-text">Hunt started</p>
          <p className="mt-1 text-ink">{String(event.payload.hypothesis ?? '')}</p>
        </div>
      )

    case 'iteration_started':
      return (
        <p className="pt-2 text-xs uppercase tracking-wide text-slate">
          Iteration {String(event.payload.iteration ?? '')}
        </p>
      )

    case 'agent_reasoning':
      return (
        <div className="card border-l-2 border-l-indigo p-4">
          <p className="whitespace-pre-wrap text-ink">{String(event.payload.text ?? '')}</p>
        </div>
      )

    case 'tool_call': {
      const args = (event.payload.arguments ?? {}) as Record<string, unknown>
      const intent = typeof args.intent === 'string' ? args.intent : null
      return (
        <div className="card p-4">
          <p className="meta-text">
            Call to <Mono className="text-ink">{String(event.payload.tool ?? '')}</Mono>
          </p>
          {intent ? <p className="mt-1.5 text-sm text-ink">{intent}</p> : null}
        </div>
      )
    }

    case 'tool_result': {
      const summary = (event.payload.summary ?? {}) as Record<string, unknown>
      const notes = (event.payload.notes ?? []) as string[]
      const query = event.payload.executed_query as string | undefined
      const intent = typeof event.payload.intent === 'string' ? event.payload.intent : null
      const columns = (event.payload.columns ?? []) as string[]
      const sample = (event.payload.sample ?? []) as Record<string, unknown>[]
      const modelSample = (event.payload.model_sample ?? []) as Record<string, unknown>[]
      const anonymization = (event.payload.anonymization ?? null) as AnonymizationInfo | null
      const sourceRows = Number(summary.source_rows ?? 0)
      return (
        <div className="card space-y-3 p-4">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="font-medium capitalize text-ink">
              {String(summary.siem ?? event.payload.tool ?? '')}
            </span>
            <span className="meta-text">
              {String(summary.returned_rows ?? 0)} row(s) of {String(summary.source_rows ?? 0)}
            </span>
            <Mono className="text-slate">{String(summary.query_id ?? '')}</Mono>
          </div>
          {intent ? <p className="text-sm text-ink">{intent}</p> : null}
          {sourceRows === 0 ? (
            <p className="meta-text">No row returned.</p>
          ) : (
            <>
              <AnonymizationLine info={anonymization && 'tokens' in anonymization ? anonymization : null} />
              <ResultSample
                columns={columns}
                rows={sample}
                modelRows={modelSample}
                sourceRows={sourceRows}
              />
            </>
          )}
          {query ? (
            <details className="group">
              <summary className="flex cursor-pointer select-none items-center gap-1.5 text-sm text-indigo">
                <span
                  className="inline-block transition-transform group-open:rotate-90 motion-reduce:transition-none"
                  aria-hidden="true"
                >
                  ▸
                </span>
                View the executed query
              </summary>
              <div className="mt-2">
                <QueryBlock query={query} />
              </div>
            </details>
          ) : null}
          {summary.truncated ? (
            <TruncationNotice>
              {String(summary.source_rows ?? '?')} rows returned by the source, cap reached:
              there were probably more. The model received only{' '}
              {String(summary.returned_rows ?? '?')}, with aggregates - narrow the query
              rather than concluding on this basis.
            </TruncationNotice>
          ) : null}
          {notes.map((note) => (
            <p key={note} className="meta-text">
              {note}
            </p>
          ))}
        </div>
      )
    }

    case 'tool_error':
      return (
        <ErrorNotice
          message={`${String(event.payload.tool ?? 'Tool')} - ${String(
            event.payload.message ?? 'call refused',
          )}`}
          hint={(event.payload.hint as string | null) ?? null}
        />
      )

    case 'finding_recorded': {
      const finding = event.payload.finding as
        | { title: string; description: string; severity: Severity; evidence_query_ids: string[] }
        | undefined
      if (!finding) return null
      return (
        <div className="card border-l-2 border-l-amber p-4">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.severity} />
            <h3 className="font-medium text-ink">{finding.title}</h3>
          </div>
          <p className="mt-2 text-sm text-ink">{finding.description}</p>
          <p className="meta-text mt-2">
            Evidence: {finding.evidence_query_ids.map((id) => id).join(', ')}
          </p>
        </div>
      )
    }

    case 'budget_alert':
      return (
        <div className="rounded border border-amber/40 bg-amber/5 px-4 py-3">
          <p className="text-amber">
            Budget {String(event.payload.budget ?? '')} more than 80% consumed.
          </p>
        </div>
      )

    case 'interrupted':
      return (
        <div className="rounded border border-amber/40 bg-amber/5 px-4 py-3">
          <p className="text-amber">
            Hunt interrupted: {String(event.payload.reason ?? 'reason not specified')}. A
            partial report has been produced.
          </p>
        </div>
      )

    case 'concluded':
      return (
        <div className="card border-l-2 border-l-indigo p-4">
          <p className="text-ink">
            Investigation complete - proposed verdict:{' '}
            <strong>{String(event.payload.proposed_verdict ?? '')}</strong>
          </p>
          <p className="meta-text mt-1">Redirecting to the report…</p>
        </div>
      )

    default:
      return null
  }
}

function StreamStatus({ connected, finished }: { connected: boolean; finished: boolean }) {
  if (finished) return <span className="meta-text">finished</span>
  return (
    <span className="meta-text flex items-center gap-2">
      <span
        className={`h-2 w-2 rounded-full ${connected ? 'bg-indigo' : 'bg-slate/40'}`}
        aria-hidden="true"
      />
      {connected ? 'live' : 'connecting…'}
    </span>
  )
}

function BudgetBar({ label, used, limit }: { label: string; used: number; limit: number }) {
  const ratio = limit > 0 ? Math.min(1, used / limit) : 0
  const tone = ratio >= 0.8 ? 'bg-amber' : 'bg-indigo'
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <dt className="text-sm text-ink">{label}</dt>
        <dd className="meta-text">
          {used} / {limit}
        </dd>
      </div>
      <div
        className="mt-1 h-1.5 overflow-hidden rounded bg-rule"
        role="progressbar"
        aria-valuenow={used}
        aria-valuemin={0}
        aria-valuemax={limit}
        aria-label={label}
      >
        <div className={`h-full ${tone}`} style={{ width: `${ratio * 100}%` }} />
      </div>
    </div>
  )
}

type BudgetSnapshot = Record<string, { used: number; limit: number }>

/** A budget pause is pending if no event has followed it with a resumption,
 *  an extension, an interruption or a conclusion. */
function pendingBudgetPause(events: HuntEvent[]): HuntEvent | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const type = events[index].type
    if (type === 'budget_paused') return events[index]
    if (
      type === 'budget_extended' ||
      type === 'interrupted' ||
      type === 'concluded' ||
      type === 'failed' ||
      type === 'iteration_started'
    ) {
      return null
    }
  }
  return null
}

function BudgetCheckpoint({ huntId, budget }: { huntId: string; budget: string }) {
  const [extraIterations, setExtraIterations] = useState(10)
  const [extraQueries, setExtraQueries] = useState(10)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const decide = async (action: 'extend' | 'stop') => {
    setPending(true)
    setError(null)
    try {
      await api.decideBudget(huntId, {
        action,
        ...(action === 'extend'
          ? {
              extra_iterations: extraIterations,
              extra_siem_queries: extraQueries,
              extra_minutes: 10,
            }
          : {}),
      })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The decision failed.')
      setPending(false)
    }
  }

  return (
    <div
      className="mb-5 rounded-xl border border-[#e8d5b0] bg-[#faeddc]/70 px-4 py-4"
      role="alert"
    >
      <p className="text-[13px] font-semibold text-ink">
        Budget exhausted ({budget}) - the investigation is paused.
      </p>
      <p className="meta-text mt-1">
        Continue with an additional amount (the agent resumes exactly where it left off),
        or stop and receive the partial report. Without a response within the time limit,
        the hunt stops cleanly.
      </p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="text-xs text-ink">
          <span className="label mb-1 block">+ iterations</span>
          <input
            type="number"
            min={0}
            max={100}
            value={extraIterations}
            onChange={(event) =>
              setExtraIterations(Math.min(100, Math.max(0, Number(event.target.value) || 0)))
            }
            className="field w-24 font-mono text-sm"
          />
        </label>
        <label className="text-xs text-ink">
          <span className="label mb-1 block">+ SIEM queries</span>
          <input
            type="number"
            min={0}
            max={100}
            value={extraQueries}
            onChange={(event) =>
              setExtraQueries(Math.min(100, Math.max(0, Number(event.target.value) || 0)))
            }
            className="field w-24 font-mono text-sm"
          />
        </label>
        <button
          type="button"
          className="btn-primary"
          disabled={pending || (extraIterations === 0 && extraQueries === 0)}
          onClick={() => void decide('extend')}
        >
          Continue
        </button>
        <button
          type="button"
          className="btn-secondary"
          disabled={pending}
          onClick={() => void decide('stop')}
        >
          Stop and generate the report
        </button>
      </div>
      {error ? <p className="mt-2 text-xs text-garnet">{error}</p> : null}
    </div>
  )
}

function latestBudgets(events: HuntEvent[]): BudgetSnapshot {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const budgets = events[index].payload.budgets
    if (budgets && typeof budgets === 'object') {
      return budgets as BudgetSnapshot
    }
  }
  return {}
}

function budgetLabel(name: string): string {
  const labels: Record<string, string> = {
    iterations: 'Iterations',
    siem_queries: 'SIEM queries',
    tokens: 'Tokens',
    duration_seconds: 'Duration (s)',
  }
  return labels[name] ?? name
}

function collectEntities(events: HuntEvent[]): string[] {
  const found = new Set<string>()
  for (const event of events) {
    if (event.type !== 'finding_recorded') continue
    const finding = event.payload.finding as
      | { entities?: { type: string; value: string }[] }
      | undefined
    for (const entity of finding?.entities ?? []) {
      found.add(`${entity.type}: ${entity.value}`)
    }
  }
  return [...found]
}
