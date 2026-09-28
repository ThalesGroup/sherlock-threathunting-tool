/**
 * Hunt in progress. The agent's reasoning is shown instead of being hidden behind a
 * loading indicator: the execution trace is the central object of the screen.
 */

import { useMutation } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import { api, ApiError, type AnonymizationInfo, type Severity } from '@/lib/api'
import { type HuntEvent, useHuntStream } from '@/lib/useHuntStream'

import { IconSpinner, IconStop } from '@/components/icons'
import {
  AnonymizationLine,
  Bar,
  Btn,
  Chip,
  Disclosure,
  ErrorNotice,
  Glass,
  Inner,
  Mono,
  Notice,
  QueryBlock,
  ResultSample,
  SeverityChip,
  Stepper,
  TruncationNotice,
} from '@/components/ui'

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
  const iteration = latestIteration(stream.events)
  const activity = stream.finished || stream.error || budgetPause ? null : currentActivity(stream.events, stream.connected)

  // Follow the thread as it grows: the newest step stays in view.
  const endRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [stream.events.length, activity])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <p className="tech">
            Hunts / <span className="text-[var(--ink)]">{huntId}</span>
          </p>
          <h1 className="mt-1">Investigation thread</h1>
          <p className="mt-2 text-[15px] text-[var(--slate)]">Every query is read-only, minimized and pseudonymized before the agent reads it.</p>
        </div>
        <Stepper
          steps={[
            { label: 'Indicators', state: 'done' },
            { label: 'Playbook', state: 'done' },
            { label: stream.finished ? 'Verdict' : 'Running', state: 'now' },
          ]}
        />
      </div>

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <StreamStatus connected={stream.connected} finished={stream.finished} />
              {iteration ? (
                <Chip tone="soft" small>
                  iteration {iteration}
                </Chip>
              ) : null}
            </div>
            <Btn variant="light" size="sm" onClick={() => stop.mutate()} disabled={stream.finished || stop.isPending}>
              <IconStop size={16} /> Stop the hunt
            </Btn>
          </div>

          {budgetPause && !stream.finished ? (
            <BudgetCheckpoint key={stream.events.indexOf(budgetPause)} huntId={huntId} budget={String(budgetPause.payload.budget ?? '')} />
          ) : null}

          {stream.error ? <ErrorNotice message={stream.error} /> : null}

          <ol className="space-y-3">
            {stream.events.map((event) => (
              <li key={event.sequence} className="feed-item">
                <EventCard event={event} />
              </li>
            ))}
          </ol>

          {stream.events.length === 0 && !stream.error ? <p className="muted">Waiting for the first step…</p> : null}

          {activity ? <Activity kind={activity} /> : null}
          <div ref={endRef} aria-hidden="true" />
        </div>

        <aside className="space-y-4">
          <Inner className="p-5">
            <h2 className="!text-[19px]">Budgets</h2>
            <dl className="mt-3 space-y-3">
              {Object.entries(budgets).map(([name, budget]) => (
                <div key={name}>
                  <div className="flex items-baseline justify-between text-[13.5px]">
                    <dt>{budgetLabel(name)}</dt>
                    <dd className="mono text-[12.5px] text-[var(--slate)]">
                      {budget.used} / {budget.limit}
                    </dd>
                  </div>
                  <Bar value={budget.used} max={budget.limit} tone={budget.limit > 0 && budget.used / budget.limit >= 0.8 ? 'amber' : 'navy'} className="mt-1.5" />
                </div>
              ))}
              {Object.keys(budgets).length === 0 ? <p className="muted text-[13.5px]">No budget snapshot yet.</p> : null}
            </dl>
          </Inner>

          <Inner className="p-5">
            <h2 className="!text-[19px]">Findings</h2>
            {findings.length === 0 ? (
              <p className="muted mt-2 text-[13.5px]">No finding recorded.</p>
            ) : (
              <ul className="mt-3 space-y-3">
                {findings.map((event) => {
                  const finding = event.payload.finding as { title: string; severity: Severity } | undefined
                  if (!finding) return null
                  return (
                    <li key={event.sequence} className="flex items-start gap-3">
                      <SeverityChip severity={finding.severity} small />
                      <p className="text-[13.5px] leading-snug">{finding.title}</p>
                    </li>
                  )
                })}
              </ul>
            )}
          </Inner>

          <Inner className="p-5">
            <h2 className="!text-[19px]">Entities encountered</h2>
            {entities.length === 0 ? (
              <p className="muted mt-2 text-[13.5px]">None yet.</p>
            ) : (
              <ul className="mt-3 space-y-1.5">
                {entities.map((entity) => (
                  <li key={entity} className="mono text-[12.5px]">
                    {entity}
                  </li>
                ))}
              </ul>
            )}
          </Inner>
        </aside>
      </Glass>
    </div>
  )
}

function EventCard({ event }: { event: HuntEvent }) {
  switch (event.type) {
    case 'hunt_started':
      return (
        <Inner className="p-4">
          <p className="tech">Hunt started</p>
          <p className="mt-1">{String(event.payload.hypothesis ?? '')}</p>
        </Inner>
      )
    case 'iteration_started':
      return <p className="tech pt-2 uppercase tracking-wide">Iteration {String(event.payload.iteration ?? '')}</p>
    case 'agent_reasoning':
      return (
        <Inner className="border-l-4 !border-l-[var(--indigo)] p-4">
          <p className="whitespace-pre-wrap text-[14px] leading-relaxed">{String(event.payload.text ?? '')}</p>
        </Inner>
      )
    case 'tool_call': {
      const args = (event.payload.arguments ?? {}) as Record<string, unknown>
      const intent = typeof args.intent === 'string' ? args.intent : null
      return (
        <Inner className="p-4">
          <p className="tech">
            Call to <span className="text-[var(--ink)]">{String(event.payload.tool ?? '')}</span>
          </p>
          {intent ? <p className="mt-1.5 text-[13.5px]">{intent}</p> : null}
        </Inner>
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
        <Inner className="space-y-3 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <Chip tone="navy" small className="capitalize">
              {String(summary.siem ?? event.payload.tool ?? '')}
            </Chip>
            <span className="text-[13px] text-[var(--slate)]">
              {String(summary.returned_rows ?? 0)} row(s) of {String(summary.source_rows ?? 0)}
            </span>
            <Mono className="text-[var(--slate)]">{String(summary.query_id ?? '')}</Mono>
          </div>
          {intent ? <p className="text-[13.5px]">{intent}</p> : null}
          {sourceRows === 0 ? (
            <p className="muted text-[13px]">No row returned.</p>
          ) : (
            <>
              <AnonymizationLine info={anonymization && 'tokens' in anonymization ? anonymization : null} />
              <ResultSample columns={columns} rows={sample} modelRows={modelSample} sourceRows={sourceRows} />
            </>
          )}
          {query ? (
            <Disclosure summary="View the executed query">
              <QueryBlock query={query} />
            </Disclosure>
          ) : null}
          {summary.truncated ? (
            <TruncationNotice>
              {String(summary.source_rows ?? '?')} rows returned by the source, cap reached: there were probably more. The model received only {String(summary.returned_rows ?? '?')}, with aggregates; narrow the query rather than concluding on this basis.
            </TruncationNotice>
          ) : null}
          {notes.map((note) => (
            <p key={note} className="text-[13px] text-[var(--slate)]">
              {note}
            </p>
          ))}
        </Inner>
      )
    }
    case 'tool_error':
      return <ErrorNotice message={`${String(event.payload.tool ?? 'Tool')}: ${String(event.payload.message ?? 'call refused')}`} hint={(event.payload.hint as string | null) ?? null} />
    case 'finding_recorded': {
      const finding = event.payload.finding as { title: string; description: string; severity: Severity; evidence_query_ids: string[] } | undefined
      if (!finding) return null
      return (
        <Inner className="border-l-4 !border-l-[var(--amber)] p-4">
          <div className="flex flex-wrap items-center gap-3">
            <SeverityChip severity={finding.severity} small />
            <h3>{finding.title}</h3>
          </div>
          <p className="mt-2 text-[13.5px] leading-relaxed">{finding.description}</p>
          <p className="tech mt-2">Evidence: {finding.evidence_query_ids.join(', ')}</p>
        </Inner>
      )
    }
    case 'budget_alert':
      return (
        <Notice tone="amber">
          Budget {String(event.payload.budget ?? '')} more than 80% consumed.
        </Notice>
      )
    case 'interrupted':
      return (
        <Notice tone="amber">
          Hunt interrupted: {String(event.payload.reason ?? 'reason not specified')}. A partial report has been produced.
        </Notice>
      )
    case 'concluded':
      return (
        <Inner className="border-l-4 !border-l-[var(--indigo)] p-4">
          <p>
            Investigation complete, proposed verdict: <strong>{String(event.payload.proposed_verdict ?? '')}</strong>
          </p>
          <p className="muted mt-1 text-[13px]">Redirecting to the report…</p>
        </Inner>
      )
    default:
      return null
  }
}

function StreamStatus({ connected, finished }: { connected: boolean; finished: boolean }) {
  if (finished)
    return (
      <Chip tone="soft" small>
        finished
      </Chip>
    )
  return (
    <Chip tone={connected ? 'indigo' : 'soft'} small>
      {connected ? <IconSpinner size={14} /> : null}
      {connected ? 'live' : 'connecting…'}
    </Chip>
  )
}

type ActivityKind = 'connecting' | 'thinking' | { query: string } | 'recording'

/** What the agent is doing right now, read from the tail of the thread: a tool call
 *  without its result means a query is running, otherwise the model is reasoning. */
function currentActivity(events: HuntEvent[], connected: boolean): ActivityKind {
  if (!connected) return 'connecting'
  const last = events[events.length - 1]
  if (!last) return 'thinking'
  if (last.type === 'tool_call') {
    const tool = String(last.payload.tool ?? '')
    if (tool === 'record_finding') return 'recording'
    if (tool === 'conclude_hunt') return 'recording'
    const source = tool.includes('sentinel') ? 'Sentinel' : tool.includes('defender') ? 'Defender' : tool.includes('secops') ? 'SecOps' : 'the source'
    return { query: source }
  }
  return 'thinking'
}

function Activity({ kind }: { kind: ActivityKind }) {
  if (kind === 'connecting') {
    return (
      <div className="feed-item activity">
        <span className="dots-pulse" aria-hidden="true"><i /><i /><i /></span>
        <span>Connecting to the investigation thread…</span>
      </div>
    )
  }
  if (typeof kind === 'object') {
    return (
      <div className="feed-item activity" role="status">
        <div className="flex items-center gap-3">
          <IconSpinner size={16} />
          <span>
            Query running on <strong>{kind.query}</strong>, read-only. The result is minimized and pseudonymized before the agent reads it.
          </span>
        </div>
        <div className="bar bar-indeterminate mt-3">
          <span />
        </div>
      </div>
    )
  }
  return (
    <div className="feed-item activity" role="status">
      <span className="dots-pulse" aria-hidden="true"><i /><i /><i /></span>
      <span>{kind === 'recording' ? 'The agent is writing up what it found…' : 'The agent is reading the result and deciding its next step…'}</span>
    </div>
  )
}

type BudgetSnapshot = Record<string, { used: number; limit: number }>

function pendingBudgetPause(events: HuntEvent[]): HuntEvent | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const type = events[index].type
    if (type === 'budget_paused') return events[index]
    if (type === 'budget_extended' || type === 'interrupted' || type === 'concluded' || type === 'failed' || type === 'iteration_started') return null
  }
  return null
}

function BudgetCheckpoint({ huntId, budget }: { huntId: string; budget: string }) {
  const [extraIterations, setExtraIterations] = useState(10)
  const [extraQueries, setExtraQueries] = useState(10)
  const [extraTokens, setExtraTokens] = useState(budget === 'tokens' ? 300_000 : 0)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const decide = async (action: 'extend' | 'stop') => {
    setPending(true)
    setError(null)
    try {
      await api.decideBudget(huntId, {
        action,
        ...(action === 'extend' ? { extra_iterations: extraIterations, extra_siem_queries: extraQueries, extra_minutes: 10, extra_tokens: extraTokens } : {}),
      })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The decision failed.')
      setPending(false)
    }
  }

  return (
    <div className="rounded-[22px] border border-[#ecd9bf] bg-[#f8ebd9]/80 p-5" role="alert">
      <h3>Budget exhausted ({budget}), the investigation is paused.</h3>
      <p className="mt-1 text-[13.5px] text-[var(--slate)]">
        Continue with an additional amount (the agent resumes exactly where it left off), or stop and receive the partial report. Without a response within the time limit, the hunt stops cleanly.
      </p>
      <div className="mt-4 flex flex-wrap items-end gap-3">
        {(
          [
            ['+ iterations', extraIterations, setExtraIterations, 100, 1],
            ['+ SIEM queries', extraQueries, setExtraQueries, 100, 1],
            ['+ tokens', extraTokens, setExtraTokens, 2_000_000, 50_000],
          ] as const
        ).map(([label, value, setter, max, step]) => (
          <label key={label} className="text-[13px]">
            <span className="lbl block">{label}</span>
            <input
              type="number"
              min={0}
              max={max}
              step={step}
              value={value}
              onChange={(event) => setter(Math.min(max, Math.max(0, Number(event.target.value) || 0)))}
              className="field field-pill mono mt-1 w-36"
            />
          </label>
        ))}
        <Btn onClick={() => void decide('extend')} disabled={pending || (extraIterations === 0 && extraQueries === 0 && extraTokens === 0)}>
          Continue
        </Btn>
        <Btn variant="light" onClick={() => void decide('stop')} disabled={pending}>
          Stop and generate the report
        </Btn>
      </div>
      {error ? <p className="mt-2 text-[13px] text-[var(--garnet)]">{error}</p> : null}
    </div>
  )
}

function latestBudgets(events: HuntEvent[]): BudgetSnapshot {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const budgets = events[index].payload.budgets
    if (budgets && typeof budgets === 'object') return budgets as BudgetSnapshot
  }
  return {}
}

function latestIteration(events: HuntEvent[]): string | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    if (events[index].type === 'iteration_started') return String(events[index].payload.iteration ?? '')
  }
  return null
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
    const finding = event.payload.finding as { entities?: { type: string; value: string }[] } | undefined
    for (const entity of finding?.entities ?? []) found.add(`${entity.type}: ${entity.value}`)
  }
  return [...found]
}
