/**
 * Playbook screen — third human checkpoint.
 *
 * The agent proposes a plan of leads and a query estimate; the analyst validates, adjusts
 * the budgets or rephrases with an instruction. Nothing goes to a SIEM until the analyst
 * has launched the hunt from this screen: the limit set here is the one the middleware
 * enforces.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import { EmptyState, ErrorNotice, Mono } from '@/components/primitives'
import { api, ApiError, type Playbook } from '@/lib/api'

const SOURCE_LABELS: Record<string, string> = {
  sentinel: 'Sentinel',
  defender: 'Defender',
  secops: 'SecOps',
}

export function PlaybookScreen() {
  const { huntId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const plan = useQuery({
    queryKey: ['plan', huntId],
    queryFn: () => api.getPlan(huntId),
  })

  const [iterations, setIterations] = useState<number | ''>('')
  const [queries, setQueries] = useState<number | ''>('')
  const [instruction, setInstruction] = useState('')
  const autoTriggered = useRef(false)

  const generate = useMutation({
    mutationFn: (text: string | null) => api.planHunt(huntId, text),
    onSuccess: (playbook) => {
      queryClient.setQueryData(['plan', huntId], playbook)
      void queryClient.invalidateQueries({ queryKey: ['hunts'] })
      setInstruction('')
    },
  })

  const launch = useMutation({
    mutationFn: () =>
      api.startHunt(huntId, {
        max_iterations: iterations === '' ? undefined : Number(iterations),
        max_siem_queries: queries === '' ? undefined : Number(queries),
      }),
    onSuccess: () => navigate(`/hunts/${huntId}/feed`),
  })

  useEffect(() => {
    if (
      plan.isSuccess &&
      plan.data === null &&
      !autoTriggered.current &&
      !generate.isPending
    ) {
      autoTriggered.current = true
      generate.mutate(null)
    }
  }, [plan.isSuccess, plan.data, generate])

  useEffect(() => {
    if (plan.data) {
      setIterations(
        plan.data.validated_iterations ?? plan.data.estimated_iterations,
      )
      setQueries(plan.data.validated_queries ?? plan.data.estimated_queries)
    }
  }, [plan.data])

  if (plan.isLoading) return <p className="meta-text">Loading…</p>
  if (plan.error) {
    return (
      <EmptyState title="Hunt unavailable">
        {plan.error instanceof ApiError
          ? plan.error.message
          : 'This hunt could not be found.'}
      </EmptyState>
    )
  }

  const playbook = plan.data ?? null
  const generating = generate.isPending
  const adjusted =
    playbook !== null &&
    (Number(iterations) !== playbook.estimated_iterations ||
      Number(queries) !== playbook.estimated_queries)

  return (
    <article className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_300px]">
      <div className="min-w-0">
        <header className="mb-4">
          <p className="meta-mono uppercase tracking-[0.22em]">
            Checkpoint · playbook
          </p>
          <h1 className="mt-1 text-[21px] font-semibold tracking-tight text-ink">
            The agent&apos;s plan, before any query
          </h1>
          <p className="mt-1.5 max-w-[70ch] text-sm text-slate">
            The agent proposes its leads and estimates the number of queries.
            You validate, adjust the budgets or rephrase. No query goes to a
            SIEM before you launch.{' '}
            <Mono className="text-[11px]">{huntId}</Mono>
          </p>
        </header>

        {generating ? (
          <section className="card mb-4 p-5" aria-live="polite">
            <p className="text-sm text-ink">
              The agent is building its playbook…
            </p>
            <div className="bar-track mt-3">
              <div className="bar-indeterminate" />
            </div>
          </section>
        ) : null}

        {generate.error ? (
          <div className="mb-4">
            <ErrorNotice
              message={
                generate.error instanceof ApiError
                  ? generate.error.message
                  : 'The plan could not be generated.'
              }
              hint={
                generate.error instanceof ApiError ? generate.error.hint : null
              }
            />
          </div>
        ) : null}

        {playbook ? <PlaybookBody playbook={playbook} /> : null}

        <section className="card mt-4 p-5">
          <label htmlFor="instruction" className="label mb-2 block">
            Rephrase with an instruction{' '}
            <span className="text-[#a8b4bf]">optional</span>
          </label>
          <textarea
            id="instruction"
            value={instruction}
            onChange={(event) => setInstruction(event.target.value)}
            rows={2}
            className="field text-sm"
            placeholder="E.g.: ignore Sentinel, focus on macOS persistence."
          />
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => generate.mutate(instruction.trim() || null)}
              disabled={generating || launch.isPending}
            >
              {playbook ? 'Rephrase the plan' : 'Generate the plan'}
            </button>
            <span className="meta-mono">
              Every generation is logged; the previous one is replaced.
            </span>
          </div>
        </section>
      </div>

      <aside className="sticky top-[72px] flex flex-col gap-4 xl:flex">
        <div className="card p-4">
          <div className="label mb-3">Budgets to validate</div>
          <label className="mb-3 block text-sm text-ink">
            SIEM queries
            <input
              type="number"
              min={1}
              max={100}
              value={queries}
              onChange={(event) =>
                setQueries(
                  event.target.value === '' ? '' : Number(event.target.value),
                )
              }
              className="field mt-1 font-mono text-sm"
              disabled={!playbook}
            />
            {playbook ? (
              <span className="meta-mono mt-1 block">
                agent estimate: {playbook.estimated_queries}
              </span>
            ) : null}
          </label>
          <label className="mb-3 block text-sm text-ink">
            Iterations
            <input
              type="number"
              min={1}
              max={100}
              value={iterations}
              onChange={(event) =>
                setIterations(
                  event.target.value === '' ? '' : Number(event.target.value),
                )
              }
              className="field mt-1 font-mono text-sm"
              disabled={!playbook}
            />
            {playbook ? (
              <span className="meta-mono mt-1 block">
                agent estimate: {playbook.estimated_iterations}
              </span>
            ) : null}
          </label>
          {adjusted ? (
            <p className="mb-3 text-xs text-amber">
              Budgets adjusted from the estimate: the difference will be logged.
            </p>
          ) : null}
          <button
            type="button"
            className="btn-primary w-full justify-center"
            disabled={
              !playbook ||
              generating ||
              launch.isPending ||
              queries === '' ||
              iterations === ''
            }
            onClick={() => launch.mutate()}
          >
            {launch.isPending ? 'Launching…' : 'Launch with this plan'}
          </button>
          {launch.error ? (
            <div className="mt-2 space-y-1.5">
              <p className="text-sm text-garnet">
                {launch.error instanceof ApiError
                  ? launch.error.message
                  : 'Launch failed.'}
              </p>
              {launch.error instanceof ApiError && launch.error.hint ? (
                <p className="text-xs text-slate">{launch.error.hint}</p>
              ) : null}
              {launch.error instanceof ApiError &&
              launch.error.code === 'ioc_not_validated' ? (
                <button
                  type="button"
                  className="text-xs text-indigo hover:underline"
                  onClick={() => navigate(`/hunts/${huntId}/indicators`)}
                >
                  Open the indicators screen →
                </button>
              ) : null}
            </div>
          ) : null}
          <p className="meta-mono mt-3">
            If the budget runs out during the hunt, the agent will ask you again
            before continuing.
          </p>
        </div>
      </aside>
    </article>
  )
}

function PlaybookBody({ playbook }: { playbook: Playbook }) {
  return (
    <>
      <section className="card mb-4 p-5">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2 border-b border-navy pb-2">
          <h2 className="text-[15px] font-semibold text-ink">
            Proposed approach
          </h2>
          <span className="meta-mono uppercase">
            {playbook.steps.length} lead(s) · generated on{' '}
            {formatDate(playbook.generated_at)}
          </span>
        </div>
        <p className="max-w-[190ch] whitespace-pre-wrap text-sm leading-relaxed text-[#243544]">
          {playbook.summary}
        </p>
        {playbook.instruction ? (
          <p className="meta-text mt-3">
            Instruction taken into account: “{playbook.instruction}”
          </p>
        ) : null}
      </section>

      <section className="card mb-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule px-5 py-3">
          <h2 className="text-[13px] font-semibold text-ink">Leads</h2>
          <span className="meta-mono uppercase">
            {playbook.estimated_queries} estimated query(ies) ·{' '}
            {playbook.estimated_iterations} iteration(s)
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-soft-bg">
              <tr>
                <th className="meta-mono px-5 py-2 font-medium uppercase">#</th>
                <th className="meta-mono px-3 py-2 font-medium uppercase">
                  SIEM
                </th>
                <th className="meta-mono px-3 py-2 font-medium uppercase">
                  Objective
                </th>
                <th className="meta-mono px-3 py-2 font-medium uppercase">
                  Technique
                </th>
                <th className="meta-mono px-5 py-2 text-right font-medium uppercase">
                  Queries
                </th>
              </tr>
            </thead>
            <tbody>
              {playbook.steps.map((step) => (
                <tr
                  key={step.order}
                  className="border-t border-rule-soft align-top"
                >
                  <td className="px-5 py-2.5">
                    <Mono className="text-[11px] text-meta">{step.order}</Mono>
                  </td>
                  <td className="px-3 py-2.5 text-xs text-slate">
                    {SOURCE_LABELS[step.siem] ?? step.siem}
                  </td>
                  <td className="max-w-[40rem] px-3 py-2.5 text-[13px] text-ink">
                    {step.objective}
                  </td>
                  <td className="px-3 py-2.5">
                    {step.technique ? (
                      <Mono className="rounded-[5px] bg-rule-soft px-2 py-1 text-[9px] font-semibold tracking-[0.1em] text-slate">
                        {step.technique}
                      </Mono>
                    ) : null}
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <Mono className="text-xs font-medium">
                      {step.expected_queries}
                    </Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card p-5">
        <span className="label mb-1.5 block">
          What this plan will not cover
        </span>
        <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-[#3d4d5c]">
          {playbook.not_covered}
        </p>
      </section>
    </>
  )
}

function formatDate(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}
