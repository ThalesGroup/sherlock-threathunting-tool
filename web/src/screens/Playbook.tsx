/**
 * Playbook checkpoint. The agent proposes leads and an estimate; the analyst validates,
 * adjusts the budgets or rephrases with an instruction. The limit set here is the one the
 * middleware enforces.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import { api, ApiError, type Playbook } from '@/lib/api'

import { formatDate, plural, sourceLabel } from '@/components/format'
import { IconAlert, IconArrowRight, IconMinus, IconPlus, IconRefresh, IconSearch } from '@/components/icons'
import { Btn, Chip, Dots, EmptyState, ErrorNotice, Glass, Inner, Stepper } from '@/components/ui'

export function PlaybookScreen() {
  const { huntId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const plan = useQuery({ queryKey: ['plan', huntId], queryFn: () => api.getPlan(huntId) })
  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const summaries = useQuery({ queryKey: ['hunts', { limit: 50 }], queryFn: () => api.listHunts({ limit: 50 }) })
  const hunt = summaries.data?.find((item) => item.hunt_id === huntId)

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
    if (plan.isSuccess && plan.data === null && !autoTriggered.current && !generate.isPending) {
      autoTriggered.current = true
      generate.mutate(null)
    }
  }, [plan.isSuccess, plan.data, generate])

  useEffect(() => {
    if (plan.data) {
      setIterations(plan.data.validated_iterations ?? plan.data.estimated_iterations)
      setQueries(plan.data.validated_queries ?? plan.data.estimated_queries)
    }
  }, [plan.data])

  if (plan.isLoading) return <p className="muted">Loading…</p>
  if (plan.error) {
    return (
      <EmptyState title="Hunt unavailable">{plan.error instanceof ApiError ? plan.error.message : 'This hunt could not be found.'}</EmptyState>
    )
  }

  const playbook = plan.data ?? null
  const generating = generate.isPending
  const adjusted =
    playbook !== null && (Number(iterations) !== playbook.estimated_iterations || Number(queries) !== playbook.estimated_queries)
  const bySource = playbook ? planned(playbook) : {}
  const configured = config.data?.sources.filter((source) => source.configured) ?? []
  const sourcesUsed = playbook ? Object.keys(bySource) : configured.map((source) => source.name)
  const windowDays = configured.filter((source) => sourcesUsed.includes(source.name)).map((source) => source.max_window_days)
  const rowsMax = Math.max(0, ...configured.filter((source) => sourcesUsed.includes(source.name)).map((source) => source.max_rows))

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <p className="tech">
            Hunts / <span className="text-[var(--ink)]">{hunt ? clip(hunt.campaign ?? hunt.hypothesis) : huntId}</span>
          </p>
          <h1 className="mt-1">The agent&apos;s plan, before any query</h1>
          <p className="mt-2 max-w-3xl text-[15px] text-[var(--slate)]">
            The agent proposes its leads and estimates the number of queries. You validate, adjust the budgets or rephrase. No query goes to a SIEM before you launch.
          </p>
        </div>
        <Stepper
          steps={[
            { label: 'Indicators', state: 'done' },
            { label: 'Playbook', state: 'now' },
            { label: 'Verdict', state: 'todo' },
          ]}
        />
      </div>

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 space-y-4">
          {generating ? (
            <Inner className="p-5" aria-live="polite">
              <p className="font-medium">The agent is building its playbook…</p>
              <div className="bar bar-indeterminate mt-3">
                <span />
              </div>
            </Inner>
          ) : null}

          {generate.error ? (
            <ErrorNotice
              message={generate.error instanceof ApiError ? generate.error.message : 'The plan could not be generated.'}
              hint={generate.error instanceof ApiError ? generate.error.hint : null}
            />
          ) : null}

          {playbook ? (
            <>
              <Inner className="flex gap-4 p-5">
                <span className="ic ic-dark !cursor-default">
                  <IconSearch size={20} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <h2>Proposed approach</h2>
                    <Chip tone="soft" small>
                      {playbook.steps.length} {plural(playbook.steps.length, 'lead')}
                    </Chip>
                    <span className="tech">generated {formatDate(playbook.generated_at)}</span>
                  </div>
                  <p className="mt-2 whitespace-pre-wrap text-[15px] leading-relaxed">{playbook.summary}</p>
                  {playbook.instruction ? (
                    <p className="mt-2 text-[13px] text-[var(--slate)]">Instruction taken into account: &ldquo;{playbook.instruction}&rdquo;</p>
                  ) : null}
                </div>
              </Inner>

              <Inner className="p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2>Leads</h2>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(bySource).map(([siem, count]) => (
                      <Chip key={siem} tone={siem === 'sentinel' ? 'indigo' : 'soft'} small>
                        {sourceLabel(siem)} · {count} {plural(count, 'query', 'queries')}
                      </Chip>
                    ))}
                  </div>
                </div>
                <div className="mt-2 overflow-x-auto">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th className="w-14">#</th>
                        <th className="w-28">SIEM</th>
                        <th>Objective</th>
                        <th className="w-32">Technique</th>
                        <th className="w-20 text-right">Queries</th>
                      </tr>
                    </thead>
                    <tbody>
                      {playbook.steps.map((step) => (
                        <tr key={step.order}>
                          <td>
                            <span className="av av-sm !bg-[var(--navy)]">{step.order}</span>
                          </td>
                          <td className="text-[13.5px] text-[var(--slate)]">{sourceLabel(step.siem)}</td>
                          <td className="text-[14px]">{step.objective}</td>
                          <td>{step.technique ? <Chip tone="soft" small className="mono !font-medium">{step.technique}</Chip> : null}</td>
                          <td className="mono text-right text-[13px] font-medium">{step.expected_queries}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Inner>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-[22px] border border-[#ecd9bf] bg-[#f8ebd9]/70 p-5">
                  <div className="flex items-center gap-3">
                    <span className="sm !border-0 !bg-[var(--amber)] !text-white">
                      <IconAlert size={16} />
                    </span>
                    <h3>What this plan will not cover</h3>
                  </div>
                  <p className="mt-3 whitespace-pre-wrap text-[13.5px] leading-relaxed">{playbook.not_covered}</p>
                </div>
                <RephraseCard instruction={instruction} onChange={setInstruction} onSubmit={() => generate.mutate(instruction.trim() || null)} disabled={generating || launch.isPending} hasPlan />
              </div>
            </>
          ) : !generating ? (
            <RephraseCard instruction={instruction} onChange={setInstruction} onSubmit={() => generate.mutate(instruction.trim() || null)} disabled={launch.isPending} hasPlan={false} />
          ) : null}
        </div>

        <aside className="inner flex flex-col p-5">
          <div className="flex items-center justify-between">
            <h2>Budgets to validate</h2>
            <Chip tone="amber" small>
              you decide
            </Chip>
          </div>

          <BudgetControl label="SIEM queries" value={queries} estimate={playbook?.estimated_queries ?? null} onChange={setQueries} disabled={!playbook} />
          <BudgetControl label="Iterations" value={iterations} estimate={playbook?.estimated_iterations ?? null} onChange={setIterations} disabled={!playbook} />

          <dl className="mt-4 space-y-2 text-[13.5px]">
            <div className="flex justify-between gap-3">
              <dt className="text-[var(--slate)]">Sources</dt>
              <dd className="text-right font-medium">{sourcesUsed.length > 0 ? sourcesUsed.map(sourceLabel).join(', ') : '-'}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-[var(--slate)]">Window</dt>
              <dd className="mono text-right">{windowDays.length > 0 ? `last ${Math.min(...windowDays)} d` : '-'}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-[var(--slate)]">Rows per query</dt>
              <dd className="mono text-right">{rowsMax > 0 ? `${rowsMax} max` : '-'}</dd>
            </div>
          </dl>

          {adjusted ? <p className="mt-3 text-[12.5px] text-[var(--amber)]">Budgets adjusted from the estimate: the difference will be logged.</p> : null}

          <div className="mt-auto pt-6">
            <Btn
              className="w-full"
              disabled={!playbook || generating || launch.isPending || queries === '' || iterations === ''}
              onClick={() => launch.mutate()}
              end={<IconArrowRight size={16} />}
            >
              {launch.isPending ? 'Launching…' : 'Launch with this plan'}
            </Btn>
            {launch.error ? (
              <div className="mt-3 space-y-1.5">
                <p className="text-[13px] text-[var(--garnet)]">{launch.error instanceof ApiError ? launch.error.message : 'Launch failed.'}</p>
                {launch.error instanceof ApiError && launch.error.hint ? <p className="text-[12.5px] text-[var(--slate)]">{launch.error.hint}</p> : null}
                {launch.error instanceof ApiError && launch.error.code === 'ioc_not_validated' ? (
                  <button type="button" className="link text-[13px]" onClick={() => navigate(`/hunts/${huntId}/indicators`)}>
                    Open the indicators screen
                  </button>
                ) : null}
              </div>
            ) : null}
            <p className="mt-3 text-center text-[12.5px] text-[var(--slate)]">If the budget runs out during the hunt, the agent will ask you again before continuing.</p>
          </div>
        </aside>
      </Glass>
    </div>
  )
}

function RephraseCard({
  instruction,
  onChange,
  onSubmit,
  disabled,
  hasPlan,
}: {
  instruction: string
  onChange: (value: string) => void
  onSubmit: () => void
  disabled: boolean
  hasPlan: boolean
}) {
  return (
    <Inner className="p-5">
      <label htmlFor="instruction" className="block">
        <span className="font-medium">Rephrase with an instruction</span>{' '}
        <span className="text-[13px] text-[var(--meta)]">optional</span>
      </label>
      <div className="relative mt-3">
        <input
          id="instruction"
          value={instruction}
          onChange={(event) => onChange(event.target.value)}
          className="field field-pill pr-14"
          placeholder="E.g.: ignore Sentinel, focus on macOS persistence."
        />
        <button type="button" className="sm absolute right-1 top-1 !h-10 !w-10 !border-0 !bg-[var(--navy)] !text-white" onClick={onSubmit} disabled={disabled} aria-label={hasPlan ? 'Rephrase the plan' : 'Generate the plan'} title={hasPlan ? 'Rephrase the plan' : 'Generate the plan'}>
          <IconRefresh size={16} />
        </button>
      </div>
      <p className="mt-2 text-[12.5px] text-[var(--slate)]">
        {hasPlan ? 'The agent regenerates the leads; the current plan is kept in the audit log.' : 'Generate the plan from the briefing, optionally guided by an instruction.'}
      </p>
    </Inner>
  )
}

function BudgetControl({
  label,
  value,
  estimate,
  onChange,
  disabled,
}: {
  label: string
  value: number | ''
  estimate: number | null
  onChange: (value: number | '') => void
  disabled: boolean
}) {
  const current = value === '' ? 0 : Number(value)
  const step = (delta: number) => onChange(Math.min(100, Math.max(1, current + delta)))
  return (
    <div className="inner-solid mt-4 p-4">
      <div className="flex items-center justify-between">
        <span className="font-medium">{label}</span>
        {estimate !== null ? <span className="tech">agent estimate {estimate}</span> : null}
      </div>
      <div className="mt-2 flex items-center justify-between gap-2">
        <button type="button" className="sm" onClick={() => step(-1)} disabled={disabled || current <= 1} aria-label={`Decrease ${label}`}>
          <IconMinus size={16} />
        </button>
        <input
          type="number"
          min={1}
          max={100}
          value={value}
          onChange={(event) => onChange(event.target.value === '' ? '' : Number(event.target.value))}
          disabled={disabled}
          className="w-24 border-0 bg-transparent text-center text-[34px] font-medium tracking-tight outline-none"
          aria-label={label}
        />
        <button type="button" className="sm" onClick={() => step(1)} disabled={disabled || current >= 100} aria-label={`Increase ${label}`}>
          <IconPlus size={16} />
        </button>
      </div>
      <div className="mt-2">
        <Dots value={current} max={Math.max(current, estimate ?? 0, 12)} />
      </div>
    </div>
  )
}

function clip(text: string): string {
  return text.length > 90 ? `${text.slice(0, 90)}…` : text
}

function planned(playbook: Playbook): Record<string, number> {
  const result: Record<string, number> = {}
  for (const step of playbook.steps) result[step.siem] = (result[step.siem] ?? 0) + step.expected_queries
  return result
}
