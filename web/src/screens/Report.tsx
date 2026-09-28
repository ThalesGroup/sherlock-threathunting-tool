/**
 * Investigation report.
 *
 * The top of the page is the decision surface: the attack, the findings and the agent's
 * proposal next to the four verdict tiles. Recommendation, limitations, playbook,
 * timeline, entities, execution log, indicators, the full queries with their anonymized
 * samples, the resume options and the exports follow below. A finding that cannot be tied
 * to a query does not exist; the verdict is a proposal until the analyst records theirs.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { api, ApiError, type AnonymizationInfo, type ExecutedQuery, type Finding, type Verdict } from '@/lib/api'

import { downloadBlob, downloadText, firstLine, formatDate, formatDuration, formatTime, formatWindow, plural, sourceLabel } from '@/components/format'
import { IconArrowRight, IconArrowUpRight, IconCheck, IconDownload } from '@/components/icons'
import {
  AnonymizationLine,
  Avatar,
  Btn,
  Chip,
  ConfidenceText,
  EmptyState,
  ErrorNotice,
  Glass,
  Inner,
  Mono,
  Notice,
  QueryBlock,
  ResultSample,
  SEVERITY_COLORS,
  SeverityMark,
  Stepper,
  Tile,
  TruncationNotice,
  VERDICT_COLORS,
  VERDICT_TITLES,
  VerdictChip,
} from '@/components/ui'

const VERDICTS: Verdict[] = ['benign', 'suspicious', 'escalate', 'inconclusive']

export function ReportScreen() {
  const { huntId = '' } = useParams()
  const queryClient = useQueryClient()
  const report = useQuery({ queryKey: ['report', huntId], queryFn: () => api.report(huntId) })

  const [verdict, setVerdict] = useState<Verdict | null>(null)
  const [comment, setComment] = useState('')
  const [resumeFrom, setResumeFrom] = useState<string | null>(null)

  const decide = useMutation({
    mutationFn: () => api.decide(huntId, verdict!, comment.trim() || null),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['report', huntId] })
      void queryClient.invalidateQueries({ queryKey: ['hunts'] })
    },
  })
  const exportMarkdown = useMutation({ mutationFn: () => api.reportMarkdown(huntId), onSuccess: (markdown) => downloadText(`${huntId}.md`, markdown) })
  const exportPdf = useMutation({ mutationFn: () => api.reportPdf(huntId), onSuccess: (blob) => downloadBlob(`${huntId}.pdf`, blob) })

  if (report.isLoading) return <p className="muted">Loading the report…</p>

  if (report.error) {
    return (
      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <EmptyState title="Report unavailable">
          This hunt did not produce a report: it may still be running, or it was interrupted before its conclusion (for example by a server restart). If it is finished or interrupted, you can resume it: the new investigation will receive its progress rebuilt from the audit log.
        </EmptyState>
        <ResumeCard huntId={huntId} queries={[]} />
      </Glass>
    )
  }

  const data = report.data!
  const iterations = data.budgets.iterations
  const siemQueries = data.budgets.siem_queries
  const duration = data.budgets.duration_seconds
  const totalRows = data.executed_queries.reduce((sum, q) => sum + q.source_rows, 0)
  const entities = observedEntities(data.findings)
  const severityCounts = countBy(data.findings.map((f) => f.severity))
  const decided = data.human_decision

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0 max-w-4xl">
          <p className="tech">
            <Link to="/history" className="hover:underline">
              Reports
            </Link>{' '}
            / <span className="text-[var(--ink)]">{data.hunt_id}</span>
            {data.parent_hunt_id ? (
              <>
                {' '}
                · resumed from{' '}
                <Link to={`/hunts/${data.parent_hunt_id}/report`} className="link">
                  {data.parent_hunt_id}
                </Link>
              </>
            ) : null}
          </p>
          <h1 className="mt-1 !text-[32px] !leading-tight">{data.hypothesis}</h1>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {data.campaign ? <Chip tone="soft" small>{data.campaign}</Chip> : null}
            {data.partial ? (
              <Chip tone="amber" small>
                partial
              </Chip>
            ) : null}
            {data.status === 'interrupted' ? (
              <Chip tone="garnet" small>
                interrupted
              </Chip>
            ) : null}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Stepper
            steps={[
              { label: 'Indicators', state: 'done' },
              { label: 'Playbook', state: 'done' },
              { label: 'Your verdict', state: decided ? 'done' : 'now' },
            ]}
          />
          <details className="relative">
            <summary className="ic" title="Export the report">
              <IconDownload size={20} />
            </summary>
            <div className="pop !bottom-auto !left-auto !right-0 !top-full !mt-2 !w-56">
              <button type="button" className="block w-full py-2 text-left text-[13.5px] hover:underline" onClick={() => exportMarkdown.mutate()}>
                Export Markdown
              </button>
              <button type="button" className="block w-full py-2 text-left text-[13.5px] hover:underline" onClick={() => exportPdf.mutate()} disabled={exportPdf.isPending}>
                {exportPdf.isPending ? 'Exporting…' : 'Export PDF'}
              </button>
            </div>
          </details>
        </div>
      </div>

      {data.partial ? (
        <Notice tone="amber">
          Partial report: the hunt was interrupted ({data.interruption_reason ?? 'reason not specified'}).
        </Notice>
      ) : null}

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(300px,0.9fr)_minmax(0,1.6fr)_minmax(300px,0.9fr)]">
        <Inner className="flex flex-col p-5">
          <div className="flex items-center justify-between">
            <h2>The attack</h2>
            <a href="#scope" className="sm" title="Hunt scope">
              <IconArrowUpRight size={16} />
            </a>
          </div>
          {data.attack_overview ? (
            <>
              <p className="mt-3 text-[13.5px] leading-relaxed">{data.attack_overview.description}</p>
              {data.attack_overview.techniques.length > 0 ? (
                <ol className="mt-4 space-y-2 border-t border-[var(--rule-soft)] pt-4">
                  {data.attack_overview.techniques.map((technique, index) => (
                    <li key={technique.id} className="flex items-start gap-3">
                      <span className="av !bg-[var(--navy)]">{index + 1}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-[13.5px] font-semibold">{technique.name}</span>
                        <span className="tech block">
                          {technique.id} · {technique.description}
                        </span>
                      </span>
                      <span className="sm !cursor-default" aria-hidden="true">
                        <IconCheck size={16} className="text-[var(--mint)]" />
                      </span>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="muted mt-3 text-[13px]">No MITRE ATT&amp;CK technique was tied to this hunt by the agent.</p>
              )}
            </>
          ) : null}

          <div className="mt-auto grid grid-cols-2 gap-3 pt-6">
            <Tile label="Analyst">
              <span className="flex items-center gap-2">
                <Avatar name={data.analyst} small /> {data.analyst}
              </span>
            </Tile>
            <Tile label="Window">
              <span className="mono text-[13px]">{formatWindow(data.investigation_window)}</span>
            </Tile>
            <Tile label="Sources">{data.sources.length > 0 ? data.sources.map(sourceLabel).join(', ') : 'none'}</Tile>
            <Tile label="Budget">
              <span className="mono text-[13px]">
                {siemQueries ? `${siemQueries.used}/${siemQueries.limit} q` : '-'} · {iterations ? `${iterations.used}/${iterations.limit} it` : '-'}
              </span>
            </Tile>
          </div>
        </Inner>

        <Inner className="flex flex-col p-5">
          <div className="flex flex-wrap items-center gap-3">
            <h2>Findings</h2>
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) =>
              severityCounts[severity] ? (
                <Chip key={severity} small tone={severity === 'critical' ? 'garnet' : severity === 'high' ? 'amber' : severity === 'medium' ? 'olive' : severity === 'low' ? 'mint' : 'soft'}>
                  {severityCounts[severity]} {severity}
                </Chip>
              ) : null,
            )}
          </div>
          {data.findings.length === 0 ? (
            <p className="muted mt-4 text-[13.5px]">No finding recorded.</p>
          ) : (
            <ul className="mt-2">
              {data.findings.map((finding) => (
                <li key={finding.id} id={finding.id} className="flex scroll-mt-24 items-start gap-3 border-t border-[var(--rule-soft)] py-3.5 first:border-t-0">
                  <SeverityMark severity={finding.severity} />
                  <div className="min-w-0 flex-1">
                    <h3 className="!text-[14.5px] !font-semibold">{finding.title}</h3>
                    <p className="tech mt-0.5">
                      {finding.entities.slice(0, 2).map((entity) => `${entity.type}:${entity.value}`).join(' · ')}
                      {finding.entities.length > 0 ? ' · ' : ''}
                      {finding.evidence_query_ids.join(', ')} · <ConfidenceText confidence={finding.confidence} />
                    </p>
                    <p className="mt-2 whitespace-pre-wrap text-[13.5px] leading-relaxed">{finding.description}</p>
                    {finding.entities.length > 0 ? (
                      <ul className="mt-2 flex flex-wrap gap-1.5">
                        {finding.entities.map((entity) => (
                          <li key={`${entity.type}:${entity.value}`} className="chip chip-sm !bg-white/80">
                            <span className="tech uppercase">{entity.type}</span>
                            <span className="mono text-[11.5px] font-medium">{entity.value}</span>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                  <a href={`#${finding.evidence_query_ids[0]}`} className="sm" title="Open the evidence">
                    <IconArrowUpRight size={16} />
                  </a>
                </li>
              ))}
            </ul>
          )}

          {data.playbook ? (
            <div className="mt-auto rounded-[18px] bg-white/60 p-4 pt-5">
              <p className="tech">Playbook · {data.playbook.validated_by ? `validated by ${data.playbook.validated_by}` : 'not validated'}</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {data.playbook.steps.map((step) => (
                  <Chip key={step.order} small>
                    {step.order} · {step.objective.length > 48 ? `${step.objective.slice(0, 48)}…` : step.objective}
                  </Chip>
                ))}
              </div>
            </div>
          ) : null}
        </Inner>

        <div className="flex flex-col gap-3">
          <Inner className="p-5">
            <p className="text-[13px] text-[var(--slate)]">Agent proposes</p>
            <div className="mt-1 flex items-center gap-3">
              <span className="text-[30px] font-medium leading-none" style={{ color: VERDICT_COLORS[data.proposed_verdict] }}>
                {VERDICT_TITLES[data.proposed_verdict]}
              </span>
            </div>
            <p className="mt-3 whitespace-pre-wrap text-[13.5px] leading-relaxed">{data.summary}</p>
          </Inner>

          {decided ? (
            <Inner className="p-5">
              <p className="text-[13px] text-[var(--slate)]">Your verdict</p>
              <div className="mt-1 flex items-center gap-3">
                <span className="text-[26px] font-medium leading-none" style={{ color: VERDICT_COLORS[decided.verdict] }}>
                  {VERDICT_TITLES[decided.verdict]}
                </span>
                <VerdictChip verdict={decided.verdict} small />
              </div>
              <p className="tech mt-2">
                validated by {decided.decided_by} · {formatDate(decided.decided_at)}
              </p>
              {decided.comment ? <p className="mt-3 whitespace-pre-wrap text-[13.5px] leading-relaxed">{decided.comment}</p> : null}
            </Inner>
          ) : (
            <>
              <fieldset className="grid grid-cols-2 gap-3">
                <legend className="sr-only">Your verdict</legend>
                {VERDICTS.map((option) => {
                  const active = verdict === option
                  const proposed = option === data.proposed_verdict
                  return (
                    <label key={option} className={`tile cursor-pointer transition-colors ${active ? '!bg-[var(--navy)] text-white' : 'hover:bg-white'}`}>
                      <input type="radio" name="verdict" value={option} checked={active} onChange={() => setVerdict(option)} className="sr-only" />
                      <span className={`text-[13px] ${active ? 'text-white/80' : 'text-[var(--slate)]'}`}>{proposed ? 'Proposed' : 'Verdict'}</span>
                      <span className="text-[19px] font-medium" style={{ color: active ? '#fff' : VERDICT_COLORS[option] }}>
                        {VERDICT_TITLES[option]}
                      </span>
                    </label>
                  )
                })}
              </fieldset>
              <textarea value={comment} onChange={(event) => setComment(event.target.value)} rows={3} className="field !rounded-[22px] !p-4 text-[13.5px]" placeholder="Notes for the audit log (optional)" aria-label="Decision comment" />
              {decide.error ? <ErrorNotice message={decide.error instanceof ApiError ? decide.error.message : 'The decision could not be recorded.'} /> : null}
              <p className="text-[12.5px] text-[var(--slate)]">You confirm, correct or overturn the agent&apos;s proposal. Your decision is timestamped and attributed to you; no decision is recorded before validation.</p>
              <div className="mt-auto pt-2">
                <Btn className="w-full" disabled={!verdict || decide.isPending} onClick={() => decide.mutate()} end={<IconArrowRight size={16} />}>
                  {decide.isPending ? 'Recording…' : 'Submit and close the hunt'}
                </Btn>
              </div>
            </>
          )}
        </div>
      </Glass>

      <Glass className="grid gap-5 p-5 md:grid-cols-2">
        {data.recommendation ? (
          <Inner className="p-5">
            <h2 className="!text-[19px]">Recommendation</h2>
            <p className="mt-2 whitespace-pre-wrap text-[13.5px] leading-relaxed">{data.recommendation}</p>
          </Inner>
        ) : null}
        <Inner className="p-5">
          <h2 className="!text-[19px]">Investigation limitations</h2>
          <p className="mt-2 whitespace-pre-wrap text-[13.5px] leading-relaxed">{data.limitations}</p>
        </Inner>
        {data.attack_overview ? (
          <Inner className="p-5 md:col-span-2" id="scope">
            <h2 className="!text-[19px]">Hunt scope</h2>
            <p className="mt-2 text-[13.5px] leading-relaxed">{data.attack_overview.scope}</p>
          </Inner>
        ) : null}
      </Glass>

      {data.playbook ? (
        <Glass className="p-5">
          <Inner className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2>Playbook</h2>
              <span className="tech">
                {data.playbook.validated_by
                  ? `validated by ${data.playbook.validated_by} · ${data.playbook.validated_queries} queries / ${data.playbook.validated_iterations} iterations`
                  : 'not validated'}{' '}
                · estimate {data.playbook.estimated_queries} / {data.playbook.estimated_iterations} · executed {data.executed_queries.length}
              </span>
            </div>
            <p className="mt-2 text-[13.5px] leading-relaxed">{data.playbook.summary}</p>
            <table className="tbl mt-3">
              <thead>
                <tr>
                  <th className="w-12">#</th>
                  <th className="w-28">SIEM</th>
                  <th>Objective</th>
                  <th className="w-32">Technique</th>
                  <th className="w-20 text-right">Planned</th>
                </tr>
              </thead>
              <tbody>
                {data.playbook.steps.map((step) => (
                  <tr key={step.order}>
                    <td className="mono text-[12.5px] text-[var(--slate)]">{step.order}</td>
                    <td className="text-[13.5px] text-[var(--slate)]">{sourceLabel(step.siem)}</td>
                    <td className="text-[13.5px]">{step.objective}</td>
                    <td>{step.technique ? <Chip tone="soft" small className="mono !font-medium">{step.technique}</Chip> : null}</td>
                    <td className="mono text-right text-[13px] font-medium">{step.expected_queries}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="mt-4 rounded-[18px] bg-white/60 p-4">
              <span className="lbl">Not covered by the plan</span>
              <p className="mt-1 whitespace-pre-wrap text-[13.5px] leading-relaxed">{data.playbook.not_covered}</p>
            </div>
          </Inner>
        </Glass>
      ) : null}

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-5">
          {data.timeline.length > 0 ? (
            <Inner className="p-5">
              <h2>Timeline</h2>
              <ol className="mt-4 space-y-3 border-l border-[var(--rule)] pl-5">
                {data.timeline.map((event, index) => (
                  <li key={`${event.timestamp}-${index}`} className="relative">
                    <span className="absolute -left-[1.45rem] top-1.5 h-2.5 w-2.5 rounded-full bg-[var(--accent)]" aria-hidden="true" />
                    <Mono className="text-[12px] text-[var(--slate)]">{event.timestamp}</Mono>
                    <p className="text-[13.5px]">{event.event}</p>
                    <p className="tech">{event.source}</p>
                  </li>
                ))}
              </ol>
            </Inner>
          ) : null}

          {entities.length > 0 ? (
            <Inner className="p-5">
              <div className="flex items-center justify-between">
                <h2>Observed entities</h2>
                <span className="tech">{entities.length} cited by the findings</span>
              </div>
              <table className="tbl mt-2">
                <thead>
                  <tr>
                    <th className="w-28">Type</th>
                    <th>Value</th>
                    <th>Context</th>
                    <th className="w-16 text-right">Occ.</th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((entry) => (
                    <tr key={entry.key}>
                      <td className="tech uppercase">{entry.type}</td>
                      <td className="mono text-[13px] font-medium">{entry.value}</td>
                      <td className="text-[13px] text-[var(--slate)]">
                        <a href={`#${entry.findings[0].id}`} className="hover:underline">
                          {entry.findings[0].title}
                        </a>
                      </td>
                      <td className="mono text-right text-[13px] font-medium">{entry.findings.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Inner>
          ) : null}

          {data.executed_queries.length > 0 ? (
            <Inner className="p-5">
              <div className="flex items-center justify-between">
                <h2>Execution log</h2>
                <span className="tech">
                  {data.executed_queries.length} {plural(data.executed_queries.length, 'query', 'queries')}
                  {duration ? ` · ${formatDuration(duration.used)}` : ''} · {totalRows} events read
                </span>
              </div>
              <table className="tbl mt-2">
                <thead>
                  <tr>
                    <th className="w-24">Time</th>
                    <th className="w-32">Reference</th>
                    <th className="w-24">SIEM</th>
                    <th>Objective</th>
                    <th className="w-16 text-right">Rows</th>
                  </tr>
                </thead>
                <tbody>
                  {data.executed_queries.map((query) => (
                    <tr key={query.query_id}>
                      <td className="mono text-[12px] text-[var(--slate)]">{formatTime(query.executed_at)}</td>
                      <td>
                        <a href={`#${query.query_id}`} className="link mono text-[12px]">
                          {query.query_id}
                        </a>
                      </td>
                      <td className="tech uppercase">{query.siem}</td>
                      <td className="max-w-[28rem] text-[13px]">{query.intent ?? <Mono className="block truncate text-[11.5px]">{firstLine(query.query)}</Mono>}</td>
                      <td className="mono text-right text-[12.5px] font-medium">
                        {query.returned_rows}
                        {query.truncated ? ' ⚠' : ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Inner>
          ) : null}

          {data.iocs.length > 0 ? (
            <Inner className="p-5">
              <h2>Indicators</h2>
              <ul className="mt-2">
                {data.iocs.map((ioc) => (
                  <li key={`${ioc.type}:${ioc.value}`} className="flex flex-wrap items-center gap-3 border-t border-[var(--rule-soft)] py-2.5 first:border-t-0">
                    <Mono className="text-[12.5px] font-medium">{ioc.value}</Mono>
                    <Chip tone="soft" small>
                      {ioc.type}
                    </Chip>
                    <Chip tone={ioc.status === 'validated' ? 'mint' : ioc.status === 'rejected' ? 'garnet' : 'amber'} small>
                      {ioc.status.replace('_', ' ')}
                    </Chip>
                    {ioc.source_url.startsWith('internal://') ? (
                      <span className="text-[13px] text-[var(--slate)]">{ioc.source}</span>
                    ) : (
                      <a href={ioc.source_url} target="_blank" rel="noreferrer noopener" className="link text-[13px]">
                        {ioc.source}
                      </a>
                    )}
                  </li>
                ))}
              </ul>
            </Inner>
          ) : null}

          <Inner className="p-5">
            <h2>Appendix · executed queries</h2>
            <p className="text-[13px] text-[var(--slate)]">Full text, the agent&apos;s reading, and the sample as the analyst sees it versus what the model received.</p>
            <div className="mt-4 space-y-6">
              {data.executed_queries.map((query) => (
                <div key={query.query_id} id={query.query_id} className="scroll-mt-24 space-y-2 border-t border-[var(--rule-soft)] pt-4 first:border-t-0 first:pt-0">
                  <div className="flex flex-wrap items-center gap-3">
                    <Mono className="text-[12.5px] font-medium text-[var(--indigo)]">{query.query_id}</Mono>
                    <Chip tone="navy" small className="uppercase">
                      {query.siem}
                    </Chip>
                    <span className="tech">
                      {query.returned_rows} row(s) · {formatDate(query.executed_at)}
                    </span>
                  </div>
                  {query.intent ? <p className="text-[14px] font-medium">{query.intent}</p> : null}
                  <QueryBlock query={query.query} />
                  <AnonymizationLine info={query.anonymization} />
                  <ResultSample columns={query.columns} rows={query.sample} modelRows={query.model_sample} sourceRows={query.source_rows} />
                  {query.interpretation ? (
                    <div className="rounded-[18px] bg-white/60 p-4">
                      <span className="lbl">The agent&apos;s reading</span>
                      <p className="mt-1 whitespace-pre-wrap text-[13.5px] leading-relaxed">{query.interpretation}</p>
                    </div>
                  ) : null}
                  {query.truncated ? (
                    <TruncationNotice>
                      {query.source_rows} rows returned by the source, cap reached: the result is not exhaustive. The model received {query.returned_rows}
                      {query.source_rows > query.returned_rows ? ' (with aggregates)' : ''}.
                    </TruncationNotice>
                  ) : null}
                  <button
                    type="button"
                    className="link text-[13px]"
                    onClick={() => {
                      setResumeFrom(query.query_id)
                      document.getElementById('card-resume')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
                    }}
                  >
                    Resume the investigation from here
                  </button>
                </div>
              ))}
            </div>
          </Inner>
        </div>

        <aside className="space-y-4 xl:sticky xl:top-6 xl:self-start">
          {data.findings.length > 0 ? (
            <Inner className="p-5">
              <span className="lbl">Contents</span>
              <nav className="mt-2" aria-label="Findings summary">
                {data.findings.map((finding) => (
                  <a key={finding.id} href={`#${finding.id}`} className="flex gap-2.5 border-t border-[var(--rule-soft)] py-2.5 text-[13px] leading-snug first:border-t-0 hover:underline">
                    <span className="mt-1.5 h-2 w-2 flex-none rounded-full" style={{ background: SEVERITY_COLORS[finding.severity] }} aria-hidden="true" />
                    {finding.title}
                  </a>
                ))}
              </nav>
            </Inner>
          ) : null}
          <ResumeCard huntId={data.hunt_id} queries={data.executed_queries} prefillFromQuery={resumeFrom} />
          <Inner className="p-5">
            <span className="lbl">Execution</span>
            <dl className="mono mt-2 text-[12.5px]">
              {(
                [
                  ['iterations', iterations ? `${iterations.used} / ${iterations.limit}` : '-'],
                  ['SIEM queries', siemQueries ? `${siemQueries.used} / ${siemQueries.limit}` : '-'],
                  ['events read', String(totalRows)],
                  ['findings', String(data.findings.length)],
                  ['duration', duration ? formatDuration(duration.used) : '-'],
                  ['anonymization', anonymizationSummary(data.executed_queries)],
                  ['generated', formatDate(data.generated_at)],
                ] as [string, string][]
              ).map(([key, value]) => (
                <div key={key} className="flex justify-between gap-3 border-t border-[var(--rule-soft)] py-1.5 first:border-t-0">
                  <dt className="text-[var(--slate)]">{key}</dt>
                  <dd className="text-right font-medium">{value}</dd>
                </div>
              ))}
            </dl>
          </Inner>
        </aside>
      </Glass>
    </div>
  )
}

function ResumeCard({ huntId, queries, prefillFromQuery = null }: { huntId: string; queries: ExecutedQuery[]; prefillFromQuery?: string | null }) {
  const navigate = useNavigate()
  const [instruction, setInstruction] = useState('')
  const [fromQuery, setFromQuery] = useState('')
  useEffect(() => {
    if (prefillFromQuery) setFromQuery(prefillFromQuery)
  }, [prefillFromQuery])
  const options = useQuery({ queryKey: ['resume-options', huntId], queryFn: () => api.resumeOptions(huntId) })

  const continueInPlace = useMutation({
    mutationFn: () => api.continueHunt(huntId, instruction.trim() ? { instruction: instruction.trim() } : {}),
    onSuccess: () => navigate(`/hunts/${huntId}/feed`),
  })
  const resume = useMutation({
    mutationFn: () =>
      api.resumeHunt(huntId, {
        ...(instruction.trim() ? { instruction: instruction.trim() } : {}),
        ...(fromQuery ? { from_query_id: fromQuery } : {}),
      }),
    onSuccess: (created) => navigate(`/hunts/${created.hunt_id}/playbook`),
  })

  return (
    <Inner className="p-5" id="card-resume">
      <span className="lbl">Resume this hunt</span>
      <textarea value={instruction} onChange={(event) => setInstruction(event.target.value)} rows={2} className="field mt-2 !rounded-[18px] text-[13.5px]" placeholder="Question or instruction for what follows (optional)" aria-label="Instruction for the resume" />
      {options.data?.continuable ? (
        <div className="mt-3 border-b border-[var(--rule-soft)] pb-4">
          <p className="text-[12.5px] text-[var(--slate)]">
            {options.data.status === 'awaiting_review'
              ? 'Same investigation: the agent starts again from its memory, its queries and its findings, with your instruction, and will conclude again. This report will be replaced; the previous one stays in the audit trail. Once the verdict is validated, the hunt is frozen.'
              : 'Same investigation: the agent starts again from its memory, its queries and its findings, with your instruction and its remaining budgets. If they are exhausted, it will ask you for an extension in the feed.'}
          </p>
          <Btn className="mt-3 w-full" size="sm" onClick={() => continueInPlace.mutate()} disabled={continueInPlace.isPending}>
            {continueInPlace.isPending ? 'Resuming…' : 'Continue the same investigation'}
          </Btn>
          {continueInPlace.error ? <p className="mt-2 text-[13px] text-[var(--garnet)]">{continueInPlace.error instanceof ApiError ? continueInPlace.error.message : 'Cannot resume.'}</p> : null}
        </div>
      ) : null}
      <p className="mt-3 text-[12.5px] text-[var(--slate)]">
        {options.data?.continuable ? 'Or start over in a n' : 'N'}ew linked investigation, with a new hunt and a new report: it inherits the validated indicators and this hunt&apos;s progress, and goes through the playbook again. This report stays unchanged.
      </p>
      <label className="mt-3 block text-[13px]">
        <span className="lbl">Resume after</span>
        <select value={fromQuery} onChange={(event) => setFromQuery(event.target.value)} className="field field-pill mono mt-1 text-[12.5px]">
          <option value="">the end of the hunt</option>
          {queries.map((query) => (
            <option key={query.query_id} value={query.query_id}>
              {query.query_id} · {query.siem}
            </option>
          ))}
        </select>
      </label>
      <Btn variant="light" className="mt-3 w-full" size="sm" onClick={() => resume.mutate()} disabled={resume.isPending}>
        {resume.isPending ? 'Creating…' : 'New linked investigation'}
      </Btn>
      {resume.error ? <p className="mt-2 text-[13px] text-[var(--garnet)]">{resume.error instanceof ApiError ? resume.error.message : 'Cannot resume.'}</p> : null}
    </Inner>
  )
}

interface ObservedEntity {
  key: string
  type: string
  value: string
  findings: Finding[]
}

function observedEntities(findings: Finding[]): ObservedEntity[] {
  const seen = new Map<string, ObservedEntity>()
  for (const finding of findings) {
    for (const entity of finding.entities) {
      const key = `${entity.type.toLowerCase()}:${entity.value}`
      const entry = seen.get(key)
      if (entry) entry.findings.push(finding)
      else seen.set(key, { key, type: entity.type, value: entity.value, findings: [finding] })
    }
  }
  return [...seen.values()].sort((a, b) => b.findings.length - a.findings.length)
}

function countBy(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1
  return counts
}

function anonymizationSummary(queries: ExecutedQuery[]): string {
  const traced = queries.map((query) => query.anonymization).filter((info): info is AnonymizationInfo => info !== null && 'tokens' in info)
  if (traced.length === 0) return 'not traced'
  if (traced.some((info) => !info.tokenization)) return 'tokenization disabled'
  const degraded = traced.filter((info) => info.semantic === 'degraded').length
  const disabled = traced.filter((info) => info.semantic === 'disabled').length
  if (degraded > 0) return `semantic degraded ${degraded}/${traced.length}`
  if (disabled === traced.length) return 'deterministic only'
  return `semantic active ${traced.length - disabled}/${traced.length}`
}
