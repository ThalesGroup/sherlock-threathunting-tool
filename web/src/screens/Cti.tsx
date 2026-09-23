/**
 * Screen - CTI analysis.
 *
 * The analyst imports a report (PDF). The agent summarizes the described attacks, extracts
 * the indicators published in the document, then a threat intel probe checks whether IOCs
 * exist online for each threat. The cards only appear once all probes are finished, each
 * with its final recommendation.
 *
 * The analysis state lives in an application store (`ctiStore`): navigation does not
 * interrupt it, the analyst finds the analysis in progress or finished on returning.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, useSyncExternalStore } from 'react'
import { useNavigate } from 'react-router-dom'

import { ErrorNotice, Mono } from '@/components/primitives'
import { api, ApiError, type CtiAttack } from '@/lib/api'
import {
  getCtiState,
  loadCtiAnalysis,
  probeOne,
  startCtiAnalysis,
  subscribeCti,
} from '@/lib/ctiStore'

export function CtiScreen() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const history = useQuery({
    queryKey: ['cti-history'],
    queryFn: api.ctiHistory,
    refetchOnMount: 'always',
  })

  const cti = useSyncExternalStore(subscribeCti, getCtiState)
  const [launching, setLaunching] = useState<number | null>(null)
  const [launchError, setLaunchError] = useState<string | null>(null)

  useEffect(() => {
    if (cti.phase === 'ready') {
      void queryClient.invalidateQueries({ queryKey: ['cti-history'] })
    }
  }, [cti.phase, queryClient])

  const launchByIocs = async (index: number, attack: CtiAttack) => {
    setLaunching(index)
    setLaunchError(null)
    try {
      const created = await api.createHunt({
        campaign: attack.name.slice(0, 120),
        manual_iocs: attack.iocs.map((ioc) => ({ value: ioc.value, type: ioc.type })),
      })
      navigate(
        `/hunts/${created.hunt_id}/indicators?auto=1&campaign=${encodeURIComponent(
          attack.name.slice(0, 120),
        )}`,
      )
    } catch (error) {
      setLaunchError(error instanceof ApiError ? error.message : 'Unable to create the hunt.')
      setLaunching(null)
    }
  }

  const launchByHypothesis = async (index: number, attack: CtiAttack) => {
    setLaunching(index)
    setLaunchError(null)
    try {
      const created = await api.createHunt({
        hypothesis: attack.suggested_hypothesis || `${attack.name} - ${attack.summary}`,
      })
      navigate(`/hunts/${created.hunt_id}/playbook`)
    } catch (error) {
      setLaunchError(error instanceof ApiError ? error.message : 'Unable to create the hunt.')
      setLaunching(null)
    }
  }

  const attacks = cti.analysis?.attacks ?? []
  const busy = cti.phase === 'analyzing' || cti.phase === 'probing'
  const probesDone = Object.values(cti.probes).filter(
    (p) => p.state === 'done' || p.state === 'error',
  ).length

  return (
    <div>
      <header className="mb-5">
        <h1 className="text-[22px] font-semibold tracking-tight text-ink">CTI analysis</h1>
        <p className="meta-text mt-1">
          Import a threat intelligence report (PDF). The agent summarizes the described
          attacks, extracts the published indicators, and checks in threat intel whether
          IOCs exist online - that check is what decides the approach: by indicators when
          there are some, by behavioral hypothesis otherwise.
        </p>
      </header>

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0">
          <div className="card mb-5">
            <h2 className="card-header">Import a report</h2>
            <div className="px-4 py-4">
              <input
                type="file"
                accept="application/pdf,.pdf"
                disabled={busy}
                onChange={(event) => {
                  const file = event.target.files?.[0]
                  if (file) {
                    void startCtiAnalysis(
                      file,
                      config.data?.threat_intel_enabled ?? false,
                    )
                  }
                  event.target.value = ''
                }}
                className="block w-full text-xs text-slate
                  file:mr-3 file:cursor-pointer file:rounded-btn file:border-0
                  file:bg-navy file:px-3.5 file:py-2 file:text-xs file:font-medium
                  file:text-white hover:file:bg-navy-hover"
                aria-label="CTI report in PDF format"
              />
              <p className="mt-2.5 text-xs text-meta">
                Text PDF only (no scans), 80 pages and 15 MB maximum. The document does not
                leave the internal perimeter; its content is treated as untrusted. The
                analysis continues if you navigate away.
              </p>

              {cti.phase === 'analyzing' ? (
                <div className="mt-3" role="status">
                  <div className="mb-1.5 flex items-baseline justify-between">
                    <span className="text-xs text-indigo">
                      Reading and analyzing {cti.filename ?? 'this report'}…
                    </span>
                    <span className="meta-mono">step 1/2</span>
                  </div>
                  <div className="bar-track">
                    <div className="bar-indeterminate" />
                  </div>
                </div>
              ) : null}

              {cti.phase === 'probing' ? (
                <div className="mt-3" role="status">
                  <div className="mb-1.5 flex items-baseline justify-between">
                    <span className="text-xs text-indigo">
                      {attacks.length} attack{attacks.length > 1 ? 's' : ''} identified -
                      checking IOCs online ({probesDone}/{attacks.length})
                    </span>
                    <span className="meta-mono">step 2/2</span>
                  </div>
                  <div className="bar-track">
                    <div
                      className="bar-progress"
                      style={{
                        width: `${Math.max(
                          6,
                          Math.round((probesDone / Math.max(1, attacks.length)) * 100),
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              ) : null}

              {cti.phase === 'ready' && cti.analyzedAt ? (
                <p className="meta-mono mt-3 uppercase" role="status">
                  {cti.filename} · analysis finished at {cti.analyzedAt} · {attacks.length}{' '}
                  attack{attacks.length > 1 ? 's' : ''} · IOCs checked online
                </p>
              ) : null}

              {cti.error ? (
                <div className="mt-3">
                  <ErrorNotice message={cti.error} hint={cti.errorHint} />
                </div>
              ) : null}

              {cti.phase === 'ready' && attacks.length === 0 ? (
                <p className="mt-3 text-xs text-amber" role="status">
                  No attack identified in this document.
                </p>
              ) : null}

              {cti.analysis?.truncated ? (
                <p className="mt-3 text-xs text-amber">
                  Long document: only the first pages were analyzed.
                </p>
              ) : null}
            </div>
          </div>

          {launchError ? (
            <div className="mb-4">
              <ErrorNotice message={launchError} />
            </div>
          ) : null}

          {cti.phase === 'idle' && attacks.length === 0 ? (
            <div className="grid gap-4 sm:grid-cols-3">
              {(
                [
                  [
                    '01',
                    'Import',
                    'Drop in a CTI report: daily digest, vendor analysis, CERT bulletin. The document stays within the internal perimeter.',
                  ],
                  [
                    '02',
                    'Analyze and verify',
                    'The agent summarizes each described attack, extracts the IOCs published in the document, then probes threat intel: do IOCs exist online?',
                  ],
                  [
                    '03',
                    'Launch the right hunt',
                    'Each attack comes with its recommendation: hunt by indicators (IOC validation) or by behavioral hypothesis (direct launch).',
                  ],
                ] as const
              ).map(([step, title, body]) => (
                <div key={step} className="card px-4 py-4">
                  <div className="meta-mono">{step}</div>
                  <div className="mt-2 text-[13px] font-semibold text-ink">{title}</div>
                  <p className="mt-1.5 text-xs leading-relaxed text-slate">{body}</p>
                </div>
              ))}
            </div>
          ) : null}

          {attacks.length > 0 && cti.phase === 'ready' ? (
            <div className="grid gap-4 xl:grid-cols-2">
              {attacks.map((attack, index) => {
                const probeState = cti.probes[index]
                const webIocs = probeState?.state === 'done' ? probeState.result.found : null
                const hasIocs = attack.iocs.length > 0 || (webIocs ?? 0) > 0
                return (
                  <section key={`${attack.name}-${index}`} className="card flex flex-col">
                    <div className="flex items-center justify-between gap-3 border-b border-rule-soft px-4 py-3">
                      <h2 className="text-sm font-semibold text-ink">{attack.name}</h2>
                      <span className="badge bg-[#eef1f4] text-[#5b6b7c]">
                        {attack.kind}
                      </span>
                    </div>
                    <div className="flex flex-1 flex-col px-4 py-3.5">
                      <p className="text-[13px] leading-relaxed text-[#3d4d5c]">
                        {attack.summary}
                      </p>

                      <div className="mt-3.5 rounded-[10px] border border-[#e3e8ed] bg-soft-bg px-3.5 py-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="meta-mono uppercase">
                            {attack.iocs.length} IOCs in the report
                          </span>
                          {probeState?.state === 'error' ? (
                            <button
                              type="button"
                              className="btn-secondary px-2.5 py-1.5 text-[11px]"
                              onClick={() => void probeOne(index, attack)}
                            >
                              Retry the probe
                            </button>
                          ) : null}
                        </div>
                        {probeState?.state === 'done' ? (
                          probeState.result.found > 0 ? (
                            <div className="mt-2 text-xs text-mint">
                              {probeState.result.found}+ IOCs available online (
                              {probeState.result.sources.join(', ')})
                              <span className="mt-1 block font-mono text-[10px] text-slate">
                                {probeState.result.sample
                                  .map((ioc) => ioc.value)
                                  .slice(0, 3)
                                  .join(' · ')}
                              </span>
                            </div>
                          ) : (
                            <p className="mt-2 text-xs text-amber">
                              No IOC published in threat intel: favor behavioral hunting.
                            </p>
                          )
                        ) : null}
                        {probeState?.state === 'error' ? (
                          <p className="mt-2 text-xs text-garnet">{probeState.message}</p>
                        ) : null}
                      </div>

                      {attack.iocs.length > 0 ? (
                        <p className="mt-2.5 truncate font-mono text-[10px] text-meta">
                          {attack.iocs.slice(0, 3).map((ioc) => ioc.value).join(' · ')}
                          {attack.iocs.length > 3 ? ` · +${attack.iocs.length - 3}` : ''}
                        </p>
                      ) : null}

                      <div className="flex-1" aria-hidden="true" />
                      <div className="mt-3.5 flex items-center gap-2 border-t border-rule-soft pt-3.5">
                        <button
                          type="button"
                          className="btn-primary px-3.5 py-2 text-xs"
                          disabled={!hasIocs || launching !== null}
                          title={
                            hasIocs
                              ? undefined
                              : 'No known IOC: start from the hypothesis.'
                          }
                          onClick={() => void launchByIocs(index, attack)}
                        >
                          {launching === index ? 'Creating…' : 'Launch by IOC'}
                        </button>
                        <button
                          type="button"
                          className="btn-secondary"
                          disabled={launching !== null}
                          onClick={() => void launchByHypothesis(index, attack)}
                        >
                          Launch by hypothesis
                        </button>
                        <Mono className="ml-auto text-[10px] text-meta">
                          {hasIocs ? 'IOC → validation' : 'hypothesis → direct'}
                        </Mono>
                      </div>
                    </div>
                  </section>
                )
              })}
            </div>
          ) : null}
        </div>

        <aside className="card">
          <h2 className="card-header">Analyzed reports</h2>
          {history.data && history.data.length > 0 ? (
            history.data.map((entry) => (
              <div
                key={entry.id}
                className={`flex items-start gap-2 border-b border-rule-soft px-4 py-3
                last:border-b-0 ${cti.analysisId === entry.id ? 'bg-[#f4f7fa]' : ''}`}
              >
                <button
                  type="button"
                  className="min-w-0 flex-1 text-left"
                  disabled={busy}
                  title="Reopen this analysis"
                  onClick={() => void loadCtiAnalysis(entry.id)}
                >
                  <span className="block truncate font-mono text-[11px] font-medium text-indigo hover:underline">
                    {entry.filename}
                  </span>
                  <span className="meta-mono mt-1 block">
                    {new Date(entry.analyzed_at).toLocaleString('en-GB', {
                      dateStyle: 'short',
                      timeStyle: 'short',
                    })}{' '}
                    · {entry.analyzed_by}
                  </span>
                  <span className="meta-mono mt-0.5 block uppercase">
                    {entry.attacks} attack{entry.attacks > 1 ? 's' : ''} · {entry.iocs}{' '}
                    IOCs · {entry.pages} page{entry.pages > 1 ? 's' : ''}
                  </span>
                </button>
                <button
                  type="button"
                  className="flex-none px-1 text-[11px] font-medium text-[#9d3b34] hover:underline"
                  title="Delete this analysis from the history"
                  onClick={() => {
                    if (
                      window.confirm(
                        `Delete the analysis of ${entry.filename}? The trace stays in ` +
                          'the audit log.',
                      )
                    ) {
                      void api.deleteCtiAnalysis(entry.id).then(() => {
                        void queryClient.invalidateQueries({ queryKey: ['cti-history'] })
                      })
                    }
                  }}
                >
                  Delete
                </button>
              </div>
            ))
          ) : (
            <p className="meta-text px-4 py-5">
              No report analyzed yet. Each analysis is kept here with its results: click one
              to reopen it.
            </p>
          )}
        </aside>
      </div>
    </div>
  )
}
