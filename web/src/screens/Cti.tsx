/**
 * CTI analysis. The analyst imports a report (PDF); the agent summarizes the described
 * attacks, extracts the published indicators and probes threat intel. State lives in the
 * shared store so navigation does not interrupt an analysis.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, useSyncExternalStore, type DragEvent } from 'react'
import { useNavigate } from 'react-router-dom'

import { api, ApiError, type CtiAttack } from '@/lib/api'
import { getCtiState, loadCtiAnalysis, probeOne, startCtiAnalysis, subscribeCti } from '@/lib/ctiStore'

import { formatShort, plural } from '@/components/format'
import { IconArrowRight, IconCheck, IconFileUp, IconTrash } from '@/components/icons'
import { Avatar, Btn, Chip, ErrorNotice, Glass, Inner, Notice, Stepper, type StepState } from '@/components/ui'

const KIND_TONES: Record<string, 'indigo' | 'garnet' | 'amber' | 'soft'> = {
  campaign: 'indigo',
  malware: 'garnet',
  vulnerability: 'amber',
  actor: 'amber',
  other: 'soft',
}

export function CtiScreen() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const history = useQuery({ queryKey: ['cti-history'], queryFn: api.ctiHistory, refetchOnMount: 'always' })

  const cti = useSyncExternalStore(subscribeCti, getCtiState)
  const [launching, setLaunching] = useState<number | null>(null)
  const [launchError, setLaunchError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)

  useEffect(() => {
    if (cti.phase === 'ready') void queryClient.invalidateQueries({ queryKey: ['cti-history'] })
  }, [cti.phase, queryClient])

  const attacks = cti.analysis?.attacks ?? []
  const busy = cti.phase === 'analyzing' || cti.phase === 'probing'
  const probesDone = Object.values(cti.probes).filter((p) => p.state === 'done' || p.state === 'error').length

  const start = (file: File | undefined) => {
    if (file) void startCtiAnalysis(file, config.data?.threat_intel_enabled ?? false)
  }
  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)
    if (!busy) start(event.dataTransfer.files?.[0])
  }

  const launchByIocs = async (index: number, attack: CtiAttack) => {
    setLaunching(index)
    setLaunchError(null)
    try {
      const created = await api.createHunt({ origin: 'cti', campaign: attack.name.slice(0, 120), manual_iocs: attack.iocs.map((ioc) => ({ value: ioc.value, type: ioc.type })) })
      navigate(`/hunts/${created.hunt_id}/indicators?auto=1&campaign=${encodeURIComponent(attack.name.slice(0, 120))}`)
    } catch (error) {
      setLaunchError(error instanceof ApiError ? error.message : 'Unable to create the hunt.')
      setLaunching(null)
    }
  }
  const launchByHypothesis = async (index: number, attack: CtiAttack) => {
    setLaunching(index)
    setLaunchError(null)
    try {
      const created = await api.createHunt({ origin: 'cti', hypothesis: attack.suggested_hypothesis || `${attack.name} - ${attack.summary}` })
      navigate(`/hunts/${created.hunt_id}/playbook`)
    } catch (error) {
      setLaunchError(error instanceof ApiError ? error.message : 'Unable to create the hunt.')
      setLaunching(null)
    }
  }

  const steps: { label: string; state: StepState }[] = [
    { label: 'Import', state: cti.phase === 'idle' ? 'now' : 'done' },
    { label: 'Analyze and verify', state: cti.phase === 'analyzing' || cti.phase === 'probing' ? 'now' : cti.phase === 'ready' ? 'done' : 'todo' },
    { label: 'Launch the right hunt', state: cti.phase === 'ready' && attacks.length > 0 ? 'now' : 'todo' },
  ]

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="max-w-3xl">
          <h1>CTI analysis</h1>
          <p className="mt-2 text-[15px] text-[var(--slate)]">
            Import a threat intelligence report. The agent summarizes the described attacks, extracts the published indicators and checks in threat intel whether IOCs exist online. That check decides the approach: by indicators when there are some, by behavioral hypothesis otherwise.
          </p>
        </div>
        <Stepper steps={steps} />
      </div>

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0 space-y-4">
          {cti.phase === 'idle' && attacks.length === 0 ? (
            <div
              className={`inner flex min-h-[420px] flex-col items-center justify-center border-dashed !border-[var(--rule)] p-8 text-center transition-colors ${dragging ? '!bg-white' : ''}`}
              onDragOver={(event) => {
                event.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
            >
              <span className="ic !h-[88px] !w-[88px] !cursor-default">
                <IconFileUp size={30} />
              </span>
              <h2 className="mt-5 !text-[28px]">Drop a CTI report here</h2>
              <p className="mt-2 max-w-md text-[14.5px] text-[var(--slate)]">Daily digest, vendor analysis, CERT bulletin. The document stays within the internal perimeter and the analysis continues if you navigate away.</p>
              <div className="mt-5 flex items-center gap-3">
                <label className="btn btn-dark cursor-pointer">
                  Choose a file <IconArrowRight size={16} />
                  <input
                    type="file"
                    accept="application/pdf,.pdf"
                    className="sr-only"
                    disabled={busy}
                    onChange={(event) => {
                      start(event.target.files?.[0])
                      event.target.value = ''
                    }}
                    aria-label="CTI report in PDF format"
                  />
                </label>
                <span className="text-[13px] text-[var(--slate)]">no file selected</span>
              </div>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                <Chip small>PDF with text layer</Chip>
                <Chip small>80 pages max</Chip>
                <Chip small>15 MB max</Chip>
              </div>
            </div>
          ) : (
            <Inner className="flex flex-wrap items-center gap-4 p-4">
              <span className={`ic !cursor-default ${cti.phase === 'ready' ? '!border-0 !bg-[var(--mint)] !text-white' : ''}`}>
                {cti.phase === 'ready' ? <IconCheck size={20} /> : <IconFileUp size={20} />}
              </span>
              <div className="min-w-0 flex-1">
                <p className="mono truncate text-[13px] font-medium">{cti.filename ?? 'this report'}</p>
                {cti.phase === 'analyzing' ? (
                  <p className="text-[13px] text-[var(--slate)]" role="status">
                    Reading and analyzing… step 1/2
                  </p>
                ) : null}
                {cti.phase === 'probing' ? (
                  <p className="text-[13px] text-[var(--slate)]" role="status">
                    {attacks.length} {plural(attacks.length, 'attack')} identified, checking IOCs online ({probesDone}/{attacks.length}), step 2/2
                  </p>
                ) : null}
                {cti.phase === 'ready' && cti.analyzedAt ? (
                  <p className="text-[13px] text-[var(--slate)]" role="status">
                    Analysis finished {cti.analyzedAt} · {attacks.length} {plural(attacks.length, 'attack')} · IOCs checked online
                  </p>
                ) : null}
                {busy ? (
                  <div className={`bar mt-2 ${cti.phase === 'analyzing' ? 'bar-indeterminate' : ''}`}>
                    <span style={cti.phase === 'probing' ? { width: `${Math.max(6, Math.round((probesDone / Math.max(1, attacks.length)) * 100))}%`, background: 'var(--accent)' } : undefined} />
                  </div>
                ) : null}
              </div>
              <label className={`btn btn-light btn-sm ${busy ? 'pointer-events-none opacity-50' : 'cursor-pointer'}`}>
                Choose another file
                <input
                  type="file"
                  accept="application/pdf,.pdf"
                  className="sr-only"
                  disabled={busy}
                  onChange={(event) => {
                    start(event.target.files?.[0])
                    event.target.value = ''
                  }}
                />
              </label>
            </Inner>
          )}

          {cti.error ? <ErrorNotice message={cti.error} hint={cti.errorHint} /> : null}
          {launchError ? <ErrorNotice message={launchError} /> : null}
          {cti.phase === 'ready' && attacks.length === 0 ? <Notice tone="amber" role="status">No attack identified in this document.</Notice> : null}
          {cti.analysis?.truncated ? <Notice tone="amber">Long document: only the first pages were analyzed.</Notice> : null}

          {cti.phase === 'idle' && attacks.length === 0 ? (
            <div className="grid gap-4 md:grid-cols-3">
              {(
                [
                  ['Import', 'Drop in a CTI report: daily digest, vendor analysis, CERT bulletin. The document stays within the internal perimeter.'],
                  ['Analyze and verify', 'The agent summarizes each described attack, extracts the IOCs published in the document, then probes threat intel: do IOCs exist online?'],
                  ['Launch the right hunt', 'Each attack comes with its recommendation: hunt by indicators (IOC validation) or by behavioral hypothesis (direct launch).'],
                ] as const
              ).map(([title, body], index) => (
                <Inner key={title} className="flex gap-3 p-4">
                  <span className="av !bg-[var(--navy)]">{index + 1}</span>
                  <span>
                    <span className="block font-semibold">{title}</span>
                    <span className="mt-1 block text-[13px] leading-relaxed text-[var(--slate)]">{body}</span>
                  </span>
                </Inner>
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
                  <Inner key={`${attack.name}-${index}`} className="flex flex-col p-5">
                    <div className="flex items-start justify-between gap-3">
                      <h2 className="!text-[20px]">{attack.name}</h2>
                      <Chip tone={KIND_TONES[attack.kind] ?? 'soft'} small className="capitalize">
                        {attack.kind}
                      </Chip>
                    </div>
                    <p className="mt-3 text-[13.5px] leading-relaxed">{attack.summary}</p>

                    <div className="mt-4 rounded-[18px] bg-white/70 p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-[13px] text-[var(--slate)]">
                          {attack.iocs.length} IOCs in the report
                        </span>
                        {probeState?.state === 'done' ? (
                          probeState.result.found > 0 ? (
                            <Chip tone="mint" small title={probeState.result.sources.join(', ')}>
                              {probeState.result.found}+ seen online
                            </Chip>
                          ) : (
                            <Chip tone="amber" small>
                              none online
                            </Chip>
                          )
                        ) : null}
                        {probeState?.state === 'loading' ? (
                          <Chip tone="soft" small>
                            probing…
                          </Chip>
                        ) : null}
                        {probeState?.state === 'error' ? (
                          <Btn variant="light" size="xs" onClick={() => void probeOne(index, attack)}>
                            Retry the probe
                          </Btn>
                        ) : null}
                      </div>
                      {probeState?.state === 'done' && probeState.result.found > 0 ? (
                        <p className="tech mt-2 break-all">
                          {probeState.result.sources.join(', ')} · {probeState.result.sample.map((ioc) => ioc.value).slice(0, 3).join(' · ')}
                        </p>
                      ) : null}
                      {probeState?.state === 'done' && probeState.result.found === 0 ? <p className="mt-2 text-[12.5px] text-[var(--amber)]">No IOC published in threat intel: favor behavioral hunting.</p> : null}
                      {probeState?.state === 'error' ? <p className="mt-2 text-[12.5px] text-[var(--garnet)]">{probeState.message}</p> : null}
                      {attack.iocs.length > 0 ? (
                        <p className="mono mt-2 break-all text-[12px] text-[var(--slate)]">
                          {attack.iocs.slice(0, 3).map((ioc) => ioc.value).join(' · ')}
                          {attack.iocs.length > 3 ? ` · +${attack.iocs.length - 3}` : ''}
                        </p>
                      ) : null}
                    </div>

                    <div className="mt-4 flex flex-wrap items-center gap-2 pt-1">
                      <Btn size="sm" disabled={!hasIocs || launching !== null} title={hasIocs ? undefined : 'No known IOC: start from the hypothesis.'} onClick={() => void launchByIocs(index, attack)}>
                        {launching === index ? 'Creating…' : 'Launch by IOC'}
                      </Btn>
                      <Btn variant="light" size="sm" disabled={launching !== null} onClick={() => void launchByHypothesis(index, attack)}>
                        Launch by hypothesis
                      </Btn>
                      <span className="tech ml-auto">{hasIocs ? 'IOC → validation' : 'hypothesis → direct'}</span>
                    </div>
                  </Inner>
                )
              })}
            </div>
          ) : null}
        </div>

        <aside className="inner flex flex-col p-5">
          <div className="flex items-center justify-between">
            <h2>Analyzed reports</h2>
            <Chip tone="soft" small>
              {history.data?.length ?? 0}
            </Chip>
          </div>
          {history.data && history.data.length > 0 ? (
            <ul className="mt-2">
              {history.data.map((entry) => (
                <li key={entry.id} className={`flex items-start gap-3 border-t border-[var(--rule-soft)] py-3 first:border-t-0 ${cti.analysisId === entry.id ? 'rounded-[16px] bg-white/60 px-2' : ''}`}>
                  <Avatar name={entry.analyzed_by} />
                  <button type="button" className="min-w-0 flex-1 text-left" disabled={busy} title="Reopen this analysis" onClick={() => void loadCtiAnalysis(entry.id)}>
                    <span className="link mono block truncate text-[12.5px]">{entry.filename}</span>
                    <span className="mt-0.5 block text-[12.5px] text-[var(--slate)]">
                      {formatShort(entry.analyzed_at)} · {entry.analyzed_by}
                    </span>
                    <span className="mt-1.5 flex flex-wrap gap-1.5">
                      <Chip small>
                        {entry.attacks} {plural(entry.attacks, 'attack')}
                      </Chip>
                      <Chip small>{entry.iocs} IOCs</Chip>
                      <Chip small>
                        {entry.pages} {plural(entry.pages, 'page')}
                      </Chip>
                    </span>
                  </button>
                  <button
                    type="button"
                    className="sm !text-[var(--garnet)]"
                    title="Delete this analysis from the history"
                    aria-label={`Delete the analysis of ${entry.filename}`}
                    onClick={() => {
                      if (window.confirm(`Delete the analysis of ${entry.filename}? The trace stays in the audit log.`)) {
                        void api.deleteCtiAnalysis(entry.id).then(() => void queryClient.invalidateQueries({ queryKey: ['cti-history'] }))
                      }
                    }}
                  >
                    <IconTrash size={16} />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted mt-3 text-[13.5px]">No report analyzed yet. Each analysis is kept here with its results: click one to reopen it.</p>
          )}
          <p className="mt-auto pt-6 text-[12.5px] text-[var(--slate)]">Text PDF only (no scans), 80 pages and 15 MB maximum. The document does not leave the internal perimeter; its content is treated as untrusted.</p>
        </aside>
      </Glass>
    </div>
  )
}
