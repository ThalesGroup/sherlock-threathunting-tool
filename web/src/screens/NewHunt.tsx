/**
 * New hunt: a hypothesis or a campaign, the
 * sources to query with their real limits, an optional period, and known indicators
 * (typed by hand or imported from a file) that arrive validated under the analyst's name.
 */

import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { huntPath, api, ApiError, type CreateHuntPayload } from '@/lib/api'

import { IconAlert, IconArrowRight, IconArrowUpRight, IconCalendar, IconCheck, IconDoc, IconInfo, IconPlus, IconX } from '@/components/icons'
import { Avatar, Btn, ErrorNotice, Glass, Inner, Notice, StatusChip, Stepper } from '@/components/ui'

const IOC_TYPES = ['hash', 'ip', 'domain', 'url', 'email', 'file_path', 'registry_key', 'other']

type HuntMode = 'hypothesis' | 'campaign'

interface ManualIocDraft {
  value: string
  type: string
}

export function NewHuntScreen() {
  const navigate = useNavigate()
  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const recent = useQuery({ queryKey: ['hunts', { limit: 5 }], queryFn: () => api.listHunts({ limit: 5 }) })

  const [mode, setMode] = useState<HuntMode>('hypothesis')
  const [hypothesis, setHypothesis] = useState('')
  const [campaign, setCampaign] = useState('')
  const [sources, setSources] = useState<string[]>([])
  const [windowStart, setWindowStart] = useState('')
  const [windowEnd, setWindowEnd] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [manualIocs, setManualIocs] = useState<ManualIocDraft[]>([{ value: '', type: 'domain' }])
  const [importedFile, setImportedFile] = useState<File | null>(null)

  const create = useMutation({
    mutationFn: (payload: CreateHuntPayload) => api.createHunt(payload),
    onSuccess: async (result, payload) => {
      let importedPending = false
      let importError: string | null = null
      if (importedFile) {
        try {
          const imported = await api.importIocs(result.hunt_id, importedFile)
          importedPending = imported.added > 0
          if (imported.added === 0) {
            importError =
              imported.extracted === 0
                ? 'No indicator recognized in the imported file.'
                : `Nothing to add: the ${imported.duplicates} indicators in the file are already present.`
          }
        } catch (error) {
          importedPending = true
          importError = error instanceof ApiError ? error.message : 'The file could not be imported.'
        }
      }
      const basedOnIocs =
        result.requires_ioc_validation || importedPending || (payload.manual_iocs?.length ?? 0) > 0
      if (basedOnIocs) {
        navigate(`/hunts/${result.hunt_id}/indicators`, { state: importError ? { importError } : undefined })
        return
      }
      navigate(`/hunts/${result.hunt_id}/playbook`)
    },
  })

  const configuredSources = config.data?.sources.filter((source) => source.configured) ?? []
  const selectedCount = sources.length === 0 ? configuredSources.length : sources.length

  /** Sources whose API cannot physically serve the whole period (Defender: 30 days). */
  const periodNotices = configuredSources
    .filter((source) => source.note && (sources.length === 0 || sources.includes(source.name)))
    .filter(() => windowStart !== '')
    .filter((source) => {
      const start = new Date(windowStart)
      if (Number.isNaN(start.getTime())) return false
      const daysBack = (Date.now() - start.getTime()) / 86_400_000
      return daysBack > source.max_window_days
    })
    .map(
      (source) =>
        `${source.name.charAt(0).toUpperCase() + source.name.slice(1)} only returns the last ${source.max_window_days} days: on that source, the period will start ${new Date(Date.now() - source.max_window_days * 86_400_000).toLocaleDateString('en-GB')}.`,
    )

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    const cleaned = manualIocs.filter((ioc) => ioc.value.trim().length > 0)
    create.mutate({
      hypothesis: mode === 'hypothesis' ? hypothesis.trim() : null,
      campaign: mode === 'campaign' ? campaign.trim() : null,
      manual_iocs: advanced ? cleaned.map((ioc) => ({ value: ioc.value.trim(), type: ioc.type })) : [],
      sources,
      ...(windowStart ? { window_start: new Date(windowStart).toISOString() } : {}),
      ...(windowStart && windowEnd ? { window_end: new Date(windowEnd).toISOString() } : {}),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <h1>New hunt</h1>
          <p className="mt-2 max-w-2xl text-[15px] text-[var(--slate)]">
            Describe a hypothesis or name a campaign. The agent enriches it, queries the sources and hands you a report to validate.
          </p>
        </div>
        <Stepper
          steps={[
            { label: 'Describe', state: 'now' },
            { label: 'Validate indicators', state: 'todo' },
            { label: 'Validate playbook', state: 'todo' },
          ]}
        />
      </div>

      {config.data?.demo_siem ? (
        <Notice tone="amber" role="status">
          <span className="font-semibold">Demonstration mode.</span> The SIEM responses are simulated and marked as such; no real SIEM is queried. The agent&apos;s reasoning, the threat intel enrichment and the anonymization, however, are real.
        </Notice>
      ) : null}

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <form onSubmit={submit} className="inner flex min-w-0 flex-col p-6">
          <fieldset className="flex flex-wrap items-center justify-between gap-4">
            <legend className="sr-only">Starting point of the investigation</legend>
            <div>
              <div className="font-medium">Starting point</div>
              <p className="text-[13px] text-[var(--slate)]">
                {mode === 'hypothesis'
                  ? 'Start from a behavior to look for. The agent enriches it, then queries the sources.'
                  : 'Name a campaign or an actor. The agent searches its indicators in threat intel, which you validate before any querying.'}
              </p>
            </div>
            <div className="seg" role="radiogroup" aria-label="Starting point of the investigation">
              {(
                [
                  ['hypothesis', 'Hypothesis'],
                  ['campaign', 'Campaign or actor'],
                ] as [HuntMode, string][]
              ).map(([value, label]) => (
                <label key={value} className={mode === value ? 'on' : ''}>
                  <input type="radio" name="mode" value={value} checked={mode === value} onChange={() => setMode(value)} className="sr-only" />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>

          <div className="mt-6">
            <label htmlFor={mode === 'hypothesis' ? 'hypothesis' : 'campaign'} className="lbl block">
              {mode === 'hypothesis' ? 'Hypothesis' : 'Campaign or actor'}
            </label>
            {mode === 'hypothesis' ? (
              <>
                <textarea
                  id="hypothesis"
                  required
                  minLength={10}
                  rows={5}
                  value={hypothesis}
                  onChange={(event) => setHypothesis(event.target.value)}
                  className="field mt-2 !rounded-[20px] !p-5 text-[15px]"
                  placeholder="An actor uses legitimate system binaries to move laterally toward the backup servers."
                />
                <p className="mt-2 text-[13px] text-[var(--slate)]">A behavioral hypothesis yields better results than a list of hashes.</p>
              </>
            ) : (
              <>
                <input
                  id="campaign"
                  required
                  minLength={2}
                  maxLength={120}
                  value={campaign}
                  onChange={(event) => setCampaign(event.target.value)}
                  className="field field-pill mt-2 text-[15px]"
                  placeholder="Volt Typhoon"
                />
                <p className="mt-2 text-[13px] text-[var(--slate)]">Only this name leaves the internal perimeter, toward the whitelisted threat intel sources.</p>
              </>
            )}
          </div>

          <fieldset className="mt-6">
            <legend className="sr-only">Queried sources</legend>
            <div className="flex items-center justify-between">
              <span className="lbl">Queried sources</span>
              <span className="text-[13px] text-[var(--slate)]">
                {selectedCount} of {configuredSources.length} selected
              </span>
            </div>
            {configuredSources.length === 0 ? (
              <p className="muted mt-2">No source configured on this installation. The hunt will not be able to run any query.</p>
            ) : (
              <div className="mt-2 grid gap-3 md:grid-cols-3">
                {configuredSources.map((source) => {
                  const checked = sources.length === 0 || sources.includes(source.name)
                  return (
                    <label
                      key={source.name}
                      className={`inner-solid flex cursor-pointer items-start gap-3 px-4 py-3 transition-colors ${checked ? '' : 'opacity-70'}`}
                    >
                      <input
                        type="checkbox"
                        className="sr-only"
                        checked={checked}
                        onChange={(event) =>
                          setSources((current) => {
                            const base = current.length === 0 ? configuredSources.map((item) => item.name) : current
                            return event.target.checked
                              ? [...new Set([...base, source.name])]
                              : base.filter((name) => name !== source.name)
                          })
                        }
                      />
                      <span className={`sm mt-0.5 ${checked ? '!bg-[var(--navy)] !text-white' : ''}`} aria-hidden="true">
                        {checked ? <IconCheck size={16} /> : null}
                      </span>
                      <span className="min-w-0 pt-1">
                        <span className="flex items-center gap-1.5 font-semibold capitalize leading-tight">
                          {source.name}
                          {source.note ? (
                            <span className="tip text-[var(--slate)]" tabIndex={0} aria-label={source.note}>
                              <IconInfo size={15} />
                              <span role="tooltip">{source.note}</span>
                            </span>
                          ) : null}
                        </span>
                        <span className="tech block">
                          default depth {source.max_window_days} d · {source.max_rows} rows / query
                        </span>
                      </span>
                    </label>
                  )
                })}
              </div>
            )}
          </fieldset>

          <div className="mt-6">
            <span className="lbl">
              Investigation period <span className="font-normal text-[var(--meta)]">optional</span>
            </span>
            <div className="mt-2 flex flex-wrap items-center gap-3">
              <span className="relative">
                <IconCalendar size={16} className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-[var(--slate)]" />
                <input
                  type="datetime-local"
                  value={windowStart}
                  onChange={(event) => setWindowStart(event.target.value)}
                  className="field field-pill mono w-auto !pl-11 text-[13px]"
                  aria-label="Start of the investigation period"
                />
              </span>
              <span className="h-px w-4 bg-[var(--rule)]" aria-hidden="true" />
              <span className="relative">
                <IconCalendar size={16} className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-[var(--slate)]" />
                <input
                  type="datetime-local"
                  value={windowEnd}
                  onChange={(event) => setWindowEnd(event.target.value)}
                  disabled={!windowStart}
                  min={windowStart || undefined}
                  className="field field-pill mono w-auto !pl-11 text-[13px]"
                  aria-label="End of the investigation period"
                  placeholder="until now"
                />
              </span>
              <p className="min-w-[240px] flex-1 text-[13px] text-[var(--slate)]">
                Every query is bounded to this period by the middleware: it takes precedence over the default depth of each source. Without an end, the period runs until now; without a start, the agent picks its windows within the default depths.
              </p>
            </div>
            {periodNotices.map((notice) => (
              <p key={notice} className="mt-2 flex items-start gap-1.5 text-[13px] text-[var(--amber)]">
                <IconAlert size={14} className="mt-0.5 flex-none" />
                {notice}
              </p>
            ))}
          </div>

          <div className="mt-6">
            <button
              type="button"
              onClick={() => setAdvanced((value) => !value)}
              aria-expanded={advanced}
              className="flex w-full items-center gap-4 rounded-[24px] border border-dashed border-[var(--rule)] bg-white/40 px-3 py-2 text-left transition-colors hover:bg-white/70"
            >
              <span className="sm">{advanced ? <IconX size={16} /> : <IconPlus size={16} />}</span>
              <span className="link">{advanced ? 'Hide known indicators' : 'Provide known indicators'}</span>
              <span className="text-[13px] text-[var(--slate)]">hashes, IPs, domains. They arrive validated, attributed to your account.</span>
            </button>

            {advanced ? (
              <div className="mt-3 space-y-2.5 px-1">
                <p className="text-[13px] text-[var(--slate)]">
                  These indicators are attributed to your account as their source and are considered validated. Those coming from threat intel go through the validation screen.
                </p>
                {manualIocs.map((ioc, index) => (
                  <div key={index} className="flex flex-wrap gap-2">
                    <input
                      value={ioc.value}
                      onChange={(event) =>
                        setManualIocs((current) => current.map((item, position) => (position === index ? { ...item, value: event.target.value } : item)))
                      }
                      className="field field-pill mono flex-1 text-[13px]"
                      placeholder="indicator value"
                      aria-label={`Indicator ${index + 1}`}
                    />
                    <select
                      value={ioc.type}
                      onChange={(event) =>
                        setManualIocs((current) => current.map((item, position) => (position === index ? { ...item, type: event.target.value } : item)))
                      }
                      className="field field-pill w-40 text-[13px]"
                      aria-label={`Type of indicator ${index + 1}`}
                    >
                      {IOC_TYPES.map((type) => (
                        <option key={type} value={type}>
                          {type}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
                <div className="flex flex-wrap items-center gap-4">
                  <button type="button" className="link text-[13px]" onClick={() => setManualIocs((current) => [...current, { value: '', type: 'domain' }])}>
                    + Add a row
                  </button>
                  <label className="link cursor-pointer text-[13px]">
                    {importedFile ? 'Change file' : 'Import an indicators file'}
                    <input
                      type="file"
                      accept=".txt,.csv,.xlsx,.log,.list,.ioc,text/plain,text/csv"
                      className="sr-only"
                      onChange={(event) => {
                        setImportedFile(event.target.files?.[0] ?? null)
                        event.target.value = ''
                      }}
                    />
                  </label>
                  {importedFile ? (
                    <>
                      <span className="mono text-[12.5px]">{importedFile.name}</span>
                      <button type="button" className="text-[12.5px] text-[var(--slate)] hover:text-[var(--garnet)] hover:underline" onClick={() => setImportedFile(null)}>
                        remove
                      </button>
                    </>
                  ) : (
                    <span className="text-[12.5px] text-[var(--meta)]">txt, csv or xlsx, pattern extraction</span>
                  )}
                </div>
                {importedFile ? (
                  <p className="text-[13px] text-[var(--mint)]">
                    {importedFile.name} will be analyzed on creation: the extracted indicators will arrive pending validation.
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>

          {create.error ? (
            <div className="mt-5">
              <ErrorNotice
                message={create.error instanceof ApiError ? create.error.message : 'The hunt could not be created.'}
                hint={create.error instanceof ApiError ? create.error.hint : null}
              />
            </div>
          ) : null}

          <div className="mt-auto flex flex-wrap items-center justify-between gap-4 border-t border-[var(--rule-soft)] pt-5">
            <span className="text-[13px] text-[var(--slate)]">
              Nothing is sent to a SIEM before you validate the playbook. {selectedCount} {selectedCount === 1 ? 'source' : 'sources'} · budgets set at the playbook.
            </span>
            <Btn type="submit" disabled={create.isPending} end={<IconArrowRight size={16} />}>
              {create.isPending ? 'Creating…' : 'Start the hunt'}
            </Btn>
          </div>
        </form>

        <aside className="flex flex-col gap-4">
          <Inner className="p-5">
            <div className="flex items-center justify-between">
              <h2 className="!text-[19px]">Recent hunts</h2>
              <Link to="/history" className="sm" title="Full history">
                <IconArrowUpRight size={16} />
              </Link>
            </div>
            {recent.data && recent.data.length > 0 ? (
              <ul className="mt-2">
                {recent.data.map((hunt) => (
                  <li key={hunt.hunt_id} className="border-b border-[var(--rule-soft)] py-3 last:border-b-0">
                    <Link to={huntPath(hunt)} className="flex items-start gap-3 no-underline hover:no-underline">
                      <Avatar name={hunt.analyst} />
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center justify-between gap-2">
                          <span className="mono text-[11.5px] text-[var(--slate)]">{hunt.hunt_id}</span>
                          <StatusChip status={hunt.status} verdict={hunt.verdict ?? null} small />
                        </span>
                        <span className="mt-1 line-clamp-2 block text-[13.5px] leading-snug">{hunt.hypothesis}</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted mt-3 text-[13.5px]">No hunt yet. The first one starts from the hypothesis written on the left.</p>
            )}
          </Inner>

          <Inner className="flex items-center gap-3 p-4">
            <span className="sm">
              <IconDoc size={16} />
            </span>
            <p className="text-[13.5px]">
              Have a CTI report?{' '}
              <Link to="/cti" className="link">
                Import it
              </Link>{' '}
              and the agent will extract attacks and indicators for you.
            </p>
          </Inner>
        </aside>
      </Glass>
    </div>
  )
}
