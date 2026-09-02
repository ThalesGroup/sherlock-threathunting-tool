/**
 * Screen 1 — New hunt.
 *
 * The real limits of each source are shown rather than endured: the analyst sees that
 * Defender caps at 30 days instead of asking for the impossible and getting an error.
 */

import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { ErrorNotice, Mono, StatusBadge } from '@/components/primitives'
import { api, ApiError, huntPath, type CreateHuntPayload } from '@/lib/api'

const IOC_TYPES = ['hash', 'ip', 'domain', 'url', 'email', 'file_path', 'registry_key', 'other']

type HuntMode = 'hypothesis' | 'campaign'

interface ManualIocDraft {
  value: string
  type: string
}

export function NewHuntScreen() {
  const navigate = useNavigate()
  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const recent = useQuery({
    queryKey: ['hunts', { limit: 5 }],
    queryFn: () => api.listHunts({ limit: 5 }),
  })

  const [mode, setMode] = useState<HuntMode>('hypothesis')
  const [hypothesis, setHypothesis] = useState('')
  const [campaign, setCampaign] = useState('')
  const [sources, setSources] = useState<string[]>([])
  const [windowStart, setWindowStart] = useState('')
  const [windowEnd, setWindowEnd] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [manualIocs, setManualIocs] = useState<ManualIocDraft[]>([{ value: '', type: 'domain' }])
  const [importedFile, setImportedFile] = useState<File | null>(null)
  const [importNotice, setImportNotice] = useState<string | null>(null)

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
          importedPending = true // the indicators screen allows retrying
          importError =
            error instanceof ApiError ? error.message : 'The file could not be imported.'
        }
      }
      const basedOnIocs =
        result.requires_ioc_validation ||
        importedPending ||
        (payload.manual_iocs?.length ?? 0) > 0
      if (basedOnIocs) {
        navigate(`/hunts/${result.hunt_id}/indicators`, {
          state: importError ? { importError } : undefined,
        })
        return
      }
      navigate(`/hunts/${result.hunt_id}/playbook`)
    },
  })

  const configuredSources = config.data?.sources.filter((source) => source.configured) ?? []

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    const cleaned = manualIocs.filter((ioc) => ioc.value.trim().length > 0)
    create.mutate({
      hypothesis: mode === 'hypothesis' ? hypothesis.trim() : null,
      campaign: mode === 'campaign' ? campaign.trim() : null,
      manual_iocs: advanced ? cleaned.map((ioc) => ({ value: ioc.value.trim(), type: ioc.type })) : [],
      sources,
      ...(windowStart ? { window_start: new Date(windowStart).toISOString() } : {}),
      ...(windowStart && windowEnd
        ? { window_end: new Date(windowEnd).toISOString() }
        : {}),
    })
  }

  return (
    <div>
      <header className="mb-5">
        <h1 className="text-[22px] font-semibold tracking-tight text-ink">New hunt</h1>
        <p className="meta-text mt-1 max-w-[62ch]">
          Describe a hypothesis or name a campaign. The agent enriches it, queries the
          sources and hands you a report to validate.
        </p>
      </header>

      {config.data?.demo_siem ? (
        <div
          role="status"
          className="mb-5 rounded-xl border border-[#e8d5b0] bg-[#faeddc]/60 px-4 py-3 text-sm text-amber"
        >
          <span className="font-semibold">Demonstration mode.</span> The SIEM responses are
          simulated and marked as such; no real SIEM is queried. The agent&apos;s reasoning,
          the threat intel enrichment and the anonymization, however, are real.
        </div>
      ) : null}

      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form onSubmit={submit} className="card">
          <fieldset className="border-b border-rule-soft px-5 py-4">
            <legend className="sr-only">Starting point of the investigation</legend>
            <div className="label mb-2.5" aria-hidden="true">
              Starting point
            </div>
            <div
              role="radiogroup"
              aria-label="Starting point of the investigation"
              className="inline-flex overflow-hidden rounded-btn border border-field-border"
            >
              {(
                [
                  ['hypothesis', 'Hypothesis'],
                  ['campaign', 'Campaign or actor'],
                ] as [HuntMode, string][]
              ).map(([value, label]) => {
                const active = mode === value
                return (
                  <label
                    key={value}
                    className={`cursor-pointer px-4 py-2 text-xs transition-colors
                    focus-within:ring-2 focus-within:ring-accent ${
                      active
                        ? 'bg-navy font-semibold text-white'
                        : 'bg-white font-normal text-slate hover:bg-soft-bg'
                    }`}
                  >
                    <input
                      type="radio"
                      name="mode"
                      value={value}
                      checked={active}
                      onChange={() => setMode(value)}
                      className="sr-only"
                    />
                    {label}
                  </label>
                )
              })}
            </div>
            <p className="mt-2.5 text-xs text-meta">
              {mode === 'hypothesis'
                ? 'Start from a behavior to look for. The agent enriches it then queries the sources.'
                : 'Name a campaign or an actor. The agent searches its indicators in threat intel, which you validate before any querying.'}
            </p>
          </fieldset>

          <div className="border-b border-rule-soft px-5 py-4">
            <label
              htmlFor={mode === 'hypothesis' ? 'hypothesis' : 'campaign'}
              className="label mb-2.5 block"
            >
              {mode === 'hypothesis' ? 'Hypothesis' : 'Campaign or actor'}
            </label>
            {mode === 'hypothesis' ? (
              <>
                <textarea
                  id="hypothesis"
                  required
                  minLength={10}
                  rows={4}
                  value={hypothesis}
                  onChange={(event) => setHypothesis(event.target.value)}
                  className="field resize-y text-[13px] leading-relaxed"
                  placeholder="An actor uses legitimate system binaries to move laterally toward the backup servers."
                />
                <p className="mt-2 text-xs text-meta">
                  A behavioral hypothesis yields better results than a list of hashes.
                </p>
              </>
            ) : (
              <>
                <input
                  id="campaign"
                  required
                  minLength={2}
                  value={campaign}
                  onChange={(event) => setCampaign(event.target.value)}
                  className="field"
                  placeholder="Volt Typhoon"
                  maxLength={120}
                />
                <p className="mt-2 text-xs text-meta">
                  Only this name leaves the internal perimeter, toward the whitelisted threat
                  intel sources.
                </p>
              </>
            )}
          </div>

          <fieldset className="border-b border-rule-soft px-5 py-4">
            <legend className="sr-only">Queried sources</legend>
            <div className="label mb-3" aria-hidden="true">
              Queried sources
            </div>
            {configuredSources.length === 0 ? (
              <p className="meta-text">
                No source configured on this installation. The hunt will not be able to run
                any query.
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {configuredSources.map((source) => {
                  const checked = sources.length === 0 || sources.includes(source.name)
                  return (
                    <label
                      key={source.name}
                      className={`flex cursor-pointer items-center gap-3 rounded-btn border
                      px-3 py-2.5 transition-colors ${
                        checked
                          ? 'border-navy-active bg-[#f4f7fa]'
                          : 'border-[#e3e8ed] bg-white'
                      }`}
                    >
                      <input
                        type="checkbox"
                        className="h-[13px] w-[13px] accent-navy"
                        checked={checked}
                        onChange={(event) =>
                          setSources((current) => {
                            const base = current.length === 0
                              ? configuredSources.map((item) => item.name)
                              : current
                            return event.target.checked
                              ? [...new Set([...base, source.name])]
                              : base.filter((name) => name !== source.name)
                          })
                        }
                      />
                      <span className="w-[110px] text-[13px] font-medium capitalize text-ink">
                        {source.name}
                      </span>
                      <span className="font-mono text-[11px] text-meta">
                        window {source.max_window_days} d · {source.max_rows} rows / query
                      </span>
                      {source.note ? (
                        <span className="text-xs text-amber">{source.note}</span>
                      ) : null}
                    </label>
                  )
                })}
              </div>
            )}
          </fieldset>

          <div className="px-5 py-4">
            <div className="label mb-3">
              Investigation period <span className="text-[#a8b4bf]">optional</span>
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <input
                type="datetime-local"
                value={windowStart}
                onChange={(event) => setWindowStart(event.target.value)}
                className="field w-auto font-mono text-[13px]"
                aria-label="Start of the investigation period"
              />
              <span className="h-px w-3.5 bg-field-border" aria-hidden="true" />
              <input
                type="datetime-local"
                value={windowEnd}
                onChange={(event) => setWindowEnd(event.target.value)}
                disabled={!windowStart}
                min={windowStart || undefined}
                className="field w-auto font-mono text-[13px] disabled:opacity-50"
                aria-label="End of the investigation period"
              />
            </div>
            <p className="mt-2 text-xs text-meta">
              The agent&apos;s queries are bounded to this period by the middleware. Without
              an end, the period runs until now. Otherwise, the agent picks its windows
              within the per-source limits.
            </p>

            <button
              type="button"
              onClick={() => setAdvanced((value) => !value)}
              className="mt-4 w-full rounded-btn border border-dashed border-field-border
                bg-[#f9fafb] px-3.5 py-2.5 text-left text-xs font-medium text-indigo
                transition-colors hover:bg-soft-bg"
              aria-expanded={advanced}
            >
              {advanced ? '− Hide known indicators' : '+ Provide known indicators'}
            </button>

            {advanced ? (
              <div className="mt-3 space-y-2.5">
                <p className="text-xs text-meta">
                  These indicators are attributed to your account as their source and are
                  considered validated. Those coming from threat intel go through the
                  validation screen.
                </p>
                {manualIocs.map((ioc, index) => (
                  <div key={index} className="flex flex-wrap gap-2">
                    <input
                      value={ioc.value}
                      onChange={(event) =>
                        setManualIocs((current) =>
                          current.map((item, position) =>
                            position === index ? { ...item, value: event.target.value } : item,
                          ),
                        )
                      }
                      className="field flex-1 font-mono text-xs"
                      placeholder="indicator value"
                      aria-label={`Indicator ${index + 1}`}
                    />
                    <select
                      value={ioc.type}
                      onChange={(event) =>
                        setManualIocs((current) =>
                          current.map((item, position) =>
                            position === index ? { ...item, type: event.target.value } : item,
                          ),
                        )
                      }
                      className="field w-36 text-xs"
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
                <button
                  type="button"
                  className="text-xs font-medium text-indigo hover:underline"
                  onClick={() =>
                    setManualIocs((current) => [...current, { value: '', type: 'domain' }])
                  }
                >
                  + Add a row
                </button>
                <div className="flex flex-wrap items-center gap-2.5 border-t border-rule-soft pt-2.5">
                  <label className="cursor-pointer text-xs font-medium text-indigo hover:underline">
                    {importedFile ? 'Change file' : 'Import an indicators file'}
                    <input
                      type="file"
                      accept=".txt,.csv,.xlsx,.log,.list,.ioc,text/plain,text/csv"
                      className="sr-only"
                      onChange={(event) => {
                        const file = event.target.files?.[0] ?? null
                        setImportedFile(file)
                        setImportNotice(
                          file
                            ? `${file.name} will be analyzed on creation: the extracted indicators will arrive pending validation.`
                            : null,
                        )
                        event.target.value = ''
                      }}
                    />
                  </label>
                  {importedFile ? (
                    <>
                      <span className="font-mono text-xs text-ink">{importedFile.name}</span>
                      <button
                        type="button"
                        className="text-xs text-slate hover:text-garnet hover:underline"
                        onClick={() => {
                          setImportedFile(null)
                          setImportNotice(null)
                        }}
                      >
                        remove
                      </button>
                    </>
                  ) : (
                    <span className="text-xs text-meta">txt, csv or xlsx — pattern extraction</span>
                  )}
                </div>
                {importNotice ? <p className="text-xs text-mint">{importNotice}</p> : null}
              </div>
            ) : null}

            {create.error ? (
              <div className="mt-4">
                <ErrorNotice
                  message={
                    create.error instanceof ApiError
                      ? create.error.message
                      : 'The hunt could not be created.'
                  }
                  hint={create.error instanceof ApiError ? create.error.hint : null}
                />
              </div>
            ) : null}
          </div>

          <div className="flex items-center justify-between border-t border-rule bg-soft-bg px-5 py-4">
            <span className="meta-mono uppercase">
              {sources.length === 0 ? configuredSources.length : sources.length} source
              {(sources.length === 0 ? configuredSources.length : sources.length) > 1
                ? 's'
                : ''}{' '}
              · budgets set at the playbook
            </span>
            <button type="submit" className="btn-primary" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create hunt'}
            </button>
          </div>
        </form>

        <aside className="card">
          <h2 className="card-header">Recent hunts</h2>
          {recent.data && recent.data.length > 0 ? (
            recent.data.map((hunt) => (
              <Link
                key={hunt.hunt_id}
                to={huntPath(hunt)}
                className="block border-b border-rule-soft px-4 py-3 transition-colors last:border-b-0 hover:bg-soft-bg"
              >
                <div className="mb-1.5 flex items-center justify-between gap-2">
                  <Mono className="text-[11px] font-medium text-indigo">{hunt.hunt_id}</Mono>
                  <StatusBadge status={hunt.status} />
                </div>
                <p className="line-clamp-2 text-xs leading-relaxed text-[#3d4d5c]">
                  {hunt.hypothesis}
                </p>
              </Link>
            ))
          ) : (
            <p className="meta-text px-4 py-5">
              No hunt yet. The first one starts from the hypothesis written on the left.
            </p>
          )}
        </aside>
      </div>
    </div>
  )
}
