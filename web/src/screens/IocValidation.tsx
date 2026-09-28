/**
 * Indicator validation. First blocking human checkpoint: nothing is queried until
 * the analyst has decided. The source column is always filled and clickable, the visual
 * translation of the rule "no indicator from the model's memory".
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { api, ApiError, type Ioc, type TimeRange } from '@/lib/api'
import { ENRICH_IDLE, getEnrichSnapshot, startIocSearch, subscribeEnrich } from '@/lib/enrichStore'

import { IconArrowRight, IconFileUp, IconSearch } from '@/components/icons'
import { Btn, Chip, EmptyState, ErrorNotice, Glass, Inner, Notice, Stepper } from '@/components/ui'

export function IocValidationScreen() {
  const { huntId = '' } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const iocs = useQuery({ queryKey: ['iocs', huntId], queryFn: () => api.listIocs(huntId) })
  const summaries = useQuery({ queryKey: ['hunts', { limit: 50 }], queryFn: () => api.listHunts({ limit: 50 }) })

  const [selected, setSelected] = useState<Set<string> | null>(null)
  const [campaignInput, setCampaignInput] = useState<string | null>(null)
  const [maxResults, setMaxResults] = useState(50)
  const [timeRange, setTimeRange] = useState<TimeRange>(null)
  const [manualValue, setManualValue] = useState('')
  const [manualType, setManualType] = useState('hash')

  const hunt = summaries.data?.find((item) => item.hunt_id === huntId)
  const huntCampaign = hunt?.campaign ?? ''
  const campaign = campaignInput ?? huntCampaign

  const rows = iocs.data ?? []
  const selectable = useMemo(() => rows.filter(hasSource), [rows])
  const currentSelection = useMemo(() => {
    if (selected !== null) return selected
    return new Set(selectable.filter((ioc) => ioc.status === 'validated').map((ioc) => ioc.value))
  }, [selected, selectable])

  const enrichStates = useSyncExternalStore(subscribeEnrich, getEnrichSnapshot)
  const search = enrichStates[huntId] ?? ENRICH_IDLE

  const [addNotice, setAddNotice] = useState<{ tone: 'mint' | 'amber' | 'garnet'; text: string } | null>(null)
  const [lastAdded, setLastAdded] = useState<string | null>(null)

  const importFile = useMutation({
    mutationFn: (file: File) => api.importIocs(huntId, file),
    onSuccess: (result) => {
      const types = Object.entries(result.by_type)
        .map(([type, count]) => `${count} ${type}`)
        .join(', ')
      setAddNotice({
        tone: result.added > 0 ? 'mint' : 'amber',
        text:
          result.added > 0
            ? `${result.added} indicator(s) imported (${types})` + (result.duplicates > 0 ? ` · ${result.duplicates} already present` : '') + ', validate them below.'
            : result.extracted === 0
              ? 'No indicator recognized in this file.'
              : `Nothing to add: the ${result.duplicates} indicators in the file are already in the list.`,
      })
      queryClient.invalidateQueries({ queryKey: ['iocs', huntId] })
    },
  })

  const addManual = useMutation({
    mutationFn: () => api.addIocs(huntId, [{ value: manualValue.trim(), type: manualType }]),
    onSuccess: (result) => {
      if (result.duplicates.length > 0) {
        setAddNotice({ tone: 'amber', text: `Already present in the list (defang normalized): ${result.duplicates.join(', ')}. Nothing was added.` })
        setLastAdded(null)
        return
      }
      setAddNotice({ tone: 'mint', text: `${result.added} indicator added at the bottom of the list.` })
      setLastAdded(manualValue.trim())
      setManualValue('')
      queryClient.invalidateQueries({ queryKey: ['iocs', huntId] })
    },
  })

  const validateAndStart = useMutation({
    mutationFn: async () => {
      const validated = [...currentSelection]
      const rejected = selectable.map((ioc) => ioc.value).filter((value) => !currentSelection.has(value))
      await api.validateIocs(huntId, validated, rejected)
    },
    onSuccess: () => navigate(`/hunts/${huntId}/playbook`),
  })

  const autoTriggered = useRef(false)
  const importNoticeShown = useRef(false)

  useEffect(() => {
    const state = location.state as { importError?: string } | null
    if (state?.importError && !importNoticeShown.current) {
      importNoticeShown.current = true
      setAddNotice({ tone: 'garnet', text: state.importError })
      navigate(location.pathname + location.search, { replace: true })
    }
  }, [location, navigate])

  useEffect(() => {
    const fromUrl = searchParams.get('campaign')
    if (fromUrl && campaignInput === null) setCampaignInput(fromUrl)
    const name = (fromUrl ?? campaign).trim()
    if (searchParams.get('auto') === '1' && !autoTriggered.current && name.length >= 2 && config.data?.threat_intel_enabled) {
      autoTriggered.current = true
      setSearchParams({}, { replace: true })
      void startIocSearch(huntId, name, maxResults, timeRange, rows.length)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [campaign, campaignInput, config.data?.threat_intel_enabled, searchParams])

  const toggle = (value: string) => {
    setSelected(() => {
      const next = new Set(currentSelection)
      if (next.has(value)) next.delete(value)
      else next.add(value)
      return next
    })
  }
  const toggleAll = () => {
    setSelected(currentSelection.size === selectable.length ? new Set() : new Set(selectable.map((ioc) => ioc.value)))
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <p className="tech">
            Hunts / <span className="text-[var(--ink)]">{huntId}</span>
          </p>
          <h1 className="mt-1">Validate the indicators</h1>
          <p className="mt-2 text-[15px] text-[var(--slate)]">
            No query goes to a SIEM until you have decided.
            {hunt ? <span className="ml-1 text-[var(--ink)]">{hunt.campaign ?? hunt.hypothesis}</span> : null}
          </p>
        </div>
        <Stepper
          steps={[
            { label: 'Indicators', state: 'now' },
            { label: 'Playbook', state: 'todo' },
            { label: 'Verdict', state: 'todo' },
          ]}
        />
      </div>

      <Glass className="space-y-4 p-5">
        {config.data?.threat_intel_enabled ? (
          <Inner className="p-5">
            <div className="flex items-start gap-4">
              <span className="ic ic-dark !cursor-default">
                <IconSearch size={20} />
              </span>
              <div className="min-w-0 flex-1">
                <h2 className="!text-[19px]">Search for indicators</h2>
                <p className="text-[13.5px] text-[var(--slate)]">Only the campaign name leaves the internal scope. No element of the hunt&apos;s context is sent.</p>
                <div className="mt-3 flex flex-wrap items-end gap-3">
                  <input
                    value={campaign}
                    onChange={(event) => setCampaignInput(event.target.value)}
                    className="field field-pill max-w-sm flex-1"
                    placeholder="Volt Typhoon"
                    aria-label="Campaign name to search"
                  />
                  <label className="text-[13px]">
                    <span className="lbl block">Number of IOCs</span>
                    <input
                      type="number"
                      min={1}
                      max={200}
                      value={maxResults}
                      onChange={(event) => setMaxResults(Math.min(200, Math.max(1, Number(event.target.value) || 1)))}
                      className="field field-pill mono mt-1 w-28"
                      aria-label="Maximum number of indicators to search (1 to 200)"
                    />
                  </label>
                  <label className="text-[13px]">
                    <span className="lbl block">Freshness</span>
                    <select
                      value={timeRange ?? ''}
                      onChange={(event) => setTimeRange(event.target.value === '' ? null : (event.target.value as NonNullable<TimeRange>))}
                      className="field field-pill mt-1"
                      aria-label="Freshness of the indicators searched"
                    >
                      <option value="">All periods</option>
                      <option value="month">Less than a month</option>
                      <option value="3months">Less than 3 months</option>
                      <option value="9months">Less than 9 months</option>
                      <option value="year">Less than a year</option>
                    </select>
                  </label>
                  <Btn
                    variant="light"
                    onClick={() => void startIocSearch(huntId, campaign, maxResults, timeRange, rows.length)}
                    disabled={search.status === 'running' || campaign.trim().length < 2}
                  >
                    Search
                  </Btn>
                </div>
                {search.status === 'running' ? (
                  <div className="mt-3" role="status">
                    <p className="text-[13px] text-[var(--indigo)]">Searching indicators for &quot;{search.campaign}&quot;… The search continues if you change pages.</p>
                    <div className="bar bar-indeterminate mt-2">
                      <span />
                    </div>
                  </div>
                ) : null}
                {search.status === 'error' && search.error ? (
                  <div className="mt-3">
                    <ErrorNotice message={search.error} hint={search.hint} />
                  </div>
                ) : null}
                {search.status === 'done' && search.added !== null ? (
                  <p className={`mt-3 text-[13px] ${search.added > 0 ? 'text-[var(--mint)]' : 'text-[var(--amber)]'}`} role="status">
                    {search.added > 0
                      ? `Search complete: ${search.added} new indicator${search.added > 1 ? 's' : ''} added to the table.`
                      : 'Search complete: no new indicator found for this name. Vulnerability disclosures rarely publish IOCs; try a shorter name, a different freshness, or start from a behavioral hypothesis.'}
                  </p>
                ) : null}
              </div>
            </div>
          </Inner>
        ) : null}

        <Inner className="p-5">
          <h2 className="!text-[19px]">Add my indicators</h2>
          <p className="text-[13.5px] text-[var(--slate)]">Your own indicators complement those from threat intel. Their source is you: they arrive validated and attributed by name.</p>
          <div className="mt-3 flex flex-wrap items-end gap-3">
            <input
              value={manualValue}
              onChange={(event) => setManualValue(event.target.value)}
              className="field field-pill mono max-w-xl flex-1 text-[13px]"
              placeholder="e.g. 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
              aria-label="Value of the indicator to add"
              onKeyDown={(event) => {
                if (event.key === 'Enter' && manualValue.trim().length > 0) {
                  event.preventDefault()
                  addManual.mutate()
                }
              }}
            />
            <label className="text-[13px]">
              <span className="lbl block">Type</span>
              <select value={manualType} onChange={(event) => setManualType(event.target.value)} className="field field-pill mt-1" aria-label="Indicator type">
                <option value="hash">hash</option>
                <option value="ip">ip</option>
                <option value="domain">domain</option>
                <option value="url">url</option>
                <option value="email">email</option>
                <option value="file_path">file path</option>
                <option value="registry_key">registry key</option>
                <option value="other">other</option>
              </select>
            </label>
            <Btn variant="light" onClick={() => addManual.mutate()} disabled={addManual.isPending || manualValue.trim().length === 0}>
              {addManual.isPending ? 'Adding…' : 'Add'}
            </Btn>
            <label className="btn btn-light cursor-pointer">
              <IconFileUp size={18} />
              {importFile.isPending ? 'Importing…' : 'Import a file'}
              <input
                type="file"
                accept=".txt,.csv,.xlsx,.log,.list,.ioc,text/plain,text/csv"
                className="sr-only"
                onChange={(event) => {
                  const file = event.target.files?.[0]
                  if (file) importFile.mutate(file)
                  event.target.value = ''
                }}
              />
            </label>
            <span className="text-[12.5px] text-[var(--meta)]">txt, csv or xlsx, pattern extraction, to validate afterward</span>
          </div>
          {addNotice ? (
            <div className="mt-3">
              <Notice tone={addNotice.tone} role="status">
                {addNotice.text}
              </Notice>
            </div>
          ) : null}
          {importFile.error ? (
            <div className="mt-3">
              <ErrorNotice message={importFile.error instanceof ApiError ? importFile.error.message : 'The file could not be imported.'} />
            </div>
          ) : null}
          {addManual.error ? (
            <div className="mt-3">
              <ErrorNotice
                message={addManual.error instanceof ApiError ? addManual.error.message : 'The indicator could not be added.'}
                hint={addManual.error instanceof ApiError ? addManual.error.hint : null}
              />
            </div>
          ) : null}
        </Inner>

        {rows.length === 0 ? (
          <EmptyState title="No indicator">
            This hunt is purely behavioral. You can launch it as is: the agent will reason on TTPs rather than on matches.
          </EmptyState>
        ) : (
          <Inner className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4">
              <h2 className="!text-[19px]">Indicators surfaced</h2>
              <div className="flex items-center gap-2">
                <Chip tone="navy" small>
                  {currentSelection.size} selected
                </Chip>
                <Chip tone="soft" small>
                  {rows.length} in the list
                </Chip>
              </div>
            </div>
            <div className="overflow-x-auto px-2 pb-2 pt-2">
              <table className="tbl">
                <caption className="sr-only">Indicators surfaced for this hunt</caption>
                <thead>
                  <tr>
                    <th scope="col" className="w-12">
                      <input
                        type="checkbox"
                        className="check"
                        checked={selectable.length > 0 && currentSelection.size === selectable.length}
                        onChange={toggleAll}
                        aria-label="Select all"
                      />
                    </th>
                    <th scope="col">Value</th>
                    <th scope="col">Type</th>
                    <th scope="col">Source</th>
                    <th scope="col">First seen</th>
                    <th scope="col">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((ioc) => {
                    const sourced = hasSource(ioc)
                    return (
                      <tr
                        key={`${ioc.type}:${ioc.value}`}
                        className={`${ioc.value === lastAdded ? 'bg-[#e0efea]/60' : ''} ${sourced ? '' : 'line-through opacity-60'}`}
                      >
                        <td>
                          <input type="checkbox" className="check" disabled={!sourced} checked={currentSelection.has(ioc.value)} onChange={() => toggle(ioc.value)} aria-label={`Keep ${ioc.value}`} />
                        </td>
                        <td className="mono max-w-[32rem] break-all text-[12.5px]">{ioc.value}</td>
                        <td className="text-[13px] text-[var(--slate)]">{ioc.type}</td>
                        <td>
                          {sourced ? (
                            <span className="flex flex-wrap items-center gap-2">
                              <SourceLink ioc={ioc} />
                              {ioc.corroborating_sources.length > 0 ? (
                                <Chip tone="indigo" small title={`Also surfaced by: ${ioc.corroborating_sources.join(', ')}`}>
                                  +{ioc.corroborating_sources.length} ({ioc.corroborating_sources.join(', ')})
                                </Chip>
                              ) : null}
                            </span>
                          ) : (
                            <span className="text-[13px] text-[var(--garnet)]">source missing, not selectable</span>
                          )}
                        </td>
                        <td className="mono text-[12.5px] text-[var(--slate)]">{ioc.first_seen ?? '-'}</td>
                        <td className="text-[13px] text-[var(--slate)]">{ioc.confidence ?? '-'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Inner>
        )}

        {validateAndStart.error ? (
          <ErrorNotice
            message={validateAndStart.error instanceof ApiError ? validateAndStart.error.message : 'The hunt could not start.'}
            hint={validateAndStart.error instanceof ApiError ? validateAndStart.error.hint : null}
          />
        ) : null}

        <div className="flex flex-wrap items-center justify-between gap-4 px-1">
          <span className="text-[13px] text-[var(--slate)]">Rejected indicators are logged with your name; the agent never sees them.</span>
          <div className="flex flex-wrap items-center gap-3">
            <Btn variant="light" onClick={() => navigate('/new')}>
              Reformulate the hypothesis
            </Btn>
            <Btn onClick={() => validateAndStart.mutate()} disabled={validateAndStart.isPending} end={<IconArrowRight size={16} />}>
              {validateAndStart.isPending ? 'Launching…' : `Launch the hunt${rows.length > 0 ? ` with ${currentSelection.size} indicator(s)` : ''}`}
            </Btn>
          </div>
        </div>
      </Glass>
    </div>
  )
}

function hasSource(ioc: Ioc): boolean {
  return Boolean(ioc.source_url && ioc.source)
}

function SourceLink({ ioc }: { ioc: Ioc }) {
  if (ioc.source_url.startsWith('internal://')) {
    return <span className="text-[13px] text-[var(--slate)]">{ioc.source}</span>
  }
  return (
    <a href={ioc.source_url} target="_blank" rel="noreferrer noopener" className="link text-[13px]">
      {ioc.source}
    </a>
  )
}
