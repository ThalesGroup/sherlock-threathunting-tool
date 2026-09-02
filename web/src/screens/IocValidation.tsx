/**
 * Screen 2 — Indicator validation. Blocking human checkpoint.
 *
 * The source column is always filled and always clickable: it is the visual translation of
 * the rule "no indicator from the model's memory". An indicator without a source should
 * never reach this point — the middleware discards it upstream — but if one did, it appears
 * struck through and non-selectable rather than silently absent.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { EmptyState, ErrorNotice, Mono, SectionTitle } from '@/components/primitives'
import { api, ApiError, type Ioc, type TimeRange } from '@/lib/api'
import {
  ENRICH_IDLE,
  getEnrichSnapshot,
  startIocSearch,
  subscribeEnrich,
} from '@/lib/enrichStore'

export function IocValidationScreen() {
  const { huntId = '' } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  const config = useQuery({ queryKey: ['config'], queryFn: api.config })
  const iocs = useQuery({ queryKey: ['iocs', huntId], queryFn: () => api.listIocs(huntId) })
  const summaries = useQuery({
    queryKey: ['hunts', { limit: 50 }],
    queryFn: () => api.listHunts({ limit: 50 }),
  })

  const [selected, setSelected] = useState<Set<string> | null>(null)
  const [campaignInput, setCampaignInput] = useState<string | null>(null)
  const [maxResults, setMaxResults] = useState(50)
  const [timeRange, setTimeRange] = useState<TimeRange>(null)
  const [manualValue, setManualValue] = useState('')
  const [manualType, setManualType] = useState('hash')

  const huntCampaign = summaries.data?.find((hunt) => hunt.hunt_id === huntId)?.campaign ?? ''
  const campaign = campaignInput ?? huntCampaign

  const rows = iocs.data ?? []
  const selectable = useMemo(() => rows.filter(hasSource), [rows])

  const currentSelection = useMemo(() => {
    if (selected !== null) return selected
    return new Set(
      selectable.filter((ioc) => ioc.status === 'validated').map((ioc) => ioc.value),
    )
  }, [selected, selectable])

  const enrichStates = useSyncExternalStore(subscribeEnrich, getEnrichSnapshot)
  const search = enrichStates[huntId] ?? ENRICH_IDLE

  const [addNotice, setAddNotice] = useState<{ tone: 'ok' | 'duplicate' | 'error'; text: string } | null>(
    null,
  )
  const [lastAdded, setLastAdded] = useState<string | null>(null)

  const importFile = useMutation({
    mutationFn: (file: File) => api.importIocs(huntId, file),
    onSuccess: (result) => {
      const types = Object.entries(result.by_type)
        .map(([type, count]) => `${count} ${type}`)
        .join(', ')
      setAddNotice({
        tone: result.added > 0 ? 'ok' : 'duplicate',
        text:
          result.added > 0
            ? `${result.added} indicator(s) imported (${types})` +
              (result.duplicates > 0 ? ` · ${result.duplicates} already present` : '') +
              ' — validate them below.'
            : result.extracted === 0
              ? 'No indicator recognized in this file.'
              : `Nothing to add: the ${result.duplicates} indicators in the file are already in the list.`,
      })
      queryClient.invalidateQueries({ queryKey: ['iocs', huntId] })
    },
  })

  const addManual = useMutation({
    mutationFn: () =>
      api.addIocs(huntId, [{ value: manualValue.trim(), type: manualType }]),
    onSuccess: (result) => {
      if (result.duplicates.length > 0) {
        setAddNotice({
          tone: 'duplicate',
          text: `Already present in the list (defang normalized): ${result.duplicates.join(', ')}. Nothing was added.`,
        })
        setLastAdded(null)
        return
      }
      setAddNotice({ tone: 'ok', text: `${result.added} indicator added at the bottom of the list.` })
      setLastAdded(manualValue.trim())
      setManualValue('')
      queryClient.invalidateQueries({ queryKey: ['iocs', huntId] })
    },
  })

  const validateAndStart = useMutation({
    mutationFn: async () => {
      const validated = [...currentSelection]
      const rejected = selectable
        .map((ioc) => ioc.value)
        .filter((value) => !currentSelection.has(value))
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
      setAddNotice({ tone: 'error', text: state.importError })
      navigate(location.pathname + location.search, { replace: true })
    }
  }, [location, navigate])
  useEffect(() => {
    const fromUrl = searchParams.get('campaign')
    if (fromUrl && campaignInput === null) {
      setCampaignInput(fromUrl)
    }
    const name = (fromUrl ?? campaign).trim()
    if (
      searchParams.get('auto') === '1' &&
      !autoTriggered.current &&
      name.length >= 2 &&
      config.data?.threat_intel_enabled
    ) {
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
    setSelected(
      currentSelection.size === selectable.length
        ? new Set()
        : new Set(selectable.map((ioc) => ioc.value)),
    )
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-[22px] font-semibold tracking-tight text-ink">Validate the indicators</h1>
        <p className="meta-text mt-1">
          No query goes to a SIEM until you have decided.
        </p>
      </header>

      {config.data?.threat_intel_enabled ? (
        <section className="card p-4">
          <SectionTitle>Search for indicators</SectionTitle>
          <p className="meta-text mt-1">
            Only the campaign name leaves the internal scope. No element of the hunt's
            context is sent.
          </p>
          <div className="mt-3 flex flex-wrap items-end gap-2">
            <input
              value={campaign}
              onChange={(event) => setCampaignInput(event.target.value)}
              className="field max-w-sm flex-1"
              placeholder="Volt Typhoon"
              aria-label="Campaign name to search"
            />
            <label className="text-sm text-ink">
              <span className="meta-text block">Number of IOCs</span>
              <input
                type="number"
                min={1}
                max={200}
                value={maxResults}
                onChange={(event) =>
                  setMaxResults(Math.min(200, Math.max(1, Number(event.target.value) || 1)))
                }
                className="field mt-1 w-24"
                aria-label="Maximum number of indicators to search (1 to 200)"
              />
            </label>
            <label className="text-sm text-ink">
              <span className="meta-text block">Freshness</span>
              <select
                value={timeRange ?? ''}
                onChange={(event) =>
                  setTimeRange(
                    event.target.value === ''
                      ? null
                      : (event.target.value as NonNullable<TimeRange>),
                  )
                }
                className="field mt-1"
                aria-label="Freshness of the indicators searched"
              >
                <option value="">All periods</option>
                <option value="month">Less than a month</option>
                <option value="3months">Less than 3 months</option>
                <option value="9months">Less than 9 months</option>
                <option value="year">Less than a year</option>
              </select>
            </label>
            <button
              type="button"
              className="btn-secondary"
              onClick={() =>
                void startIocSearch(huntId, campaign, maxResults, timeRange, rows.length)
              }
              disabled={search.status === 'running' || campaign.trim().length < 2}
            >
              Search
            </button>
          </div>
          {search.status === 'running' ? (
            <div className="mt-3" role="status">
              <div className="mb-1.5 flex items-baseline justify-between">
                <span className="text-xs text-indigo">
                  Searching indicators for "{search.campaign}"… The search continues if you
                  change pages.
                </span>
              </div>
              <div className="bar-track">
                <div className="bar-indeterminate" />
              </div>
            </div>
          ) : null}
          {search.status === 'error' && search.error ? (
            <div className="mt-3">
              <ErrorNotice message={search.error} hint={search.hint} />
            </div>
          ) : null}
          {search.status === 'done' && search.added !== null ? (
            search.added > 0 ? (
              <p className="mt-3 text-xs text-mint" role="status">
                Search complete: {search.added} new indicator{search.added > 1 ? 's' : ''} added
                to the table.
              </p>
            ) : (
              <p className="mt-3 text-xs text-amber" role="status">
                Search complete: no new indicator found for this name. Vulnerability
                disclosures rarely publish IOCs — try a shorter name (e.g. the flaw or actor
                name alone), a different freshness, or start from a behavioral hypothesis.
              </p>
            )
          ) : null}
        </section>
      ) : null}

      <section className="card p-4">
        <SectionTitle>Add my indicators</SectionTitle>
        <p className="meta-text mt-1">
          Your own indicators complement those from threat intel. Their source is you: they
          arrive validated and attributed by name.
        </p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <input
            value={manualValue}
            onChange={(event) => setManualValue(event.target.value)}
            className="field max-w-md flex-1 font-mono"
            placeholder="e.g. 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            aria-label="Value of the indicator to add"
            onKeyDown={(event) => {
              if (event.key === 'Enter' && manualValue.trim().length > 0) {
                event.preventDefault()
                addManual.mutate()
              }
            }}
          />
          <label className="text-sm text-ink">
            <span className="meta-text block">Type</span>
            <select
              value={manualType}
              onChange={(event) => setManualType(event.target.value)}
              className="field mt-1"
              aria-label="Indicator type"
            >
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
          <button
            type="button"
            className="btn-secondary"
            onClick={() => addManual.mutate()}
            disabled={addManual.isPending || manualValue.trim().length === 0}
          >
            {addManual.isPending ? 'Adding…' : 'Add'}
          </button>
          <label className="btn-secondary cursor-pointer">
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
          <span className="meta-text">txt, csv or xlsx — pattern extraction, to validate afterward</span>
        </div>
        {addNotice ? (
          <p
            className={`mt-3 text-sm ${
              addNotice.tone === 'error'
                ? 'text-garnet'
                : addNotice.tone === 'duplicate'
                  ? 'text-amber'
                  : 'text-mint'
            }`}
            role="status"
          >
            {addNotice.text}
          </p>
        ) : null}
        {importFile.error ? (
          <div className="mt-3">
            <ErrorNotice
              message={
                importFile.error instanceof ApiError
                  ? importFile.error.message
                  : 'The file could not be imported.'
              }
            />
          </div>
        ) : null}
        {addManual.error ? (
          <div className="mt-3">
            <ErrorNotice
              message={
                addManual.error instanceof ApiError
                  ? addManual.error.message
                  : 'The indicator could not be added.'
              }
              hint={addManual.error instanceof ApiError ? addManual.error.hint : null}
            />
          </div>
        ) : null}
      </section>

      {rows.length === 0 ? (
        <EmptyState title="No indicator">
          This hunt is purely behavioral. You can launch it as is: the agent will reason on
          TTPs rather than on matches.
        </EmptyState>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Indicators surfaced for this hunt</caption>
            <thead className="border-b border-rule bg-paper text-xs uppercase tracking-wide text-slate">
              <tr>
                <th scope="col" className="px-4 py-3">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      className="accent-indigo"
                      checked={
                        selectable.length > 0 && currentSelection.size === selectable.length
                      }
                      onChange={toggleAll}
                      aria-label="Select all"
                    />
                    <span className="sr-only">Selection</span>
                  </label>
                </th>
                <th scope="col" className="px-4 py-3">Value</th>
                <th scope="col" className="px-4 py-3">Type</th>
                <th scope="col" className="px-4 py-3">Source</th>
                <th scope="col" className="px-4 py-3">First seen</th>
                <th scope="col" className="px-4 py-3">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((ioc) => {
                const sourced = hasSource(ioc)
                return (
                  <tr
                    key={`${ioc.type}:${ioc.value}`}
                    className={`border-b border-rule last:border-0 ${
                      ioc.value === lastAdded ? 'bg-mint/10 ' : ''
                    }${
                      sourced ? '' : 'bg-garnet/5 line-through opacity-70'
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        className="accent-indigo"
                        disabled={!sourced}
                        checked={currentSelection.has(ioc.value)}
                        onChange={() => toggle(ioc.value)}
                        aria-label={`Keep ${ioc.value}`}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <Mono>{ioc.value}</Mono>
                    </td>
                    <td className="px-4 py-3 text-slate">{ioc.type}</td>
                    <td className="px-4 py-3">
                      {sourced ? (
                        <div className="flex flex-wrap items-center gap-2">
                          <SourceLink ioc={ioc} />
                          {ioc.corroborating_sources.length > 0 ? (
                            <span
                              className="rounded bg-indigo/10 px-1.5 py-0.5 text-xs text-indigo"
                              title={`Also surfaced by: ${ioc.corroborating_sources.join(', ')}`}
                            >
                              +{ioc.corroborating_sources.length} source
                              {ioc.corroborating_sources.length > 1 ? 's' : ''} (
                              {ioc.corroborating_sources.join(', ')})
                            </span>
                          ) : null}
                        </div>
                      ) : (
                        <span className="text-garnet">source missing — not selectable</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate">{ioc.first_seen ?? '—'}</td>
                    <td className="px-4 py-3 text-slate">{ioc.confidence ?? '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {validateAndStart.error ? (
        <ErrorNotice
          message={
            validateAndStart.error instanceof ApiError
              ? validateAndStart.error.message
              : 'The hunt could not start.'
          }
          hint={
            validateAndStart.error instanceof ApiError ? validateAndStart.error.hint : null
          }
        />
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          className="btn-primary"
          onClick={() => validateAndStart.mutate()}
          disabled={validateAndStart.isPending}
        >
          {validateAndStart.isPending
            ? 'Launching…'
            : `Launch the hunt${
                rows.length > 0 ? ` with ${currentSelection.size} indicator(s)` : ''
              }`}
        </button>
        <button type="button" className="btn-secondary" onClick={() => navigate('/')}>
          Reformulate the hypothesis
        </button>
      </div>
    </div>
  )
}

function hasSource(ioc: Ioc): boolean {
  return Boolean(ioc.source_url && ioc.source)
}

/**
 * Internal sources (indicators entered by an analyst) are not openable links: we display
 * the attribution, without fabricating a clickable URL that would lead nowhere.
 */
function SourceLink({ ioc }: { ioc: Ioc }) {
  if (ioc.source_url.startsWith('internal://')) {
    return <span className="text-slate">{ioc.source}</span>
  }
  return (
    <a
      href={ioc.source_url}
      target="_blank"
      rel="noreferrer noopener"
      className="text-indigo underline underline-offset-2"
    >
      {ioc.source}
    </a>
  )
}
