/**
 * State of IOC searches, kept outside the screens and per hunt.
 *
 * A threat intel search takes from a few seconds to a minute: its state lives here to
 * survive navigation. The analyst can leave the validation screen during the search and
 * find it in progress — or finished — on returning. On completion, the hunt's indicator
 * cache is invalidated, whether the screen is mounted or not.
 */

import { api, ApiError, type TimeRange } from './api'
import { queryClient } from './queryClient'

export interface EnrichState {
  status: 'idle' | 'running' | 'done' | 'error'
  campaign: string | null
  added: number | null
  error: string | null
  hint: string | null
}

export const ENRICH_IDLE: EnrichState = {
  status: 'idle',
  campaign: null,
  added: null,
  error: null,
  hint: null,
}

let snapshot: Record<string, EnrichState> = {}
const listeners = new Set<() => void>()

function update(huntId: string, state: EnrichState): void {
  snapshot = { ...snapshot, [huntId]: state }
  listeners.forEach((listener) => listener())
}

export function subscribeEnrich(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getEnrichSnapshot(): Record<string, EnrichState> {
  return snapshot
}

export async function startIocSearch(
  huntId: string,
  campaign: string,
  maxResults: number,
  timeRange: TimeRange,
  beforeCount: number,
): Promise<void> {
  if (snapshot[huntId]?.status === 'running') return
  const name = campaign.trim()
  update(huntId, { status: 'running', campaign: name, added: null, error: null, hint: null })
  try {
    const result = await api.enrich(huntId, name, maxResults, timeRange)
    update(huntId, {
      status: 'done',
      campaign: name,
      added: result.length - beforeCount,
      error: null,
      hint: null,
    })
    void queryClient.invalidateQueries({ queryKey: ['iocs', huntId] })
  } catch (error) {
    update(huntId, {
      status: 'error',
      campaign: name,
      added: null,
      error: error instanceof ApiError ? error.message : 'The search failed.',
      hint: error instanceof ApiError ? error.hint : null,
    })
  }
}
