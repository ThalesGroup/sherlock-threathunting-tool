/**
 * CTI analysis state, kept outside the screen.
 *
 * Analyzing a report and probing IOCs take several minutes: their state lives here, at the
 * module level, to survive navigation. The analyst can leave the page during the analysis
 * and find it in progress - or finished - on returning. Nothing is stored in the browser:
 * a full tab reload starts from scratch, the server history keeps the trace.
 */

import { api, ApiError, type CtiAnalysis, type CtiAttack, type CtiProbe } from './api'

export type ProbeState =
  | { state: 'loading' }
  | { state: 'done'; result: CtiProbe }
  | { state: 'error'; message: string }

export interface CtiState {
  phase: 'idle' | 'analyzing' | 'probing' | 'ready'
  analysisId: string | null
  filename: string | null
  analyzedAt: string | null
  error: string | null
  errorHint: string | null
  analysis: CtiAnalysis | null
  probes: Record<number, ProbeState>
}

let state: CtiState = {
  phase: 'idle',
  analysisId: null,
  filename: null,
  analyzedAt: null,
  error: null,
  errorHint: null,
  analysis: null,
  probes: {},
}

const listeners = new Set<() => void>()

function update(partial: Partial<CtiState>): void {
  state = { ...state, ...partial }
  listeners.forEach((listener) => listener())
}

export function subscribeCti(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getCtiState(): CtiState {
  return state
}

export async function startCtiAnalysis(file: File, tiEnabled: boolean): Promise<void> {
  if (state.phase === 'analyzing' || state.phase === 'probing') return
  update({
    phase: 'analyzing',
    analysisId: null,
    filename: file.name,
    analyzedAt: null,
    error: null,
    errorHint: null,
    analysis: null,
    probes: {},
  })
  try {
    const analysis = await api.analyzeCti(file)
    update({
      analysis,
      analysisId: analysis.analysis_id,
      analyzedAt: new Date().toLocaleTimeString('en-GB', { timeStyle: 'short' }),
    })
    if (tiEnabled && analysis.attacks.length > 0) {
      update({ phase: 'probing' })
      await probeAll(analysis.attacks)
    }
    update({ phase: 'ready' })
  } catch (error) {
    update({
      phase: 'idle',
      error: error instanceof ApiError ? error.message : 'The report analysis failed.',
      errorHint: error instanceof ApiError ? error.hint : null,
    })
  }
}

export async function probeOne(index: number, attack: CtiAttack): Promise<void> {
  update({ probes: { ...state.probes, [index]: { state: 'loading' } } })
  try {
    const result = await api.probeCti(
      attack.name.slice(0, 120),
      state.analysisId ?? undefined,
      index,
    )
    update({ probes: { ...state.probes, [index]: { state: 'done', result } } })
  } catch (error) {
    update({
      probes: {
        ...state.probes,
        [index]: {
          state: 'error',
          message: error instanceof ApiError ? error.message : 'The probe failed.',
        },
      },
    })
  }
}

/** Restores a persisted analysis: cards and probes reappear as they were. */
export async function loadCtiAnalysis(analysisId: string): Promise<void> {
  if (state.phase === 'analyzing' || state.phase === 'probing') return
  try {
    const stored = await api.getCtiAnalysis(analysisId)
    const probes: Record<number, ProbeState> = {}
    stored.attacks.forEach((attack, index) => {
      if (attack.probe) probes[index] = { state: 'done', result: attack.probe }
    })
    update({
      phase: 'ready',
      analysisId: stored.analysis_id,
      filename: stored.filename,
      analyzedAt: new Date(stored.analyzed_at).toLocaleString('en-GB', {
        dateStyle: 'short',
        timeStyle: 'short',
      }),
      error: null,
      errorHint: null,
      analysis: {
        analysis_id: stored.analysis_id,
        attacks: stored.attacks,
        pages: stored.pages,
        truncated: stored.truncated,
      },
      probes,
    })
  } catch (error) {
    update({
      error:
        error instanceof ApiError ? error.message : 'The analysis could not be restored.',
      errorHint: null,
    })
  }
}

/** Two probes in parallel: each probe keeps its full depth. */
async function probeAll(attacks: CtiAttack[]): Promise<void> {
  const queue = attacks.map((attack, index) => [index, attack] as const)
  const worker = async () => {
    for (let next = queue.shift(); next; next = queue.shift()) {
      await probeOne(next[0], next[1])
    }
  }
  await Promise.all([worker(), worker()])
}
