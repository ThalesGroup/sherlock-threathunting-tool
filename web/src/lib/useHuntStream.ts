/**
 * Subscription to the investigation thread via Server-Sent Events.
 *
 * `EventSource` does not allow adding a header, so no authentication token; we therefore
 * read the stream with `fetch` and a ReadableStream. This also avoids passing a token in
 * the URL, where it would end up in the logs of every intermediary.
 */

import { useEffect, useRef, useState } from 'react'

import { authHeaders } from './api'

export interface HuntEvent {
  hunt_id: string
  type: string
  sequence: number
  timestamp: string
  payload: Record<string, unknown>
}

export interface StreamState {
  events: HuntEvent[]
  connected: boolean
  finished: boolean
  error: string | null
}

const TERMINAL_EVENTS = new Set(['concluded', 'failed'])

export function useHuntStream(huntId: string | undefined, enabled = true): StreamState {
  const [state, setState] = useState<StreamState>({
    events: [],
    connected: false,
    finished: false,
    error: null,
  })
  const seen = useRef(new Set<number>())

  useEffect(() => {
    if (!huntId || !enabled) return

    const controller = new AbortController()
    seen.current = new Set()
    setState({ events: [], connected: false, finished: false, error: null })

    const read = async () => {
      try {
        const response = await fetch(`/api/hunts/${huntId}/events`, {
          headers: { Accept: 'text/event-stream', ...authHeaders() },
          signal: controller.signal,
        })
        if (!response.ok || !response.body) {
          setState((current) => ({
            ...current,
            error: 'The investigation thread is unavailable.',
          }))
          return
        }

        setState((current) => ({ ...current, connected: true }))
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })

          let separator = buffer.indexOf('\n\n')
          while (separator !== -1) {
            const frame = buffer.slice(0, separator)
            buffer = buffer.slice(separator + 2)
            const event = parseFrame(frame)
            if (event && !seen.current.has(event.sequence)) {
              seen.current.add(event.sequence)
              setState((current) => ({
                ...current,
                events: [...current.events, event],
                finished: current.finished || TERMINAL_EVENTS.has(event.type),
              }))
            }
            separator = buffer.indexOf('\n\n')
          }
        }
        setState((current) => ({ ...current, connected: false, finished: true }))
      } catch (error) {
        if (controller.signal.aborted) return
        setState((current) => ({
          ...current,
          connected: false,
          error: error instanceof Error ? error.message : 'Stream interrupted.',
        }))
      }
    }

    void read()
    return () => controller.abort()
  }, [huntId, enabled])

  return state
}

function parseFrame(frame: string): HuntEvent | null {
  const dataLines = frame
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trim())

  if (dataLines.length === 0) return null
  try {
    return JSON.parse(dataLines.join('\n')) as HuntEvent
  } catch {
    return null
  }
}
