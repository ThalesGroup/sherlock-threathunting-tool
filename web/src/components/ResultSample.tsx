/**
 * Sample of the rows returned by a query, collapsed by default, with the proof of
 * anonymization: what the model received (pseudonyms in place) is compared against what
 * the analyst sees (rehydrated locally).
 *
 * The values come from the middleware, already minimized: they are rendered as inert
 * text, never interpreted. The table only shows an excerpt (ten rows at most); the real
 * number of source rows is recalled in the panel label.
 */

import { useState } from 'react'

import { Mono } from '@/components/primitives'
import type { AnonymizationInfo } from '@/lib/api'

const MAX_CELL = 160

const TOKEN_LABELS: [keyof AnonymizationInfo['tokens'], string][] = [
  ['HOST', 'host(s)'],
  ['USER', 'account(s)'],
  ['IP-INT', 'internal IP(s)'],
  ['DATA', 'free-text fragment(s)'],
]

export function AnonymizationLine({ info }: { info: AnonymizationInfo | null | undefined }) {
  if (!info || !info.tokens) return null
  const parts = TOKEN_LABELS.filter(([key]) => info.tokens[key] > 0).map(
    ([key, label]) => `${info.tokens[key]} ${label}`,
  )
  const semantic =
    info.semantic === 'active'
      ? 'semantic pass active'
      : info.semantic === 'degraded'
        ? 'semantic pass degraded, free text masked'
        : 'semantic pass disabled'
  const tone =
    info.semantic === 'degraded' || !info.tokenization
      ? 'text-amber'
      : info.semantic === 'active'
        ? 'text-mint'
        : 'text-slate'
  return (
    <p className={`meta-mono ${tone}`}>
      <span aria-hidden="true">⛨ </span>
      Sent to the model:{' '}
      {parts.length > 0 ? `${parts.join(' · ')} pseudonymized` : 'no internal identifier'} ·{' '}
      {semantic}
      {info.masked_fields > 0 ? ` · ${info.masked_fields} masked field(s)` : ''}
      {!info.tokenization ? ' · tokenization disabled' : ''}
    </p>
  )
}

export function ResultSample({
  columns,
  rows,
  modelRows = [],
  sourceRows,
  defaultOpen = false,
}: {
  columns: string[]
  rows: Record<string, unknown>[]
  modelRows?: Record<string, unknown>[]
  sourceRows: number
  defaultOpen?: boolean
}) {
  const [view, setView] = useState<'analyst' | 'model'>('analyst')
  if (rows.length === 0 || columns.length === 0) return null
  const label =
    rows.length < sourceRows
      ? `View ${rows.length} row(s) of ${sourceRows}`
      : `View ${rows.length === 1 ? 'the row' : `the ${rows.length} rows`}`
  const shown = view === 'model' && modelRows.length > 0 ? modelRows : rows
  return (
    <details className="group" open={defaultOpen}>
      <summary className="flex cursor-pointer select-none items-center gap-1.5 text-sm text-indigo">
        <span
          className="inline-block transition-transform group-open:rotate-90 motion-reduce:transition-none"
          aria-hidden="true"
        >
          ▸
        </span>
        {label}
      </summary>
      {modelRows.length > 0 ? (
        <div className="mt-2 flex gap-1" role="tablist" aria-label="Results view">
          {(
            [
              ['analyst', 'Analyst view (rehydrated)'],
              ['model', 'Sent to the model (pseudonyms)'],
            ] as const
          ).map(([key, text]) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={view === key}
              onClick={() => setView(key)}
              className={`rounded-btn border px-2.5 py-1 text-xs ${
                view === key
                  ? 'border-navy bg-navy text-white'
                  : 'border-field-border text-slate hover:bg-soft-bg'
              }`}
            >
              {text}
            </button>
          ))}
        </div>
      ) : null}
      <div className="mt-2 overflow-x-auto rounded-[8px] border border-rule-soft">
        <table className="w-full text-left">
          <thead className="bg-soft-bg">
            <tr>
              {columns.map((column) => (
                <th key={column} className="meta-mono whitespace-nowrap px-3 py-1.5 font-medium">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, index) => (
              <tr key={index} className="border-t border-rule-soft align-top">
                {columns.map((column) => (
                  <td key={column} className="max-w-[24rem] px-3 py-1.5">
                    <Mono className="whitespace-pre-wrap break-words text-[11px] text-[#3d4d5c]">
                      {cell(row[column])}
                    </Mono>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  )
}

function cell(value: unknown): string {
  if (value === null || value === undefined) return ''
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  return text.length > MAX_CELL ? `${text.slice(0, MAX_CELL)}…` : text
}
