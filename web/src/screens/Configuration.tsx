/**
 * Screen 7 - Configuration (admin role).
 *
 * Each installation wires here the keys of its ecosystem: the AI gateway, SIEM, threat intel.
 * Keys are written and tested, they are never read back: the API only returns states. The
 * allowlist of outbound domains stays server-side, out of reach of this screen.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { ErrorNotice, Mono, SectionTitle } from '@/components/primitives'
import {
  api,
  ApiError,
  type AccountView,
  type SecretFieldView,
  type SourceConfigView,
  type SourceTestResult,
} from '@/lib/api'

const KIND_LABELS: Record<SourceConfigView['kind'], string> = {
  engine: 'Reasoning engine',
  siem: 'SIEM',
  ti: 'Threat intel',
}

const KIND_ORDER: SourceConfigView['kind'][] = ['engine', 'siem', 'ti']

export function ConfigurationScreen() {
  const sources = useQuery({
    queryKey: ['config', 'sources'],
    queryFn: api.sourceConfiguration,
    retry: false,
  })

  if (sources.isLoading) return <p className="meta-text">Loading…</p>

  if (sources.error instanceof ApiError && sources.error.status === 403) {
    return (
      <ErrorNotice
        message="This screen is reserved for the admin role."
        hint="Reserved for the admin role."
      />
    )
  }
  if (sources.error) {
    return <ErrorNotice message={sources.error.message} />
  }

  const grouped = KIND_ORDER.map((kind) => ({
    kind,
    items: (sources.data ?? []).filter((source) => source.kind === kind),
  })).filter((group) => group.items.length > 0)

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-[22px] font-semibold tracking-tight text-ink">Configuration</h1>
        <p className="mt-1 text-sm text-slate">
          The keys entered here are encrypted server-side and never come back down to the
          browser. Every change is logged. The allowed outbound domains are managed
          server-side, not here.
        </p>
      </header>

      {grouped.map((group) => (
        <section key={group.kind}>
          <SectionTitle>{KIND_LABELS[group.kind]}</SectionTitle>
          <div className="mt-4 space-y-4">
            {group.items.map((source) => (
              <SourceCard key={source.id} source={source} />
            ))}
          </div>
        </section>
      ))}

      <AccountsSection />
    </div>
  )
}

const ROLE_PRESETS = [
  { value: 'analyst', label: 'Analyst', roles: ['analyst'] },
  { value: 'analyst,admin', label: 'Analyst + admin', roles: ['analyst', 'admin'] },
  { value: 'reader', label: 'Reader', roles: ['reader'] },
]

function AccountsSection() {
  const queryClient = useQueryClient()
  const accounts = useQuery({ queryKey: ['config', 'accounts'], queryFn: api.listAccounts })

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [preset, setPreset] = useState(ROLE_PRESETS[0].value)

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['config', 'accounts'] })
  const create = useMutation({
    mutationFn: () => {
      const roles = ROLE_PRESETS.find((choice) => choice.value === preset)?.roles ?? ['analyst']
      return api.createAccount(username.trim(), password, roles)
    },
    onSuccess: () => {
      setUsername('')
      setPassword('')
      invalidate()
    },
  })
  const remove = useMutation({
    mutationFn: (target: string) => api.deleteAccount(target),
    onSuccess: invalidate,
  })

  return (
    <section>
      <SectionTitle>Accounts</SectionTitle>
      <p className="meta-text mt-1">
        Access is granted here: no self-registration. Every creation and deletion is logged.
      </p>

      <div className="card mt-4 p-4">
        {accounts.isLoading ? <p className="meta-text">Loading…</p> : null}
        {accounts.data && accounts.data.length === 0 ? (
          <p className="meta-text">No local account yet.</p>
        ) : null}
        {accounts.data && accounts.data.length > 0 ? (
          <ul className="divide-y divide-rule">
            {accounts.data.map((account: AccountView) => (
              <li key={account.username} className="flex flex-wrap items-center gap-3 py-2">
                <Mono className="text-sm text-ink">{account.username}</Mono>
                <span className="meta-text">{account.roles.join(', ')}</span>
                <span className="meta-text ml-auto">created by {account.created_by}</span>
                <button
                  type="button"
                  className="text-sm text-slate underline hover:text-garnet"
                  onClick={() => remove.mutate(account.username)}
                  disabled={remove.isPending}
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {remove.error ? <p className="mt-2 text-sm text-garnet">{remove.error.message}</p> : null}

        <form
          className="mt-4 flex flex-wrap items-end gap-3 border-t border-rule pt-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (username.trim().length >= 2 && password.length >= 12) create.mutate()
          }}
        >
          <label className="block text-sm text-ink">
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="field mt-1"
              placeholder="first.last"
            />
          </label>
          <label className="block text-sm text-ink">
            Password (12 characters min)
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
              className="field mt-1"
            />
          </label>
          <label className="block text-sm text-ink">
            Roles
            <select
              value={preset}
              onChange={(event) => setPreset(event.target.value)}
              className="field mt-1"
            >
              {ROLE_PRESETS.map((choice) => (
                <option key={choice.value} value={choice.value}>
                  {choice.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            className="btn-secondary"
            disabled={create.isPending || username.trim().length < 2 || password.length < 12}
          >
            Create account
          </button>
          {create.error ? (
            <p className="w-full text-sm text-garnet">{create.error.message}</p>
          ) : null}
        </form>
      </div>
    </section>
  )
}

function SourceCard({ source }: { source: SourceConfigView }) {
  const queryClient = useQueryClient()
  const [testResult, setTestResult] = useState<SourceTestResult | null>(null)

  const test = useMutation({
    mutationFn: () => api.testSource(source.id),
    onSuccess: (result) => {
      setTestResult(result)
      void queryClient.invalidateQueries({ queryKey: ['config'] })
    },
  })

  return (
    <article className="card p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="font-medium text-ink">{source.label}</h3>
        <span
          className={`rounded px-2 py-0.5 text-xs ${
            source.active ? 'bg-indigo/10 text-indigo' : 'bg-amber/10 text-amber'
          }`}
        >
          {source.active ? 'Active' : 'Inactive'}
        </span>
      </div>

      {source.endpoint || source.model ? (
        <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs">
          {source.endpoint ? (
            <>
              <dt className="text-meta">Endpoint</dt>
              <dd className="min-w-0 truncate">
                <Mono className="text-[11px] text-slate">{source.endpoint}</Mono>
              </dd>
            </>
          ) : null}
          {source.model ? (
            <>
              <dt className="text-meta">Model</dt>
              <dd className="min-w-0 truncate">
                <Mono className="text-[11px] text-slate">{source.model}</Mono>
              </dd>
            </>
          ) : null}
          <dt className="sr-only">Scope</dt>
          <dd className="col-span-2 text-[11px] text-meta">
            Server-side setting (read-only here): a new key issued for another offer may
            require another endpoint.
          </dd>
        </dl>
      ) : null}

      {source.requirement ? <p className="mt-2 text-sm text-amber">{source.requirement}</p> : null}

      {source.secrets.length === 0 ? (
        <p className="meta-text mt-3">No key required for this source.</p>
      ) : (
        <div className="mt-3 space-y-3">
          {source.secrets.map((secret) => (
            <SecretRow key={secret.name} secret={secret} />
          ))}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-rule pt-3">
        <button
          type="button"
          className="btn-secondary"
          onClick={() => test.mutate()}
          disabled={test.isPending}
        >
          {test.isPending ? 'Testing…' : 'Test the connection'}
        </button>
        {test.error ? <span className="text-sm text-garnet">{test.error.message}</span> : null}
        {testResult ? (
          <span className={`text-sm ${testResult.ok ? 'text-indigo' : 'text-garnet'}`}>
            {testResult.detail}
          </span>
        ) : null}
      </div>
    </article>
  )
}

const FIELD_LABELS: Record<string, string> = {
  ENTRA_TENANT_ID: 'Tenant ID',
  ENTRA_CLIENT_ID: 'Client ID (application)',
  ENTRA_CLIENT_SECRET: 'Client secret',
  SENTINEL_SUBSCRIPTION_ID: 'Subscription ID (Sentinel)',
  SENTINEL_RESOURCE_GROUP: 'Resource group (Sentinel)',
  SENTINEL_WORKSPACE_NAME: 'Workspace name (Sentinel)',
  SENTINEL_WORKSPACE_ID: 'Direct workspace ID (Sentinel, GUID)',
  SECOPS_SA_KEY: 'Service account JSON key',
  SECOPS_INSTANCE_PATH: 'SecOps instance ID',
}

/** Fields that are identifiers, not secrets: entered in plain text. */
const PLAIN_FIELDS = new Set([
  'ENTRA_TENANT_ID',
  'ENTRA_CLIENT_ID',
  'SENTINEL_SUBSCRIPTION_ID',
  'SENTINEL_RESOURCE_GROUP',
  'SENTINEL_WORKSPACE_NAME',
  'SENTINEL_WORKSPACE_ID',
  'SECOPS_INSTANCE_PATH',
  'SEARCH_ENGINE_ID',
])

function SecretRow({ secret }: { secret: SecretFieldView }) {
  const queryClient = useQueryClient()
  const [value, setValue] = useState('')
  const plain = PLAIN_FIELDS.has(secret.name)
  const minLength = plain ? 1 : 4

  const invalidate = () => {
    setValue('')
    void queryClient.invalidateQueries({ queryKey: ['config'] })
  }
  const save = useMutation({
    mutationFn: () => api.setSecret(secret.name, value),
    onSuccess: invalidate,
  })
  const remove = useMutation({
    mutationFn: () => api.deleteSecret(secret.name),
    onSuccess: invalidate,
  })

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="w-56 shrink-0">
        <span className="block text-sm text-ink">{FIELD_LABELS[secret.name] ?? secret.name}</span>
        {FIELD_LABELS[secret.name] ? (
          <Mono className="text-[10px] text-meta">{secret.name}</Mono>
        ) : null}
      </div>

      <span className="meta-text w-64 shrink-0">
        {secret.configured
          ? secret.origin === 'configuration'
            ? `Configured${secret.updated_by ? ` by ${secret.updated_by}` : ''}`
            : 'Provided by the server environment'
          : 'Absent'}
      </span>

      <form
        className="flex min-w-64 flex-1 items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          if (value.trim().length >= minLength) save.mutate()
        }}
      >
        <input
          type={plain ? 'text' : 'password'}
          autoComplete="off"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="New value"
          aria-label={`New value for ${secret.name}`}
          className="field flex-1 font-mono text-sm"
        />
        <button
          type="submit"
          className="btn-secondary"
          disabled={save.isPending || value.trim().length < minLength}
        >
          Save
        </button>
        {secret.origin === 'configuration' ? (
          <button
            type="button"
            className="text-sm text-slate underline hover:text-garnet"
            onClick={() => remove.mutate()}
            disabled={remove.isPending}
          >
            Delete
          </button>
        ) : null}
      </form>

      {save.error ? <p className="w-full text-sm text-garnet">{save.error.message}</p> : null}
      {remove.error ? <p className="w-full text-sm text-garnet">{remove.error.message}</p> : null}
    </div>
  )
}
