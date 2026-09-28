/**
 * Configuration (admin role). Keys are written and tested, never read back: the API
 * only returns states. Accounts are managed here too: no self-registration.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { api, ApiError, type AccountView, type SecretFieldView, type SourceConfigView, type SourceTestResult } from '@/lib/api'

import { formatShort } from '@/components/format'
import { IconAlert, IconArrowRight, IconCheck, IconInfo, IconTrash } from '@/components/icons'
import { Avatar, Btn, Chip, ErrorNotice, Glass, Inner, Mono, Notice } from '@/components/ui'

type Tab = SourceConfigView['kind'] | 'users'

const TABS: { value: Tab; label: string }[] = [
  { value: 'engine', label: 'Reasoning engine' },
  { value: 'siem', label: 'SIEM' },
  { value: 'ti', label: 'Threat intel' },
  { value: 'users', label: 'Users' },
]

export function ConfigurationScreen() {
  const [tab, setTab] = useState<Tab>('engine')
  const sources = useQuery({ queryKey: ['config', 'sources'], queryFn: api.sourceConfiguration, retry: false })
  const [tests, setTests] = useState<Record<string, SourceTestResult>>({})

  if (sources.isLoading) return <p className="muted">Loading…</p>
  if (sources.error instanceof ApiError && sources.error.status === 403) {
    return <ErrorNotice message="This screen is reserved for the admin role." />
  }
  if (sources.error) return <ErrorNotice message={sources.error.message} />

  const all = sources.data ?? []
  const shown = all.filter((source) => source.kind === tab)
  const toFix = all.filter((source) => !source.active).length
  const lastChange = all
    .flatMap((source) => source.secrets)
    .filter((secret) => secret.updated_at)
    .sort((a, b) => (b.updated_at ?? '').localeCompare(a.updated_at ?? ''))[0]

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="max-w-3xl">
          <h1>Configuration</h1>
          <p className="mt-2 text-[15px] text-[var(--slate)]">The keys entered here are encrypted server-side and never come back down to the browser. Every change is logged. The allowed outbound domains are managed server-side, not here.</p>
        </div>
        <div className="tabs" role="tablist" aria-label="Configuration sections">
          {TABS.map((item) => (
            <button key={item.value} type="button" role="tab" aria-selected={tab === item.value} className={tab === item.value ? 'on' : ''} onClick={() => setTab(item.value)}>
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <Glass className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 space-y-4">
          {tab === 'users' ? (
            <AccountsSection />
          ) : (
            <>
              <p className="lbl px-1">{TABS.find((item) => item.value === tab)?.label}</p>
              {shown.map((source) => (
                <SourceCard key={source.id} source={source} onTested={(result) => setTests((current) => ({ ...current, [source.id]: result }))} />
              ))}
              {shown.length === 0 ? <p className="muted px-1 text-[13.5px]">No source of this kind on this installation.</p> : null}
            </>
          )}
        </div>

        <aside className="inner flex flex-col p-5">
          <div className="flex items-center justify-between">
            <h2>Connector status</h2>
            {toFix > 0 ? (
              <Chip tone="amber" small>
                {toFix} to fix
              </Chip>
            ) : (
              <Chip tone="mint" small>
                all active
              </Chip>
            )}
          </div>
          <ul className="mt-2">
            {all.map((source, index) => {
              const test = tests[source.id]
              return (
                <li key={source.id} className="flex items-center gap-3 border-t border-[var(--rule-soft)] py-3 first:border-t-0">
                  <span className={`sm !cursor-default ${source.active ? '!border-0 !bg-[var(--mint)] !text-white' : ''}`}>{source.active ? <IconCheck size={16} /> : <span className="text-[12px] text-[var(--meta)]">{index + 1}</span>}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-[13.5px] font-semibold">{shortLabel(source)}</span>
                    <span className="tech block truncate">{test ? test.detail : source.active ? 'read-only' : source.requirement ?? 'not configured'}</span>
                  </span>
                  <Chip tone={source.active ? 'mint' : 'soft'} small>
                    {source.active ? 'Active' : 'Inactive'}
                  </Chip>
                </li>
              )
            })}
          </ul>
          {lastChange ? (
            <div className="mt-auto rounded-[18px] bg-white/60 p-4 pt-4">
              <span className="lbl">Last change</span>
              <p className="mt-1 text-[13.5px]">
                <Mono>{lastChange.name}</Mono> updated{lastChange.updated_by ? ` by ${lastChange.updated_by}` : ''}
              </p>
              <p className="tech">{formatShort(lastChange.updated_at ?? '')} · written to the audit log</p>
            </div>
          ) : null}
        </aside>
      </Glass>
    </div>
  )
}

function shortLabel(source: SourceConfigView): string {
  const labels: Record<string, string> = {
    gateway: 'AI gateway',
    anonymizer: 'Anonymizer',
    entra: 'Sentinel & Defender',
    secops: 'Google SecOps',
    virustotal: 'VirusTotal',
    otx: 'AlienVault OTX',
    threatfox: 'ThreatFox',
    circl: 'CIRCL OSINT',
  }
  return labels[source.id] ?? source.label
}

function SourceCard({ source, onTested }: { source: SourceConfigView; onTested: (result: SourceTestResult) => void }) {
  const queryClient = useQueryClient()
  const [testResult, setTestResult] = useState<SourceTestResult | null>(null)
  const test = useMutation({
    mutationFn: () => api.testSource(source.id),
    onSuccess: (result) => {
      setTestResult(result)
      onTested(result)
      void queryClient.invalidateQueries({ queryKey: ['config'] })
    },
  })

  return (
    <Inner className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="!text-[20px]">{source.label}</h2>
          {source.endpoint || source.model ? (
            <p className="mt-1 text-[13px] text-[var(--slate)]">
              {source.model ? (
                <>
                  Model <Mono className="text-[var(--ink)]">{source.model}</Mono>
                </>
              ) : null}
              {source.model && source.endpoint ? ' · ' : ''}
              {source.endpoint ? (
                <>
                  Endpoint <Mono className="text-[var(--ink)]">{source.endpoint}</Mono>
                </>
              ) : null}{' '}
              · server-side setting, read-only here
            </p>
          ) : null}
        </div>
        <Chip tone={source.active ? 'mint' : 'soft'} small>
          {source.active ? 'Active' : 'Inactive'}
        </Chip>
      </div>

      {source.requirement ? (
        <div className="mt-3">
          <Notice tone="amber">{source.requirement}</Notice>
        </div>
      ) : null}

      {source.secrets.length === 0 ? (
        <p className="muted mt-3 text-[13.5px]">No key required for this source.</p>
      ) : (
        <div className="mt-4 space-y-3">
          {source.secrets.map((secret) => (
            <SecretRow key={secret.name} secret={secret} />
          ))}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--rule-soft)] pt-4">
        <span className="text-[12.5px] text-[var(--slate)]">Keys are encrypted server-side and never come back down to the browser. Every change is logged.</span>
        <div className="flex items-center gap-3">
          {test.error ? <span className="text-[13px] text-[var(--garnet)]">{test.error.message}</span> : null}
          {testResult ? (
            <span className={`flex items-center gap-1.5 text-[13px] ${testResult.ok ? 'text-[var(--mint)]' : 'text-[var(--garnet)]'}`}>
              {testResult.ok ? <IconCheck size={14} /> : <IconAlert size={14} />}
              {testResult.detail}
            </span>
          ) : null}
          <Btn variant="light" size="sm" onClick={() => test.mutate()} disabled={test.isPending}>
            {test.isPending ? 'Testing…' : 'Test the connection'} <IconArrowRight size={14} />
          </Btn>
        </div>
      </div>
    </Inner>
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

/** What each field expects, shown in a tooltip next to its label. Sourced from the
 * access-request sheet in docs/architecture.md and the validation rules of the clients. */
const FIELD_HINTS: Record<string, string> = {
  GATEWAY_API_KEY: 'API key of the OpenAI-compatible gateway set by SHL_GATEWAY_BASE_URL (OpenAI, Azure OpenAI, vLLM, Ollama or any compatible facade). The model must support function calling.',
  ANONYMIZER_API_KEY: 'API key of the anonymization endpoint (SHL_ANONYMIZER_BASE_URL). Leave absent if that endpoint needs no key, for example a local model.',
  ENTRA_TENANT_ID: 'Directory (tenant) ID of the Entra ID tenant, a GUID shown on the app registration overview.',
  ENTRA_CLIENT_ID: 'Application (client) ID of the app registration, a GUID. The registration needs Log Analytics Data.Read and ThreatHunting.Read.All (application permissions, admin consent) and the Log Analytics Reader role on the workspace.',
  ENTRA_CLIENT_SECRET: 'Value of a client secret created under the app registration (Certificates & secrets). Copy it at creation: it is never shown again.',
  SENTINEL_SUBSCRIPTION_ID: 'Azure subscription ID (GUID) hosting the Log Analytics workspace. Used with the resource group and workspace name to resolve the workspace ID; not needed when the workspace ID is entered directly.',
  SENTINEL_RESOURCE_GROUP: 'Name of the Azure resource group containing the Log Analytics workspace.',
  SENTINEL_WORKSPACE_NAME: 'Name of the Log Analytics workspace enabled for Sentinel. The platform resolves its ID through the Azure Resource Manager API.',
  SENTINEL_WORKSPACE_ID: 'Workspace ID (GUID) shown on the Log Analytics workspace overview. Entering it directly skips the resolution by subscription, resource group and name.',
  SECOPS_SA_KEY: 'Complete JSON key file of a Google Cloud service account, pasted as is (the object with client_email, private_key and token_uri). The account needs the Chronicle API Viewer role.',
  SECOPS_INSTANCE_PATH: 'Instance path in the form projects/<id>/locations/<region>/instances/<uuid>, from the SecOps console (SOC Profile > Instance ID). The regional endpoint is derived from it.',
  VIRUSTOTAL_API_KEY: 'VirusTotal API key from your profile (API key). The public API is rate-limited and for non-commercial use.',
  OTX_API_KEY: 'AlienVault OTX API key from your OTX profile (Settings > OTX Key). Free.',
  THREATFOX_API_KEY: 'abuse.ch Auth-Key, created from your abuse.ch account, used for the ThreatFox API.',
  TAVILY_API_KEY: 'Tavily Search API key. First choice for vendor-report search when several keys are present.',
  BRAVE_SEARCH_API_KEY: 'Brave Search API subscription token. Used when no Tavily key is present.',
  SEARCH_API_KEY: 'Google Programmable Search API key. Used with SEARCH_ENGINE_ID when neither Tavily nor Brave is configured.',
  SEARCH_ENGINE_ID: 'Google Programmable Search engine ID (cx). The engine is limited to 50 domains.',
}

const PLAIN_FIELDS = new Set(['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'SENTINEL_SUBSCRIPTION_ID', 'SENTINEL_RESOURCE_GROUP', 'SENTINEL_WORKSPACE_NAME', 'SENTINEL_WORKSPACE_ID', 'SECOPS_INSTANCE_PATH', 'SEARCH_ENGINE_ID'])

function SecretRow({ secret }: { secret: SecretFieldView }) {
  const queryClient = useQueryClient()
  const [value, setValue] = useState('')
  const plain = PLAIN_FIELDS.has(secret.name)
  const minLength = plain ? 1 : 4
  const invalidate = () => {
    setValue('')
    void queryClient.invalidateQueries({ queryKey: ['config'] })
  }
  const save = useMutation({ mutationFn: () => api.setSecret(secret.name, value), onSuccess: invalidate })
  const remove = useMutation({ mutationFn: () => api.deleteSecret(secret.name), onSuccess: invalidate })

  return (
    <form
      className="flex flex-wrap items-center gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (value.trim().length >= minLength) save.mutate()
      }}
    >
      <div className="w-56 shrink-0">
        <span className="flex items-center gap-1.5 text-[13.5px] font-medium">
          {FIELD_LABELS[secret.name] ?? secret.name}
          {FIELD_HINTS[secret.name] ? (
            <span className="tip tip-left text-[var(--slate)]" tabIndex={0} aria-label={FIELD_HINTS[secret.name]}>
              <IconInfo size={15} />
              <span role="tooltip">{FIELD_HINTS[secret.name]}</span>
            </span>
          ) : null}
        </span>
        {FIELD_LABELS[secret.name] ? <Mono className="text-[11px] text-[var(--meta)]">{secret.name}</Mono> : null}
      </div>
      <Chip tone={secret.configured ? 'mint' : 'soft'} small className="w-40 justify-center">
        {secret.configured ? (secret.origin === 'configuration' ? `Configured${secret.updated_by ? ` by ${secret.updated_by}` : ''}` : 'From the server') : 'Absent'}
      </Chip>
      <input type={plain ? 'text' : 'password'} autoComplete="off" value={value} onChange={(event) => setValue(event.target.value)} placeholder="New value" aria-label={`New value for ${secret.name}`} className="field field-pill mono min-w-56 flex-1 text-[13px]" />
      <Btn type="submit" variant="light" size="sm" disabled={save.isPending || value.trim().length < minLength}>
        Save
      </Btn>
      {secret.origin === 'configuration' ? (
        <button type="button" className="sm !text-[var(--garnet)]" onClick={() => remove.mutate()} disabled={remove.isPending} title={`Delete ${secret.name}`} aria-label={`Delete ${secret.name}`}>
          <IconTrash size={15} />
        </button>
      ) : null}
      {save.error ? <p className="w-full text-[13px] text-[var(--garnet)]">{save.error.message}</p> : null}
      {remove.error ? <p className="w-full text-[13px] text-[var(--garnet)]">{remove.error.message}</p> : null}
    </form>
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
    mutationFn: () => api.createAccount(username.trim(), password, ROLE_PRESETS.find((choice) => choice.value === preset)?.roles ?? ['analyst']),
    onSuccess: () => {
      setUsername('')
      setPassword('')
      invalidate()
    },
  })
  const remove = useMutation({ mutationFn: (target: string) => api.deleteAccount(target), onSuccess: invalidate })

  return (
    <>
      <p className="lbl px-1">Users</p>
      <Inner className="p-5">
        <h2 className="!text-[20px]">Accounts</h2>
        <p className="mt-1 text-[13.5px] text-[var(--slate)]">Access is granted here: no self-registration. Every creation and deletion is logged.</p>
        {accounts.isLoading ? <p className="muted mt-3">Loading…</p> : null}
        {accounts.data && accounts.data.length === 0 ? <p className="muted mt-3">No local account yet.</p> : null}
        {accounts.data && accounts.data.length > 0 ? (
          <ul className="mt-3">
            {accounts.data.map((account: AccountView) => (
              <li key={account.username} className="flex flex-wrap items-center gap-3 border-t border-[var(--rule-soft)] py-3 first:border-t-0">
                <Avatar name={account.username} />
                <span className="min-w-0 flex-1">
                  <Mono className="block text-[13.5px] font-medium">{account.username}</Mono>
                  <span className="tech">
                    created by {account.created_by} · {formatShort(account.created_at)}
                  </span>
                </span>
                <span className="flex gap-1.5">
                  {account.roles.map((role) => (
                    <Chip key={role} tone={role === 'admin' ? 'navy' : 'soft'} small>
                      {role}
                    </Chip>
                  ))}
                </span>
                <button type="button" className="sm !text-[var(--garnet)]" onClick={() => remove.mutate(account.username)} disabled={remove.isPending} title={`Delete ${account.username}`} aria-label={`Delete ${account.username}`}>
                  <IconTrash size={15} />
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {remove.error ? <p className="mt-2 text-[13px] text-[var(--garnet)]">{remove.error.message}</p> : null}
      </Inner>

      <Inner className="p-5">
        <h2 className="!text-[20px]">Create an account</h2>
        <form
          className="mt-3 flex flex-wrap items-end gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            if (username.trim().length >= 2 && password.length >= 12) create.mutate()
          }}
        >
          <label className="block text-[13px]">
            <span className="lbl">Username</span>
            <input value={username} onChange={(event) => setUsername(event.target.value)} className="field field-pill mono mt-1" placeholder="first.last" />
          </label>
          <label className="block text-[13px]">
            <span className="lbl">Password (12 characters min)</span>
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" className="field field-pill mono mt-1" />
          </label>
          <label className="block text-[13px]">
            <span className="lbl">Roles</span>
            <select value={preset} onChange={(event) => setPreset(event.target.value)} className="field field-pill mt-1">
              {ROLE_PRESETS.map((choice) => (
                <option key={choice.value} value={choice.value}>
                  {choice.label}
                </option>
              ))}
            </select>
          </label>
          <Btn type="submit" disabled={create.isPending || username.trim().length < 2 || password.length < 12}>
            Create account
          </Btn>
          {create.error ? <p className="w-full text-[13px] text-[var(--garnet)]">{create.error.message}</p> : null}
        </form>
      </Inner>
    </>
  )
}
