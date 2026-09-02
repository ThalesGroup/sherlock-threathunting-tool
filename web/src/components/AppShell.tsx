import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'

import { api, ApiError } from '@/lib/api'
import { LoginScreen } from '@/screens/Login'

const NAV = [
  { to: '/dashboard', label: 'Dashboard', end: false, adminOnly: false },
  { to: '/', label: 'New hunt', end: true, adminOnly: false },
  { to: '/cti', label: 'CTI analysis', end: false, adminOnly: false },
  { to: '/history', label: 'History', end: false, adminOnly: false },
  { to: '/configuration', label: 'Configuration', end: false, adminOnly: true },
]

const CRUMBS: [string, string, string][] = [
  ['/dashboard', 'Dashboard', 'CONSOLIDATED VIEW'],
  ['/cti', 'CTI analysis', 'IMPORTED REPORTS'],
  ['/history', 'History and audit', 'FULL LOG'],
  ['/configuration', 'Configuration', 'ADMIN'],
  ['/hunts', 'Investigation', ''],
  ['/', 'New hunt', 'DRAFT'],
]

function crumbFor(pathname: string): [string, string] {
  for (const [prefix, label, meta] of CRUMBS) {
    if (prefix === '/' ? pathname === '/' : pathname.startsWith(prefix)) {
      const huntId = pathname.startsWith('/hunts/') ? pathname.split('/')[2] : ''
      return [label, huntId ? huntId.toUpperCase() : meta]
    }
  }
  return ['Threat hunting', '']
}

export function AppShell() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const location = useLocation()
  const session = useQuery({ queryKey: ['session'], queryFn: api.me, retry: false })
  const config = useQuery({
    queryKey: ['config'],
    queryFn: api.config,
    enabled: Boolean(session.data),
  })

  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: () => queryClient.clear(),
  })

  if (session.isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-paper">
        <p className="meta-text">Loading…</p>
      </div>
    )
  }

  if (!session.data) {
    return (
      <LoginScreen
        onLoggedIn={() => void queryClient.invalidateQueries({ queryKey: ['session'] })}
      />
    )
  }

  const isAdmin = session.data.roles.includes('admin')
  const nav = NAV.filter((item) => !item.adminOnly || isAdmin)
  const activeSources = config.data?.sources.filter((source) => source.configured).length ?? 0
  const [crumb, crumbMeta] = crumbFor(location.pathname)

  return (
    <div className="flex min-h-screen">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50
          focus:rounded focus:bg-white focus:px-4 focus:py-2"
      >
        Skip to content
      </a>

      <aside className="sticky top-0 flex h-screen w-[228px] flex-none flex-col bg-navy text-white">
        <div className="border-b border-[#1c3350] px-5 pb-5 pt-6">
          <div className="flex items-center gap-2.5">
            <div className="h-[11px] w-[11px] rounded-[3px] bg-accent" aria-hidden="true" />
            <span className="text-[15px] font-semibold tracking-tight">Threat hunting</span>
          </div>
          <div className="mt-2 pl-[21px] font-mono text-[10px] tracking-[0.16em] text-[#5f7791]">
            INTERNAL SOC
          </div>
        </div>

        <nav className="flex-1 py-3.5" aria-label="Main navigation">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `mr-3 flex items-center gap-2.5 rounded-r-btn py-2.5 pr-3 text-[13px]
                transition-colors ${
                  isActive
                    ? 'bg-navy-active font-medium text-white'
                    : 'text-[#9fb3c7] hover:text-white'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <span
                    className={`h-4 w-[3px] flex-none rounded-r-[3px] ${
                      isActive ? 'bg-accent' : 'bg-transparent'
                    }`}
                    aria-hidden="true"
                  />
                  {item.label}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-[#1c3350] px-5 py-4 font-mono text-[11px] leading-relaxed text-[#5f7791]">
          <div className="font-medium text-[#c6d4e1]">{session.data.name}</div>
          <div>{session.data.roles.join(', ')}</div>
          <PasswordChange />
          <button
            type="button"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
            className="mt-2.5 text-accent hover:underline"
          >
            sign out →
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-[52px] flex-none items-center justify-between border-b border-rule bg-white px-6">
          <div className="flex items-baseline gap-2.5">
            <span className="text-[13px] font-medium text-ink">{crumb}</span>
            {crumbMeta ? <span className="meta-mono">{crumbMeta}</span> : null}
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-full border border-[#dfe5ea] bg-soft-bg px-3 py-1.5">
              <span
                className={`h-[7px] w-[7px] rounded-full ${
                  activeSources > 0 ? 'bg-[#1f8a5f]' : 'bg-meta'
                }`}
                aria-hidden="true"
              />
              <span className="font-mono text-[11px] text-[#4a5a68]">
                {activeSources} active source{activeSources > 1 ? 's' : ''}
              </span>
            </div>
            <button
              type="button"
              className="rounded-btn bg-navy px-3.5 py-2 text-xs font-medium text-white
                transition-colors hover:bg-navy-hover"
              onClick={() => navigate('/')}
            >
              New hunt
            </button>
          </div>
        </header>

        <main id="content" className="flex-1 px-6 pb-16 pt-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}


function PasswordChange() {
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)

  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: () => {
      setDone(true)
      setOpen(false)
      setCurrent('')
      setNext('')
      setConfirm('')
    },
  })

  const mismatch = confirm.length > 0 && next !== confirm

  if (!open) {
    return (
      <div className="mt-2.5">
        <button
          type="button"
          className="text-[#9fb3c7] hover:text-white hover:underline"
          onClick={() => {
            setOpen(true)
            setDone(false)
          }}
        >
          change my password
        </button>
        {done ? <div className="mt-1 text-mint">Password changed.</div> : null}
      </div>
    )
  }

  return (
    <form
      className="mt-2.5 space-y-1.5"
      onSubmit={(event) => {
        event.preventDefault()
        if (current && next.length >= 12 && next === confirm) change.mutate()
      }}
    >
      <input
        type="password"
        value={current}
        onChange={(event) => setCurrent(event.target.value)}
        placeholder="Current password"
        autoComplete="current-password"
        className="w-full rounded border border-[#2a4260] bg-navy-active px-2 py-1.5 text-white placeholder:text-[#5f7791]"
      />
      <input
        type="password"
        value={next}
        onChange={(event) => setNext(event.target.value)}
        placeholder="New (12 characters min)"
        autoComplete="new-password"
        className="w-full rounded border border-[#2a4260] bg-navy-active px-2 py-1.5 text-white placeholder:text-[#5f7791]"
      />
      <input
        type="password"
        value={confirm}
        onChange={(event) => setConfirm(event.target.value)}
        placeholder="Confirm"
        autoComplete="new-password"
        className="w-full rounded border border-[#2a4260] bg-navy-active px-2 py-1.5 text-white placeholder:text-[#5f7791]"
      />
      {mismatch ? <div className="text-amber">The two entries differ.</div> : null}
      {change.error ? (
        <div className="text-[#e08a8a]">
          {change.error instanceof ApiError ? change.error.message : 'Change failed.'}
        </div>
      ) : null}
      <div className="flex gap-3">
        <button
          type="submit"
          className="text-accent hover:underline"
          disabled={change.isPending || !current || next.length < 12 || next !== confirm}
        >
          {change.isPending ? 'Changing…' : 'save'}
        </button>
        <button
          type="button"
          className="text-[#9fb3c7] hover:underline"
          onClick={() => setOpen(false)}
        >
          cancel
        </button>
      </div>
    </form>
  )
}
