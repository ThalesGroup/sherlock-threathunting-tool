/**
 * Application shell: the icon rail on the left (labels appear on hover), the header, and
 * the session gate.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'

import { api, ApiError } from '@/lib/api'

import { isWaiting } from '@/components/format'
import {
  IconAlert,
  IconClock,
  IconDoc,
  IconGear,
  IconGrid,
  IconKey,
  IconLogout,
  IconPlus,
} from '@/components/icons'
import { LoginScreen } from '@/screens/Login'
import { Avatar, Btn } from '@/components/ui'

const RAIL = [
  { to: '/', label: 'Dashboard', icon: IconGrid, end: true, adminOnly: false },
  { to: '/new', label: 'New hunt', icon: IconPlus, end: true, adminOnly: false },
  { to: '/cti', label: 'CTI analysis', icon: IconDoc, end: false, adminOnly: false },
  { to: '/history', label: 'History', icon: IconClock, end: false, adminOnly: false },
  { to: '/configuration', label: 'Configuration', icon: IconGear, end: false, adminOnly: true },
]


export function AppShell() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const session = useQuery({ queryKey: ['session'], queryFn: api.me, retry: false })
  const config = useQuery({ queryKey: ['config'], queryFn: api.config, enabled: Boolean(session.data) })
  const hunts = useQuery({
    queryKey: ['hunts', { limit: 100 }],
    queryFn: () => api.listHunts({ limit: 100 }),
    enabled: Boolean(session.data),
  })

  const logout = useMutation({ mutationFn: api.logout, onSuccess: () => queryClient.clear() })
  const [menuOpen, setMenuOpen] = useState(false)

  if (session.isLoading) {
    return (
      <div className="app flex min-h-screen items-center justify-center">
        <p className="muted">Loading…</p>
      </div>
    )
  }

  if (!session.data) {
    return (
      <LoginScreen onLoggedIn={() => void queryClient.invalidateQueries({ queryKey: ['session'] })} />
    )
  }

  const isAdmin = session.data.roles.includes('admin')
  const rail = RAIL.filter((item) => !item.adminOnly || isAdmin)
  const activeSources = config.data?.sources.filter((source) => source.configured).length ?? 0
  const waiting = (hunts.data ?? []).filter(isWaiting).length

  return (
    <div className="app flex min-h-screen">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-full focus:bg-white focus:px-4 focus:py-2"
      >
        Skip to content
      </a>

      {/* Spacer keeping the page clear of the resting rail; the rail itself is an overlay
          and expands over the page, never pushing it. */}
      <div className="w-[100px] flex-none" aria-hidden="true" />
      <div className="rail-backdrop" aria-hidden="true" />
      <aside className={`rail fixed left-0 top-0 z-30 flex h-screen flex-col py-6 ${menuOpen ? 'menu-open' : ''}`} aria-label="Main navigation">
        <nav className="flex flex-col gap-2">
          {rail.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => `ri ${isActive ? 'on' : ''}`}>
              {({ isActive }) => (
                <>
                  <span className={`ic ${isActive ? 'on' : ''}`}>
                    <item.icon size={20} />
                  </span>
                  <span className="rl">{item.label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-2">
          <Link to="/history?filter=waiting" className="ri" title={`${waiting} hunt(s) waiting for a human`}>
            <span className="ic relative">
              <IconAlert size={20} />
              {waiting > 0 ? (
                <span
                  className="absolute right-2.5 top-2.5 h-2.5 w-2.5 rounded-full border-2 border-white"
                  style={{ background: 'var(--amber)' }}
                  aria-hidden="true"
                />
              ) : null}
            </span>
            <span className="rl">Alerts · {waiting}</span>
          </Link>
          <button type="button" className="ri" onClick={() => logout.mutate()} disabled={logout.isPending} title="Sign out">
            <span className="ic">
              <IconLogout size={20} />
            </span>
            <span className="rl">Sign out</span>
          </button>
          <UserMenu
            name={session.data.name}
            roles={session.data.roles}
            open={menuOpen}
            onToggle={setMenuOpen}
          />
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col px-6 pb-16 xl:px-8">
        <header className="flex h-[104px] flex-none items-center justify-between gap-6">
          <Link to="/" className="flex items-center gap-3 no-underline hover:no-underline">
            <img src="/logo_sherlock_mark.png" alt="" aria-hidden="true" className="h-12 w-12 object-contain" />
            <img src="/logo_sherlock_word.png" alt="SHERLOCK" className="mt-2 h-9 w-auto object-contain" />
          </Link>

          <div className="flex items-center gap-3">
            <span className="chip hidden md:inline-flex" title="Configured SIEM sources">
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: activeSources > 0 ? 'var(--mint)' : 'var(--meta)' }}
                aria-hidden="true"
              />
              {activeSources} active source{activeSources === 1 ? '' : 's'}
            </span>
            <Btn onClick={() => navigate('/new')} size="sm" className="!h-12 !rounded-full !px-5">
              <IconPlus size={18} />
              New hunt
            </Btn>
          </div>
        </header>

        <main id="content" className="min-w-0 flex-1">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

function UserMenu({
  name,
  roles,
  open,
  onToggle,
}: {
  name: string
  roles: string[]
  open: boolean
  onToggle: (open: boolean) => void
}) {
  const setOpen = onToggle
  const ref = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent) => {
      const target = event.target as Node
      if (ref.current?.contains(target) || menuRef.current?.contains(target)) return
      setOpen(false)
    }
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', escape)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', escape)
    }
  }, [open, setOpen])

  return (
    <div ref={ref} className="relative">
      <button type="button" className="ri" onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="dialog">
        <span className="ic on">
          <Avatar name={name} className="!h-full !w-full !bg-transparent" />
        </span>
        <span className="rl">
          {name} · {roles.join(', ')}
        </span>
      </button>
      {/* Rendered outside the rail: its blur filter would otherwise clip a fixed child. */}
      {open
        ? createPortal(
            <div ref={menuRef} className="app rail-menu" role="dialog" aria-label="Account">
          <div className="flex items-center gap-3">
            <Avatar name={name} />
            <div className="min-w-0">
              <div className="truncate font-semibold">{name}</div>
              <div className="tech">{roles.join(', ')}</div>
            </div>
          </div>
          <PasswordChange />
            </div>,
            document.body,
          )
        : null}
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
      <div className="mt-3">
        <button
          type="button"
          className="flex items-center gap-2 py-1.5 text-[13.5px] hover:underline"
          onClick={() => {
            setOpen(true)
            setDone(false)
          }}
        >
          <IconKey size={16} /> Change my password
        </button>
        {done ? <p className="text-[12.5px] text-[var(--mint)]">Password changed.</p> : null}
      </div>
    )
  }

  return (
    <form
      className="mt-3 space-y-2"
      onSubmit={(event) => {
        event.preventDefault()
        if (current && next.length >= 12 && next === confirm) change.mutate()
      }}
    >
      <input type="password" value={current} onChange={(event) => setCurrent(event.target.value)} placeholder="Current password" autoComplete="current-password" className="field !py-2.5 text-[13px]" />
      <input type="password" value={next} onChange={(event) => setNext(event.target.value)} placeholder="New (12 characters min)" autoComplete="new-password" className="field !py-2.5 text-[13px]" />
      <input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} placeholder="Confirm" autoComplete="new-password" className="field !py-2.5 text-[13px]" />
      {mismatch ? <p className="text-[12.5px] text-[var(--amber)]">The two entries differ.</p> : null}
      {change.error ? (
        <p className="text-[12.5px] text-[var(--garnet)]">
          {change.error instanceof ApiError ? change.error.message : 'Change failed.'}
        </p>
      ) : null}
      <div className="flex gap-2">
        <Btn type="submit" size="xs" disabled={change.isPending || !current || next.length < 12 || next !== confirm}>
          {change.isPending ? 'Changing…' : 'Save'}
        </Btn>
        <Btn variant="light" size="xs" onClick={() => setOpen(false)}>
          Cancel
        </Btn>
      </div>
    </form>
  )
}
