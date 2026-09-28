/**
 * Sign-in. One centered glass card: the logo, two
 * fields, one button. Same contract: local accounts created by an administrator, session
 * in an httpOnly cookie, nothing readable stored in the browser.
 */

import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '@/lib/api'

import { IconArrowRight, IconEye, IconEyeOff } from '@/components/icons'
import { Btn } from '@/components/ui'

export function LoginScreen({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [reveal, setReveal] = useState(false)

  const login = useMutation({
    mutationFn: () => api.login(username.trim(), password),
    onSuccess: onLoggedIn,
  })

  return (
    <div className="app flex min-h-screen flex-col px-6 py-6">
      <main className="flex flex-1 flex-col items-center justify-center py-10">
        <img src="/logo_sherlock.png" alt="SHERLOCK" className="mb-6 w-[400px] max-w-full" />
        <form
          className="glass w-full max-w-[440px] p-9"
          onSubmit={(event) => {
            event.preventDefault()
            if (username.trim() && password) login.mutate()
          }}
        >
          <div className="text-center">
            <h1 className="!text-[26px]">Sign in</h1>
            <p className="mt-1 text-[14px] text-[var(--slate)]">Your platform credentials.</p>
          </div>

          <label className="lbl mt-7 block" htmlFor="login-user">
            Username
          </label>
          <input
            id="login-user"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            autoFocus
            className="field field-pill mono mt-2 text-[14px]"
            placeholder="first.last"
          />

          <label className="lbl mt-4 block" htmlFor="login-password">
            Password
          </label>
          <div className="relative mt-2">
            <input
              id="login-password"
              type={reveal ? 'text' : 'password'}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              className="field field-pill mono pr-14 text-[14px]"
            />
            <button
              type="button"
              className="sm absolute right-1 top-1 !h-10 !w-10"
              onClick={() => setReveal((value) => !value)}
              aria-label={reveal ? 'Hide the password' : 'Show the password'}
            >
              {reveal ? <IconEyeOff size={18} /> : <IconEye size={18} />}
            </button>
          </div>

          {login.error ? (
            <p className="mt-4 text-center text-[13.5px] text-[var(--garnet)]" role="alert">
              {login.error.message}
            </p>
          ) : null}

          <Btn type="submit" className="mt-6 w-full" disabled={login.isPending || !username.trim() || !password}>
            {login.isPending ? 'Signing in…' : 'Sign in'}
            <IconArrowRight size={18} />
          </Btn>

          <p className="mt-5 text-center text-[12.5px] leading-relaxed text-[var(--slate)]">
            No account? Access is granted by a platform administrator.
          </p>
        </form>
      </main>

      <footer className="tech flex flex-wrap items-center justify-between gap-2">
        <span>SHERLOCK · Threat Hunting</span>
        <span>read-only connectors · results minimized and pseudonymized</span>
      </footer>
    </div>
  )
}
