/**
 * Local account login page.
 *
 * No self-registration: accounts are created by an administrator (Configuration screen, or
 * bootstrap script for the first one). The session lives in an httpOnly cookie; the browser
 * stores no readable token.
 */

import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '@/lib/api'

export function LoginScreen({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const login = useMutation({
    mutationFn: () => api.login(username.trim(), password),
    onSuccess: onLoggedIn,
  })

  return (
    <div className="flex min-h-screen items-center justify-center bg-white px-6 py-12">
      <div className="w-full max-w-[400px]">
        <div className="mb-9 flex flex-col items-center text-center">
          <img
            src="/logo_sherlock.jpg"
            alt="SHERLOCK"
            className="mb-6 w-[360px] max-w-full"
          />
          <h1 className="text-xl font-semibold text-ink">Sign in</h1>
          <p className="mt-1 text-[13px] text-slate">Your platform credentials.</p>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault()
            if (username.trim() && password) login.mutate()
          }}
        >
          <label className="label mb-1.5 block" htmlFor="login-user">
            Username
          </label>
          <input
            id="login-user"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            autoFocus
            className="field mb-4 font-mono text-sm"
            placeholder="first.last"
          />

          <label className="label mb-1.5 block" htmlFor="login-password">
            Password
          </label>
          <input
            id="login-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            className="field mb-6 font-mono text-sm"
          />

          {login.error ? (
            <p className="mb-4 text-center text-sm text-garnet">{login.error.message}</p>
          ) : null}

          <button
            type="submit"
            className="btn-primary w-full justify-center"
            disabled={login.isPending || !username.trim() || !password}
          >
            {login.isPending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-6 text-center text-xs leading-relaxed text-slate">
          No account? Access is granted by a platform administrator.
        </p>
      </div>
    </div>
  )
}
