import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api/client'
import Card from './Card'
import Button from './Button'
import { ShieldIcon } from '../lib/icons'

export default function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const { access_token: accessToken } = await login(username, password)
      localStorage.setItem('access_token', accessToken)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Login failed')
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-sm flex-col justify-center space-y-6 px-4">
      <div className="flex flex-col items-center gap-3 text-center">
        <span className="radius-b flex h-14 w-14 items-center justify-center bg-navy text-white shadow-card">
          <ShieldIcon size={28} strokeWidth={2} />
        </span>
        <div>
          <h1 className="font-display text-display text-ink">VACE</h1>
          <p className="font-body text-sm text-ink-2">Sign in to continue</p>
        </div>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block font-body text-xs font-semibold uppercase tracking-wide text-ink-3">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              className="radius-b w-full border border-line-strong bg-surface px-3.5 py-2.5 font-body text-sm text-ink transition-colors focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/15"
            />
          </div>

          <div>
            <label className="mb-1 block font-body text-xs font-semibold uppercase tracking-wide text-ink-3">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="radius-b w-full border border-line-strong bg-surface px-3.5 py-2.5 font-body text-sm text-ink transition-colors focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/15"
            />
          </div>

          {error && <p className="font-body text-sm text-severity-high">{error}</p>}

          <Button
            type="submit"
            variant="primary"
            className="w-full justify-center"
            disabled={submitting || !username || !password}
          >
            {submitting ? 'Signing in…' : 'Sign In'}
          </Button>
        </form>
      </Card>
    </div>
  )
}
