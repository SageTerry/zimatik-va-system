import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { startWebScan } from '../api/client'
import Card from './Card'
import Button from './Button'
import { ScanIcon } from '../lib/icons'

function isValidTargetUrl(value) {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:'
  } catch {
    return false
  }
}

export default function ScanForm() {
  const navigate = useNavigate()
  const [targetUrl, setTargetUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const urlLooksValid = targetUrl.length === 0 || isValidTargetUrl(targetUrl)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!isValidTargetUrl(targetUrl)) {
      setError('Enter a valid http(s) URL, e.g. https://example.com')
      return
    }
    setError(null)
    setSubmitting(true)
    try {
      const { scan_id: scanId } = await startWebScan(targetUrl)
      navigate(`/scan/progress/${scanId}`)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start scan')
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h1 className="font-display text-display text-ink">New Web App Scan</h1>
        <p className="mt-1 font-body text-ink-2">
          Runs an OWASP ZAP spider + active scan against a target URL and imports the results as findings.
        </p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block font-body text-xs uppercase tracking-wide text-ink-3">
              Target URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              autoComplete="off"
              className={`radius-b w-full border bg-transparent px-3 py-2 font-body text-sm text-ink focus:outline-none ${
                urlLooksValid ? 'border-line-strong focus:border-ink-2' : 'border-severity-high'
              }`}
            />
          </div>

          {error && <p className="font-body text-sm text-severity-high">{error}</p>}

          <Button type="submit" variant="primary" disabled={submitting || !targetUrl}>
            <ScanIcon size={18} />
            {submitting ? 'Starting scan…' : 'Start Scan'}
          </Button>

          <p className="font-body text-xs text-ink-3">
            ZAP scans can take 5-15 minutes against a real target. You&apos;ll be taken to a live progress view once
            the scan starts.
          </p>
        </form>
      </Card>
    </div>
  )
}
