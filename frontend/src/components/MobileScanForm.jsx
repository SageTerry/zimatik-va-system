import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { startMobileScan } from '../api/client'
import Card from './Card'
import Button from './Button'
import { ScanIcon, UploadIcon } from '../lib/icons'

function extractErrorMessage(err) {
  const detail = err.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || String(item)).join('; ')
  }
  return detail || err.message || 'Failed to start scan'
}

export default function MobileScanForm() {
  const navigate = useNavigate()
  const fileInputRef = useRef(null)
  const [file, setFile] = useState(null)
  const [appName, setAppName] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  function pickFile(candidate) {
    if (!candidate) return
    if (!candidate.name.toLowerCase().endsWith('.apk')) {
      setError('Only .apk files are supported.')
      return
    }
    setError(null)
    setFile(candidate)
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragActive(false)
    pickFile(e.dataTransfer.files?.[0])
  }

  function handleDragOver(e) {
    e.preventDefault()
    setDragActive(true)
  }

  function handleDragLeave(e) {
    e.preventDefault()
    setDragActive(false)
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!file) {
      setError('Choose an APK file to scan.')
      return
    }
    if (!appName.trim()) {
      setError('Enter an app name.')
      return
    }
    setError(null)
    setSubmitting(true)
    try {
      const { scan_id: scanId } = await startMobileScan(file, appName.trim())
      navigate(`/scan/progress/${scanId}`)
    } catch (err) {
      setError(extractErrorMessage(err))
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h1 className="font-display text-display text-ink">New Mobile App Scan</h1>
        <p className="mt-1 font-body text-ink-2">
          Runs a MobSF static analysis against an uploaded APK and imports the results as findings.
        </p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block font-body text-xs uppercase tracking-wide text-ink-3">App name</label>
            <input
              type="text"
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
              placeholder="e.g. My Banking App v2.3"
              autoComplete="off"
              className="radius-b w-full border border-line-strong bg-transparent px-3 py-2 font-body text-sm text-ink focus:border-ink-2 focus:outline-none"
            />
          </div>

          <div>
            <label className="mb-1 block font-body text-xs uppercase tracking-wide text-ink-3">APK file</label>
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click()
              }}
              className={`radius-b flex cursor-pointer flex-col items-center justify-center gap-2 border border-dashed px-4 py-8 text-center transition-colors ${
                dragActive ? 'border-ink bg-sunken' : 'border-line-strong hover:bg-sunken/60'
              }`}
            >
              <UploadIcon size={24} className="text-ink-2" />
              {file ? (
                <p className="font-body text-sm text-ink">{file.name}</p>
              ) : (
                <>
                  <p className="font-body text-sm text-ink-2">Drag and drop an APK here, or click to browse</p>
                  <p className="font-body text-xs text-ink-3">.apk files only</p>
                </>
              )}
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk"
                className="hidden"
                onChange={(e) => pickFile(e.target.files?.[0])}
              />
            </div>
          </div>

          {error && <p className="font-body text-sm text-severity-high">{error}</p>}

          <Button type="submit" variant="primary" disabled={submitting || !file || !appName.trim()}>
            <ScanIcon size={18} />
            {submitting ? 'Starting scan…' : 'Start Scan'}
          </Button>

          <p className="font-body text-xs text-ink-3">
            MobSF static analysis usually takes a few minutes. You&apos;ll be taken to a live progress view once the
            scan starts.
          </p>
        </form>
      </Card>
    </div>
  )
}
