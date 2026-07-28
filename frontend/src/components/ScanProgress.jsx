import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { openScanProgressStream } from '../api/client'
import Card from './Card'
import ProgressBar from './ProgressBar'

const STATUS_LABELS = {
  PENDING: 'Queued…',
  IN_PROGRESS: 'Scanning…',
  COMPLETED: 'Complete!',
  FAILED: 'Scan failed',
}

const TOOL_STATUS_LABELS = {
  spidering: 'Spidering target',
  scanning: 'Running active scan',
  processing: 'Processing findings',
  completed: 'Complete',
  failed: 'Failed',
}

export default function ScanProgress() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [progress, setProgress] = useState(null)
  const [error, setError] = useState(null)
  const redirectedRef = useRef(false)

  useEffect(() => {
    redirectedRef.current = false
    const close = openScanProgressStream(scanId, {
      onMessage: (data) => {
        setProgress(data)
        if (data.status === 'COMPLETED' && !redirectedRef.current) {
          redirectedRef.current = true
          close()
          navigate(`/scan-results/${scanId}`)
        } else if (data.status === 'FAILED') {
          close()
          setError('The scan failed. Check the backend logs for details.')
        }
      },
      onError: () => {
        setError((prev) => prev ?? 'Lost connection to the progress stream.')
      },
    })
    return close
  }, [scanId, navigate])

  const overallProgress = progress?.progress ?? 0
  const status = progress?.status ?? 'PENDING'
  const toolStatuses = progress?.tool_statuses ?? {}

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h1 className="font-display text-display text-ink">Scan in progress</h1>
        <p className="mt-1 font-body text-ink-2">{STATUS_LABELS[status] ?? status}</p>
      </div>

      <Card className="space-y-5">
        <div>
          <div className="mb-1 flex items-center justify-between font-body text-sm text-ink-2">
            <span>Overall progress</span>
            <span className="font-bold text-ink">{overallProgress}%</span>
          </div>
          <ProgressBar value={overallProgress} max={100} severity="info" height={18} />
        </div>

        {Object.entries(toolStatuses).map(([tool, toolStatus]) => (
          <div key={tool} className="flex items-center justify-between font-body text-sm text-ink-2">
            <span className="uppercase">{tool}</span>
            <span>{TOOL_STATUS_LABELS[toolStatus] ?? toolStatus}</span>
          </div>
        ))}

        {error && <p className="font-body text-sm text-severity-high">{error}</p>}
      </Card>
    </div>
  )
}
