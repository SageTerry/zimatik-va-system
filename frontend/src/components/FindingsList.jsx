import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getScans } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Badge from './Badge'
import { ChevronRightIcon } from '../lib/icons'
import { SEVERITY_BADGE, SEVERITY_ORDER, TOOL_OPTIONS } from '../lib/constants'

const SELECT_CLASSES =
  'radius-b border border-line-strong bg-surface px-3 py-2 font-body text-sm text-ink transition-colors focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/15'

// Maps a Scan's status onto a Badge `severity` variant - reusing the same
// palette as finding severities/remediation status rather than a third one.
const SCAN_STATUS_BADGE = {
  PENDING: 'low',
  IN_PROGRESS: 'medium',
  COMPLETED: 'resolved',
  FAILED: 'high',
}

function scanDate(scan) {
  return scan.started_at || scan.created_at
}

export default function FindingsList() {
  const navigate = useNavigate()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('')
  const [toolFilter, setToolFilter] = useState('')

  // Guards against an older, slower request overwriting a newer one if this
  // ever gets a manual refresh button in the future.
  const requestIdRef = useRef(0)

  const runFetch = useCallback(() => {
    const requestId = ++requestIdRef.current
    setLoading(true)
    setError(null)
    getScans()
      .then((data) => {
        if (requestId !== requestIdRef.current) return
        setScans(data)
      })
      .catch((err) => {
        if (requestId !== requestIdRef.current) return
        setError(err.message || 'Failed to load scans')
      })
      .finally(() => {
        if (requestId === requestIdRef.current) setLoading(false)
      })
  }, [])

  useEffect(() => {
    runFetch()
  }, [runFetch])

  const filteredScans = scans
    .filter((scan) => !severityFilter || (scan.findings_by_severity[severityFilter] ?? 0) > 0)
    .filter((scan) => !toolFilter || scan.tool_sources?.[toolFilter.toLowerCase()])
    .sort((a, b) => new Date(scanDate(b)).getTime() - new Date(scanDate(a)).getTime())

  const totalFindings = scans.reduce((sum, scan) => sum + scan.total_findings, 0)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-display text-ink">Findings</h1>
          <p className="mt-1 font-body text-ink-2">
            {totalFindings} total finding{totalFindings === 1 ? '' : 's'} across {scans.length} scan
            {scans.length === 1 ? '' : 's'}
          </p>
        </div>

        <div className="flex flex-wrap items-start gap-3">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className={SELECT_CLASSES}
          >
            <option value="">All severities</option>
            {SEVERITY_ORDER.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>

          <select value={toolFilter} onChange={(e) => setToolFilter(e.target.value)} className={SELECT_CLASSES}>
            <option value="">All tools</option>
            {TOOL_OPTIONS.map((tool) => (
              <option key={tool} value={tool}>
                {tool}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="radius-a border border-severity-high p-4 font-body text-severity-high">
          Failed to load scans: {error}
        </div>
      )}

      <div className="space-y-3">
        {loading ? (
          <div className="radius-a border border-line bg-surface p-10 text-center font-body text-ink-3 shadow-card">
            Loading scans…
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="radius-a border border-line bg-surface p-10 text-center font-body text-ink-3 shadow-card">
            No scans match these filters.
          </div>
        ) : (
          filteredScans.map((scan) => {
            const date = scanDate(scan)
            return (
              <div
                key={scan.id}
                onClick={() => navigate(`/reports/${scan.id}`)}
                className="radius-a flex cursor-pointer items-center justify-between gap-4 border border-line bg-surface p-5 shadow-card transition-colors hover:bg-sunken"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate font-display text-heading text-ink">{scan.name}</h2>
                    <Badge severity={SCAN_STATUS_BADGE[scan.status] ?? 'info'}>{scan.status.replace(/_/g, ' ')}</Badge>
                  </div>
                  <p className="mt-1 truncate font-body text-sm text-ink-2">{scan.scope}</p>
                  <p className="mt-1 font-body text-xs text-ink-3">
                    {date ? new Date(date).toLocaleString() : '—'} · {scan.total_findings} finding
                    {scan.total_findings === 1 ? '' : 's'}
                  </p>

                  <div className="mt-3 flex flex-wrap gap-2">
                    {SEVERITY_ORDER.filter((severity) => scan.findings_by_severity[severity]).map((severity) => (
                      <Badge key={severity} severity={SEVERITY_BADGE[severity] ?? 'info'}>
                        {scan.findings_by_severity[severity]} {severity}
                      </Badge>
                    ))}
                    {scan.total_findings === 0 && <span className="font-body text-xs text-ink-3">No findings</span>}
                  </div>
                </div>

                <div className="flex flex-shrink-0 items-center gap-3" onClick={(e) => e.stopPropagation()}>
                  <ReportDownloadButton
                    label="Download Report"
                    getPayload={() => (scan.total_findings ? { scan_id: scan.id } : null)}
                  />
                  <ChevronRightIcon className="text-ink-3" size={20} strokeWidth={2} />
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
