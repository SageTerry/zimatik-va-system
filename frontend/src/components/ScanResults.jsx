import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getFindings, getScan } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Card from './Card'
import Badge from './Badge'
import { REMEDIATION_STATUS_BADGE, SEVERITY_BADGE } from '../lib/constants'

export default function ScanResults() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([getScan(scanId), getFindings({ scan_id: scanId, page: 1, page_size: 200 })])
      .then(([scanData, findingsData]) => {
        if (cancelled) return
        setScan(scanData)
        setFindings(findingsData.items)
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.detail || err.message || 'Failed to load scan results')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  if (loading) {
    return <div className="flex h-64 items-center justify-center font-body text-ink-2">Loading scan results…</div>
  }

  if (error) {
    return <Card className="border-severity-high text-severity-high">{error}</Card>
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-display text-ink">{scan.name}</h1>
          <p className="mt-1 font-body text-ink-2">
            {scan.scope} · {scan.total_findings} finding{scan.total_findings === 1 ? '' : 's'}
          </p>
          {findings.length < scan.total_findings && (
            <p className="mt-1 font-body text-xs text-ink-3">
              Showing the first {findings.length} of {scan.total_findings} findings.
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-start gap-3">
          <Link
            to={`/reports/${scanId}`}
            className="radius-b inline-flex items-center gap-2 border border-line-strong bg-transparent px-4 py-2 font-body text-sm text-ink transition-colors hover:bg-sunken"
          >
            View Executive Report
          </Link>
          <ReportDownloadButton label="Download Technical Report" getPayload={() => ({ scan_id: scanId })} />
        </div>
      </div>

      <div className="radius-a overflow-x-auto border border-line">
        <table className="min-w-full divide-y divide-line">
          <thead>
            <tr>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Title</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Severity</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">URL</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-10 text-center font-body text-ink-3">
                  No findings from this scan.
                </td>
              </tr>
            ) : (
              findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="max-w-xs truncate px-4 py-3 font-body text-sm text-ink">
                    <Link to={`/findings/${finding.id}`} className="hover:underline">
                      {finding.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <Badge severity={SEVERITY_BADGE[finding.severity_normalized] ?? 'info'}>
                      {finding.severity_normalized}
                    </Badge>
                  </td>
                  <td className="max-w-xs truncate px-4 py-3 font-body text-sm text-ink-2">{finding.url || '—'}</td>
                  <td className="px-4 py-3 text-sm">
                    <Badge severity={REMEDIATION_STATUS_BADGE[finding.remediation_status] ?? 'info'}>
                      {finding.remediation_status.replace(/_/g, ' ')}
                    </Badge>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
