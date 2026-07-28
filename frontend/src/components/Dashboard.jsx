import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getFindings, getStats } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Card from './Card'
import StatCard from './StatCard'
import Badge from './Badge'
import ProgressBar from './ProgressBar'
import { SEVERITY_BADGE, SEVERITY_ORDER } from '../lib/constants'
import { RadarIcon, TargetIcon, WarnCircleIcon } from '../lib/icons'

// The report endpoint takes explicit finding_ids rather than "everything" -
// this pulls the first page at the API's max page size, which comfortably
// covers this portfolio project's dataset size.
const REPORT_FINDING_LIMIT = 200
const RECENT_FINDINGS_LIMIT = 5

async function getAllFindingIdsForReport() {
  const data = await getFindings({ page: 1, page_size: REPORT_FINDING_LIMIT })
  return data.items.length ? { finding_ids: data.items.map((f) => f.id) } : null
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [recentFindings, setRecentFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    Promise.all([getStats(), getFindings({ page: 1, page_size: RECENT_FINDINGS_LIMIT })])
      .then(([statsData, findingsData]) => {
        if (cancelled) return
        setStats(statsData)
        setRecentFindings(findingsData.items)
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Failed to load stats')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <div className="flex h-64 items-center justify-center font-body text-ink-2">Loading dashboard…</div>
  }

  if (error) {
    return (
      <Card className="border-severity-high text-severity-high">Failed to load stats: {error}</Card>
    )
  }

  const totalForBars = stats.total_findings || 1

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-display text-ink">Security overview</h1>
          <p className="mt-1 font-body text-ink-2">
            Consolidated vulnerability posture across all connected scanners.
          </p>
        </div>
        <ReportDownloadButton label="Download Technical Report" getPayload={getAllFindingIdsForReport} />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Findings" value={stats.total_findings} icon={TargetIcon} />
        <StatCard label="Affected Hosts" value={stats.affected_hosts} icon={RadarIcon} />
        <StatCard
          label="Critical + High"
          value={(stats.by_severity?.CRITICAL ?? 0) + (stats.by_severity?.HIGH ?? 0)}
          icon={WarnCircleIcon}
          accentClassName="text-severity-high"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <h2 className="mb-4 font-display text-heading text-ink">Recent findings</h2>
          {recentFindings.length === 0 ? (
            <p className="font-body text-ink-3">No findings recorded yet.</p>
          ) : (
            <ul className="divide-y divide-line">
              {recentFindings.map((finding) => (
                <li key={finding.id}>
                  <Link
                    to={`/findings/${finding.id}`}
                    className="flex items-center justify-between gap-4 py-3 transition-colors hover:bg-sunken"
                  >
                    <span className="truncate font-body text-ink">{finding.title}</span>
                    <Badge severity={SEVERITY_BADGE[finding.severity_normalized] ?? 'info'}>
                      {finding.severity_normalized}
                    </Badge>
                  </Link>
                </li>
              ))}
            </ul>
          )}
          <Link
            to="/findings"
            className="mt-4 inline-flex items-center gap-1 font-body text-ink-2 underline decoration-line-strong underline-offset-4 hover:text-ink"
          >
            View all findings →
          </Link>
        </Card>

        <Card>
          <h2 className="mb-4 font-display text-heading text-ink">Open by severity</h2>
          <ul className="space-y-4">
            {SEVERITY_ORDER.map((severity) => {
              const count = stats.by_severity?.[severity] ?? 0
              return (
                <li key={severity}>
                  <div className="mb-1 flex items-center justify-between font-body text-sm text-ink-2">
                    <span>{severity}</span>
                    <span className="font-bold text-ink">{count}</span>
                  </div>
                  <ProgressBar
                    value={count}
                    max={totalForBars}
                    severity={SEVERITY_BADGE[severity] ?? 'info'}
                  />
                </li>
              )
            })}
          </ul>
        </Card>
      </div>
    </div>
  )
}
