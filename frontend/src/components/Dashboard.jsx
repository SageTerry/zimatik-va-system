import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getFindings, getStats } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Card from './Card'
import StatCard from './StatCard'
import Badge from './Badge'
import ProgressBar from './ProgressBar'
import { SEVERITY_BADGE, SEVERITY_ORDER, THREAT_STATUS_BADGE, THREAT_STATUS_LABEL } from '../lib/constants'
import { ChevronRightIcon, FlameIcon, RadarIcon, TargetIcon, WarnCircleIcon } from '../lib/icons'

// The report endpoint takes explicit finding_ids rather than "everything" -
// this pulls the first page at the API's max page size, which comfortably
// covers this portfolio project's dataset size.
const REPORT_FINDING_LIMIT = 200
const RECENT_FINDINGS_LIMIT = 5

// Fetched sorted ACTIVELY_EXPLOITED-first (see the backend's sort=threat_status
// case), then filtered down to the top 5 non-UNKNOWN findings client-side.
// A small margin over 5 covers scans where the very top rows tie on
// threat_status and sort second by recency.
const THREAT_WIDGET_FETCH_LIMIT = 10
const THREAT_WIDGET_DISPLAY_LIMIT = 5

async function getAllFindingIdsForReport() {
  const data = await getFindings({ page: 1, page_size: REPORT_FINDING_LIMIT })
  return data.items.length ? { finding_ids: data.items.map((f) => f.id) } : null
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [recentFindings, setRecentFindings] = useState([])
  const [exploitedCount, setExploitedCount] = useState(0)
  const [threatFindings, setThreatFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [threatLoading, setThreatLoading] = useState(true)
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

    // Kept as its own request/loading state rather than folded into the
    // Promise.all above - threat intel is enrichment metadata layered on top
    // of the core findings data, so a slow CISA/NVD-backed query here
    // shouldn't hold up the rest of the dashboard from rendering.
    Promise.all([
      getFindings({ threat_status: 'ACTIVELY_EXPLOITED', page: 1, page_size: 1 }),
      getFindings({ sort: 'threat_status', page: 1, page_size: THREAT_WIDGET_FETCH_LIMIT }),
    ])
      .then(([exploitedData, sortedData]) => {
        if (cancelled) return
        setExploitedCount(exploitedData.total)
        setThreatFindings(
          sortedData.items.filter((f) => f.threat_status !== 'UNKNOWN').slice(0, THREAT_WIDGET_DISPLAY_LIMIT),
        )
      })
      .catch(() => {
        // Non-fatal: the rest of the dashboard is still useful without the
        // threat-intel widget, so this failure is silent rather than
        // blocking the page behind `error`.
      })
      .finally(() => {
        if (!cancelled) setThreatLoading(false)
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

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total Findings" value={stats.total_findings} icon={TargetIcon} />
        <StatCard label="Affected Hosts" value={stats.affected_hosts} icon={RadarIcon} />
        <StatCard
          label="Critical + High"
          value={(stats.by_severity?.CRITICAL ?? 0) + (stats.by_severity?.HIGH ?? 0)}
          icon={WarnCircleIcon}
          accentClassName="text-severity-high"
        />
        <StatCard
          label="Actively Exploited"
          value={threatLoading ? '…' : exploitedCount}
          icon={FlameIcon}
          accentClassName="text-red-700"
          as={Link}
          to="/findings?threat_status=ACTIVELY_EXPLOITED"
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
            className="mt-4 inline-flex items-center gap-1 font-body text-sm font-semibold text-brand transition-colors hover:text-brand-dark"
          >
            View all findings
            <ChevronRightIcon size={16} strokeWidth={2.5} />
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

      <Card>
        <div className="mb-4 flex items-center justify-between gap-4">
          <h2 className="font-display text-heading text-ink">Threat Intelligence</h2>
          <Link
            to="/findings?threat_status=ACTIVELY_EXPLOITED"
            className="inline-flex items-center gap-1 font-body text-sm font-semibold text-brand transition-colors hover:text-brand-dark"
          >
            View exploited findings
            <ChevronRightIcon size={16} strokeWidth={2.5} />
          </Link>
        </div>
        {threatLoading ? (
          <p className="font-body text-ink-3">Loading threat intelligence…</p>
        ) : threatFindings.length === 0 ? (
          <p className="font-body text-ink-3">No CVE-linked findings have been enriched yet.</p>
        ) : (
          <ul className="divide-y divide-line">
            {threatFindings.map((finding) => (
              <li key={finding.id}>
                <Link
                  to={`/findings/${finding.id}`}
                  className="flex items-center justify-between gap-4 py-3 transition-colors hover:bg-sunken"
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-body text-sm font-semibold text-ink">
                      {finding.cve_id ?? '—'}
                    </p>
                    <p className="truncate font-body text-sm text-ink-2">{finding.title}</p>
                  </div>
                  <div className="flex flex-shrink-0 items-center gap-3">
                    {finding.cvss_v3 != null && (
                      <span className="font-body text-xs text-ink-3">CVSS {finding.cvss_v3.toFixed(1)}</span>
                    )}
                    <Badge severity={THREAT_STATUS_BADGE[finding.threat_status] ?? 'unknown'}>
                      {THREAT_STATUS_LABEL[finding.threat_status] ?? finding.threat_status}
                    </Badge>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
