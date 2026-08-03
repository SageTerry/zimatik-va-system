import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getExecutiveReport, updateFindingStatus } from '../api/client'
import Card from './Card'
import StatCard from './StatCard'
import Badge from './Badge'
import {
  REMEDIATION_STATUS_BADGE,
  REMEDIATION_STATUS_OPTIONS,
  REMEDIATION_STATUS_SELECT_CLASSES,
  SEVERITY_BADGE,
  SEVERITY_ORDER,
} from '../lib/constants'
import { ChevronLeftIcon, TargetIcon, WarnCircleIcon, CheckCircleIcon } from '../lib/icons'

function extractErrorMessage(err) {
  const detail = err.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || String(item)).join('; ')
  }
  return detail || err.message || 'Failed to update status'
}

// Mirrors the `severity` color tokens in tailwind.config.js. Recharts fills
// are plain SVG attributes, so they need real hex values rather than
// Tailwind classes.
const SEVERITY_HEX = {
  critical: '#B91424',
  high: '#D91C1C',
  medium: '#D97706',
  low: '#64748B',
  resolved: '#15803D',
  info: '#1857A4',
}

const STATUS_ORDER = ['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE', 'WONT_FIX']

// Statuses that count as "handled" for the remediation-rate summary card -
// IN_PROGRESS is deliberately excluded since the work isn't done yet.
const CLOSED_STATUSES = new Set(['REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE', 'WONT_FIX'])

const TOP_CRITICAL_DISPLAY_LIMIT = 5

function formatDuration(startedAt, completedAt) {
  if (!startedAt || !completedAt) return '—'
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const totalSeconds = Math.round(ms / 1000)
  if (totalSeconds < 60) return `${totalSeconds}s`
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  if (minutes < 60) return `${minutes}m ${seconds}s`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ${minutes % 60}m`
}

export default function ReportsPage() {
  const { scan_id: scanId } = useParams()
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const [error, setError] = useState(null)
  const [pendingStatusIds, setPendingStatusIds] = useState(() => new Set())
  const [statusToast, setStatusToast] = useState(null)

  useEffect(() => {
    if (!statusToast) return
    const timer = setTimeout(() => setStatusToast(null), 4000)
    return () => clearTimeout(timer)
  }, [statusToast])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    setNotFound(false)

    getExecutiveReport(scanId)
      .then((data) => {
        if (cancelled) return
        setReport(data)
      })
      .catch((err) => {
        if (cancelled) return
        if (err.response?.status === 404) {
          setNotFound(true)
        } else {
          setError(err.response?.data?.detail || err.message || 'Failed to load report')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [scanId])

  function updateFindingInReport(findingId, nextStatus) {
    setReport((prev) => {
      if (!prev) return prev
      const updateList = (list) =>
        list.map((f) => (f.id === findingId ? { ...f, remediation_status: nextStatus } : f))
      return { ...prev, all_findings: updateList(prev.all_findings), top_critical: updateList(prev.top_critical) }
    })
  }

  function handleStatusChange(findingId, nextStatus) {
    const previousStatus = report.all_findings.find((f) => f.id === findingId)?.remediation_status
    if (previousStatus === undefined || previousStatus === nextStatus) return

    updateFindingInReport(findingId, nextStatus)
    setPendingStatusIds((prev) => new Set(prev).add(findingId))

    updateFindingStatus(findingId, nextStatus)
      .catch((err) => {
        updateFindingInReport(findingId, previousStatus)
        setStatusToast(extractErrorMessage(err))
      })
      .finally(() => {
        setPendingStatusIds((prev) => {
          const next = new Set(prev)
          next.delete(findingId)
          return next
        })
      })
  }

  if (loading) {
    return <div className="flex h-64 items-center justify-center font-body text-ink-2">Loading report…</div>
  }

  if (error) {
    return <Card className="border-severity-high text-severity-high">Failed to load report: {error}</Card>
  }

  const totalFindings = report
    ? Object.values(report.findings_by_severity).reduce((sum, count) => sum + count, 0)
    : 0

  if (notFound || !report || totalFindings === 0) {
    return (
      <Card className="text-center">
        <p className="font-display text-heading text-ink">Report not found</p>
        <p className="mt-2 font-body text-ink-2">
          {notFound
            ? "This scan doesn't exist, or its report is no longer available."
            : 'This scan has no findings yet, so there is nothing to report.'}
        </p>
        <Link
          to="/findings"
          className="mt-4 inline-flex items-center gap-1 font-body text-sm font-semibold text-brand hover:text-brand-dark"
        >
          <ChevronLeftIcon size={16} strokeWidth={2.5} />
          Back to findings
        </Link>
      </Card>
    )
  }

  const { scan_metadata: meta } = report
  const criticalHighCount = (report.findings_by_severity.CRITICAL ?? 0) + (report.findings_by_severity.HIGH ?? 0)
  const closedCount = Object.entries(report.findings_by_status).reduce(
    (sum, [status, count]) => sum + (CLOSED_STATUSES.has(status) ? count : 0),
    0,
  )
  const remediationRate = totalFindings ? Math.round((closedCount / totalFindings) * 100) : 0

  const severityChartData = SEVERITY_ORDER.filter((s) => report.findings_by_severity[s]).map((severity) => ({
    name: severity,
    value: report.findings_by_severity[severity],
    fill: SEVERITY_HEX[SEVERITY_BADGE[severity] ?? 'info'],
  }))

  const statusChartData = STATUS_ORDER.filter((s) => report.findings_by_status[s]).map((status) => ({
    name: status.replace(/_/g, ' '),
    count: report.findings_by_status[status],
    fill: SEVERITY_HEX[REMEDIATION_STATUS_BADGE[status] ?? 'info'],
  }))

  const showTimeline = report.timeline.length > 1
  const topCritical = report.top_critical.slice(0, TOP_CRITICAL_DISPLAY_LIMIT)
  const isTruncated = report.all_findings.length < totalFindings

  return (
    <div className="space-y-6" id="executive-report">
      <style>{`
        @media print {
          body * { visibility: hidden; }
          #executive-report, #executive-report * { visibility: visible; }
          #executive-report { position: absolute; inset: 0; }
          #executive-report .no-print { display: none; }
        }
      `}</style>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-display text-ink">{meta.name}</h1>
          <p className="mt-1 font-body text-ink-2">
            {meta.scope} · {meta.status}
          </p>
          <p className="mt-1 font-body text-xs text-ink-3">
            Started {meta.started_at ? new Date(meta.started_at).toLocaleString() : '—'} · Duration{' '}
            {formatDuration(meta.started_at, meta.completed_at)}
          </p>
        </div>
        <button
          type="button"
          onClick={() => window.print()}
          className="no-print radius-b inline-flex cursor-pointer items-center gap-2 border border-brand bg-brand px-4 py-2.5 font-body text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-dark"
        >
          Export to PDF
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Findings" value={totalFindings} icon={TargetIcon} />
        <StatCard
          label="Critical + High"
          value={criticalHighCount}
          icon={WarnCircleIcon}
          accentClassName="text-severity-high"
        />
        <StatCard
          label="Remediation Rate"
          value={`${remediationRate}%`}
          icon={CheckCircleIcon}
          accentClassName="text-severity-resolved"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <h2 className="mb-4 font-display text-heading text-ink">Findings by severity</h2>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={severityChartData} dataKey="value" nameKey="name" outerRadius={90} label>
                {severityChartData.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <h2 className="mb-4 font-display text-heading text-ink">Findings by status</h2>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={statusChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E8EE" />
              <XAxis dataKey="name" tick={{ fontSize: 12 }} interval={0} angle={-20} textAnchor="end" height={60} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count">
                {statusChartData.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card>
        <h2 className="mb-4 font-display text-heading text-ink">Discovery timeline</h2>
        {showTimeline ? (
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={report.timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E8EE" />
              <XAxis dataKey="date" tick={{ fontSize: 12 }} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              {SEVERITY_ORDER.map((severity) => (
                <Line
                  key={severity}
                  type="monotone"
                  dataKey={severity.toLowerCase()}
                  name={severity}
                  stroke={SEVERITY_HEX[SEVERITY_BADGE[severity] ?? 'info']}
                  strokeWidth={2}
                  dot={{ r: 3 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <p className="font-body text-ink-3">Not enough data for a timeline — this scan's findings span a single day.</p>
        )}
      </Card>

      <Card>
        <h2 className="mb-4 font-display text-heading text-ink">Top critical findings</h2>
        {topCritical.length === 0 ? (
          <p className="font-body text-ink-3">No critical findings on this scan.</p>
        ) : (
          <ul className="divide-y divide-line">
            {topCritical.map((finding) => (
              <li key={finding.id}>
                <Link
                  to={`/findings/${finding.id}`}
                  className="flex items-center justify-between gap-4 py-3 transition-colors hover:bg-sunken"
                >
                  <span className="truncate font-body text-ink">{finding.title}</span>
                  <Badge severity="critical">{finding.cve_id || finding.severity_normalized}</Badge>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card>
        <div className="mb-4 flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="font-display text-heading text-ink">All findings</h2>
          {isTruncated && (
            <p className="font-body text-xs text-ink-3">
              Showing the first {report.all_findings.length} of {totalFindings} findings.
            </p>
          )}
        </div>
        <div className="radius-b overflow-x-auto border border-line">
          <table className="min-w-full divide-y divide-line">
            <thead>
              <tr className="bg-sunken">
                <th className="px-4 py-3 text-left font-body text-xs font-semibold uppercase tracking-wide text-ink-3">Title</th>
                <th className="px-4 py-3 text-left font-body text-xs font-semibold uppercase tracking-wide text-ink-3">Severity</th>
                <th className="px-4 py-3 text-left font-body text-xs font-semibold uppercase tracking-wide text-ink-3">Tool</th>
                <th className="px-4 py-3 text-left font-body text-xs font-semibold uppercase tracking-wide text-ink-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {report.all_findings.map((finding) => (
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
                  <td className="px-4 py-3 font-body text-sm text-ink-2">{finding.tool_source}</td>
                  <td className="px-4 py-3 text-sm">
                    <select
                      value={finding.remediation_status}
                      disabled={pendingStatusIds.has(finding.id)}
                      onChange={(e) => handleStatusChange(finding.id, e.target.value)}
                      className={`cursor-pointer rounded-full border px-3 py-1 font-body text-xs font-semibold uppercase tracking-wide focus:outline-none disabled:cursor-not-allowed disabled:opacity-50 ${
                        REMEDIATION_STATUS_SELECT_CLASSES[finding.remediation_status] ??
                        REMEDIATION_STATUS_SELECT_CLASSES.OPEN
                      }`}
                    >
                      {REMEDIATION_STATUS_OPTIONS.map((status) => (
                        <option key={status} value={status}>
                          {status.replace(/_/g, ' ')}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {statusToast && (
        <div className="no-print fixed bottom-6 right-6 z-50 radius-a border border-severity-high bg-surface px-4 py-3 font-body text-sm text-severity-high shadow-lg">
          {statusToast}
        </div>
      )}
    </div>
  )
}
