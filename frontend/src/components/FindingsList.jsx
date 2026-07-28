import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getFindings } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Badge from './Badge'
import { REMEDIATION_STATUS_BADGE, SEVERITY_BADGE, SEVERITY_ORDER, TOOL_OPTIONS } from '../lib/constants'

const PAGE_SIZE = 25

const SELECT_CLASSES =
  'radius-b border border-line-strong bg-transparent px-3 py-2 font-body text-sm text-ink focus:border-ink-2 focus:outline-none'

export default function FindingsList() {
  const navigate = useNavigate()
  const [findings, setFindings] = useState([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(0)
  const [page, setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState('')
  const [toolFilter, setToolFilter] = useState('')
  const [sortDir, setSortDir] = useState('asc') // asc = critical first
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Guards against an older, slower request overwriting a newer one when
  // filters/page change in quick succession.
  const requestIdRef = useRef(0)

  const runFetch = useCallback((params) => {
    const requestId = ++requestIdRef.current
    getFindings(params)
      .then((data) => {
        if (requestId !== requestIdRef.current) return
        setFindings(data.items)
        setTotal(data.total)
        setTotalPages(data.total_pages)
      })
      .catch((err) => {
        if (requestId !== requestIdRef.current) return
        setError(err.message || 'Failed to load findings')
      })
      .finally(() => {
        if (requestId === requestIdRef.current) setLoading(false)
      })
  }, [])

  // Initial load only. Filter/page-driven refetches are triggered directly
  // from the event handlers below, since that's when they actually happen.
  useEffect(() => {
    runFetch({ page: 1, page_size: PAGE_SIZE })
  }, [runFetch])

  function refetch(overrides) {
    const nextSeverity = 'severity' in overrides ? overrides.severity : severityFilter
    const nextTool = 'tool' in overrides ? overrides.tool : toolFilter
    const nextPage = overrides.page ?? page
    setLoading(true)
    setError(null)
    runFetch({
      severity: nextSeverity || undefined,
      tool: nextTool || undefined,
      page: nextPage,
      page_size: PAGE_SIZE,
    })
  }

  function handleSeverityChange(value) {
    setSeverityFilter(value)
    setPage(1)
    refetch({ severity: value, page: 1 })
  }

  function handleToolChange(value) {
    setToolFilter(value)
    setPage(1)
    refetch({ tool: value, page: 1 })
  }

  function goToPage(nextPage) {
    const clamped = Math.min(Math.max(1, nextPage), totalPages || 1)
    setPage(clamped)
    refetch({ page: clamped })
  }

  function toggleSort() {
    setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'))
  }

  const sortedFindings = [...findings].sort((a, b) => {
    const rankA = SEVERITY_ORDER.indexOf(a.severity_normalized)
    const rankB = SEVERITY_ORDER.indexOf(b.severity_normalized)
    return sortDir === 'asc' ? rankA - rankB : rankB - rankA
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-display text-ink">Findings</h1>
          <p className="mt-1 font-body text-ink-2">
            {total} total finding{total === 1 ? '' : 's'}
          </p>
        </div>

        <div className="flex flex-wrap items-start gap-3">
          <ReportDownloadButton
            label="Download Technical Report"
            getPayload={() =>
              sortedFindings.length ? { finding_ids: sortedFindings.map((f) => f.id) } : null
            }
          />

          <select
            value={severityFilter}
            onChange={(e) => handleSeverityChange(e.target.value)}
            className={SELECT_CLASSES}
          >
            <option value="">All severities</option>
            {SEVERITY_ORDER.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>

          <select
            value={toolFilter}
            onChange={(e) => handleToolChange(e.target.value)}
            className={SELECT_CLASSES}
          >
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
          Failed to load findings: {error}
        </div>
      )}

      <div className="radius-a overflow-x-auto border border-line">
        <table className="min-w-full divide-y divide-line">
          <thead>
            <tr>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">CVE</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Title</th>
              <th
                onClick={toggleSort}
                className="cursor-pointer select-none px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3 hover:text-ink"
              >
                Severity {sortDir === 'asc' ? '↓' : '↑'}
              </th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Tool</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">
                Host / File
              </th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center font-body text-ink-3">
                  Loading findings…
                </td>
              </tr>
            ) : sortedFindings.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center font-body text-ink-3">
                  No findings match these filters.
                </td>
              </tr>
            ) : (
              sortedFindings.map((finding) => {
                const location = finding.host || finding.code_file || finding.url || '—'
                return (
                  <tr
                    key={finding.id}
                    onClick={() => navigate(`/findings/${finding.id}`)}
                    className="cursor-pointer transition-colors hover:bg-sunken"
                  >
                    <td className="px-4 py-3 font-body text-sm text-ink-2">{finding.cve_id || '—'}</td>
                    <td className="max-w-xs truncate px-4 py-3 font-body text-sm text-ink">{finding.title}</td>
                    <td className="px-4 py-3 text-sm">
                      <Badge severity={SEVERITY_BADGE[finding.severity_normalized] ?? 'info'}>
                        {finding.severity_normalized}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 font-body text-sm text-ink-2">{finding.tool_source}</td>
                    <td className="max-w-xs truncate px-4 py-3 font-body text-sm text-ink-2">{location}</td>
                    <td className="px-4 py-3 text-sm">
                      <Badge severity={REMEDIATION_STATUS_BADGE[finding.remediation_status] ?? 'info'}>
                        {finding.remediation_status.replace(/_/g, ' ')}
                      </Badge>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between font-body text-sm text-ink-2">
          <button
            onClick={() => goToPage(page - 1)}
            disabled={page <= 1}
            className="radius-c border border-line-strong px-3 py-1.5 transition-colors hover:bg-sunken disabled:cursor-not-allowed disabled:opacity-40"
          >
            Previous
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => goToPage(page + 1)}
            disabled={page >= totalPages}
            className="radius-c border border-line-strong px-3 py-1.5 transition-colors hover:bg-sunken disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
