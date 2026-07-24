import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getFindings } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import { SEVERITY_ORDER, SEVERITY_STYLES, TOOL_OPTIONS } from '../lib/constants'

const PAGE_SIZE = 25

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
          <h1 className="text-2xl font-bold text-white">Findings</h1>
          <p className="mt-1 text-sm text-gray-400">
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
            className="rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
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
            className="rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
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
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-300">
          Failed to load findings: {error}
        </div>
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="min-w-full divide-y divide-gray-800">
          <thead className="bg-gray-800/60">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400">
                CVE
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400">
                Title
              </th>
              <th
                onClick={toggleSort}
                className="cursor-pointer select-none px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400 hover:text-gray-200"
              >
                Severity {sortDir === 'asc' ? '↓' : '↑'}
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400">
                Tool
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400">
                Host / File
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-900">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-gray-500">
                  Loading findings…
                </td>
              </tr>
            ) : sortedFindings.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-gray-500">
                  No findings match these filters.
                </td>
              </tr>
            ) : (
              sortedFindings.map((finding) => {
                const style = SEVERITY_STYLES[finding.severity_normalized] ?? SEVERITY_STYLES.INFO
                const location = finding.host || finding.code_file || finding.url || '—'
                return (
                  <tr
                    key={finding.id}
                    onClick={() => navigate(`/findings/${finding.id}`)}
                    className="cursor-pointer transition hover:bg-gray-800/60"
                  >
                    <td className="px-4 py-3 text-sm text-gray-300">{finding.cve_id || '—'}</td>
                    <td className="max-w-xs truncate px-4 py-3 text-sm text-gray-100">{finding.title}</td>
                    <td className="px-4 py-3 text-sm">
                      <span
                        className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${style.bg} ${style.text} ${style.border}`}
                      >
                        {finding.severity_normalized}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">{finding.tool_source}</td>
                    <td className="max-w-xs truncate px-4 py-3 text-sm text-gray-300">{location}</td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {finding.remediation_status.replace(/_/g, ' ')}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-400">
          <button
            onClick={() => goToPage(page - 1)}
            disabled={page <= 1}
            className="rounded-md border border-gray-700 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Previous
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => goToPage(page + 1)}
            disabled={page >= totalPages}
            className="rounded-md border border-gray-700 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
