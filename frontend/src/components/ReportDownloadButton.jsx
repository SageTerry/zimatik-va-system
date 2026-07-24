import { useState } from 'react'
import { downloadTechnicalReport } from '../api/client'
import { defaultReportFilename, filenameFromContentDisposition, triggerFileDownload } from '../lib/download'

const DEFAULT_CLASSES =
  'inline-flex items-center gap-2 rounded-md border border-gray-700 bg-gray-800 px-4 py-2 text-sm font-medium text-gray-200 transition hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-50'

function DownloadIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4">
      <path d="M10 2a1 1 0 0 1 1 1v7.586l2.293-2.293a1 1 0 1 1 1.414 1.414l-4 4a1 1 0 0 1-1.414 0l-4-4a1 1 0 1 1 1.414-1.414L9 10.586V3a1 1 0 0 1 1-1Z" />
      <path d="M4 14a1 1 0 0 1 1 1v1a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1a1 1 0 1 1 2 0v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3v-1a1 1 0 0 1 1-1Z" />
    </svg>
  )
}

/**
 * Button that POSTs to /reports/technical and saves the resulting PDF.
 *
 * `getPayload` is a function (sync or async) returning the request body
 * ({ scan_id } or { finding_ids }), or null/undefined to skip the request -
 * e.g. when there's nothing loaded yet to include in the report.
 */
export default function ReportDownloadButton({ getPayload, label = 'Download Technical Report', className }) {
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState(null)

  async function handleClick() {
    setError(null)
    const payload = await getPayload()
    if (!payload) {
      setError('Nothing available to include in a report yet.')
      return
    }

    setDownloading(true)
    try {
      const response = await downloadTechnicalReport(payload)
      const filename = filenameFromContentDisposition(
        response.headers['content-disposition'],
        defaultReportFilename(),
      )
      triggerFileDownload(response.data, filename)
    } catch {
      setError('Failed to generate report. Please try again.')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="inline-flex flex-col items-start gap-1">
      <button type="button" onClick={handleClick} disabled={downloading} className={className || DEFAULT_CLASSES}>
        <DownloadIcon />
        {downloading ? 'Generating…' : label}
      </button>
      {error && <span className="text-xs text-red-400">{error}</span>}
    </div>
  )
}
