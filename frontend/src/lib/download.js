// Shared helpers for triggering a browser download from a Blob response.

export function triggerFileDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export function filenameFromContentDisposition(header, fallback) {
  if (!header) return fallback
  const match = /filename="?([^"]+)"?/.exec(header)
  return match ? match[1] : fallback
}

export function defaultReportFilename() {
  return `VACE-report-${new Date().toISOString().slice(0, 10)}.pdf`
}
