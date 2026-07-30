import axios from 'axios'

const API_BASE_URL = 'http://localhost:8001/api/v1'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

export async function getFindings(filters = {}) {
  const { severity, tool, host, scan_id, page, page_size } = filters
  const { data } = await apiClient.get('/findings', {
    params: { severity, tool, host, scan_id, page, page_size },
  })
  return data
}

export async function getFindingById(id) {
  const { data } = await apiClient.get(`/findings/${id}`)
  return data
}

export async function updateFindingStatus(findingId, remediationStatus) {
  const { data } = await apiClient.patch(`/findings/${findingId}`, {
    remediation_status: remediationStatus,
  })
  return data
}

export async function getStats() {
  const { data } = await apiClient.get('/stats')
  return data
}

export async function getScans() {
  const { data } = await apiClient.get('/scans')
  return data
}

export async function startWebScan(targetUrl) {
  const scanName = `ZAP scan: ${new URL(targetUrl).hostname} — ${new Date().toLocaleString()}`
  const { data } = await apiClient.post('/scans/import', {
    scan_name: scanName,
    tools: ['ZAP'],
    scope: targetUrl,
  })
  return data
}

export async function startMobileScan(apkFile, appName) {
  const formData = new FormData()
  formData.append('file', apkFile)
  formData.append('app_name', appName)
  // apiClient defaults to a JSON content-type, which would make axios
  // JSON-stringify the FormData instead of sending it as multipart. Clearing
  // it here lets the browser set the correct multipart/form-data header
  // (including the boundary) itself.
  const { data } = await apiClient.post('/scans/import-mobile', formData, {
    headers: { 'Content-Type': undefined },
  })
  return data
}

export async function startCodeScan(zipFile, projectName) {
  const formData = new FormData()
  formData.append('file', zipFile)
  formData.append('project_name', projectName)
  // apiClient defaults to a JSON content-type, which would make axios
  // JSON-stringify the FormData instead of sending it as multipart. Clearing
  // it here lets the browser set the correct multipart/form-data header
  // (including the boundary) itself.
  const { data } = await apiClient.post('/scans/import-code', formData, {
    headers: { 'Content-Type': undefined },
  })
  return data
}

export async function getScan(scanId) {
  const { data } = await apiClient.get(`/scans/${scanId}`)
  return data
}

// Opens an SSE connection to a scan's live progress stream. `onMessage` is
// called with the parsed payload on every frame; `onError` on a connection
// error. Returns a cleanup function that closes the connection - call it on
// unmount or once the scan reaches a terminal status.
export function openScanProgressStream(scanId, { onMessage, onError } = {}) {
  const source = new EventSource(`${API_BASE_URL}/scans/${scanId}/progress`)
  source.onmessage = (event) => onMessage?.(JSON.parse(event.data))
  source.onerror = (event) => onError?.(event)
  return () => source.close()
}

export async function downloadTechnicalReport(payload) {
  return apiClient.post('/reports/technical', payload, { responseType: 'blob' })
}

// Returns null (rather than throwing) when the tool has no stored credential yet.
export async function getCredentials(tool) {
  try {
    const { data } = await apiClient.get(`/credentials/${tool}`)
    return data
  } catch (err) {
    if (err.response?.status === 404) return null
    throw err
  }
}

export async function saveCredentials(tool, { base_url, api_key, api_secret }) {
  const { data } = await apiClient.post('/credentials', { tool, base_url, api_key, api_secret })
  return data
}

export async function testConnection(tool) {
  const { data } = await apiClient.post(`/credentials/${tool}/test`)
  return data
}

export async function deleteCredentials(tool) {
  await apiClient.delete(`/credentials/${tool}`)
}

export default apiClient
