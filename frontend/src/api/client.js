import axios from 'axios'
import { handleApiError } from '../services/errorHandler'

const API_BASE_URL = 'http://localhost:8001/api/v1'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// Attaches the stored JWT (if any) to every request. Login itself goes
// through this same client - there's just no token yet on that first call,
// so the header is simply omitted rather than sent as "Bearer null".
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Set by ErrorContext on mount so any API error, anywhere in the app, can
// surface a toast automatically - call sites don't need their own catch
// block just to display a failure.
let onApiError = null
export function registerApiErrorHandler(handler) {
  onApiError = handler
}

// errorHandler.handleApiError does the actual parsing (message extraction,
// 401 -> clear token + redirect to /login). This just wires its result into
// the registered toast handler and re-rejects so callers can still `catch`
// if they need to react locally (e.g. a form showing a field error).
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const parsedError = handleApiError(error)
    // A 401 is about to redirect away from the current page - flashing a
    // toast right before navigating away isn't useful.
    if (parsedError.status !== 401) {
      onApiError?.(parsedError)
    }
    return Promise.reject(error)
  },
)

export async function login(username, password) {
  const { data } = await apiClient.post('/auth/login', { username, password })
  return data
}

export async function getFindings(filters = {}) {
  const { severity, tool, host, scan_id, threat_status, sort, page, page_size } = filters
  const { data } = await apiClient.get('/findings', {
    params: { severity, tool, host, scan_id, threat_status, sort, page, page_size },
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

export async function getExecutiveReport(scanId) {
  const { data } = await apiClient.get('/reports/executive', { params: { scan_id: scanId } })
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
//
// The browser's native EventSource can't set an Authorization header, so
// the token is passed as a query param instead - the backend's JWT
// middleware special-cases this one path to accept it that way.
export function openScanProgressStream(scanId, { onMessage, onError } = {}) {
  const url = new URL(`${API_BASE_URL}/scans/${scanId}/progress`)
  const token = localStorage.getItem('access_token')
  if (token) url.searchParams.set('token', token)

  const source = new EventSource(url)
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
