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

export async function getStats() {
  const { data } = await apiClient.get('/stats')
  return data
}

export async function getScans() {
  const { data } = await apiClient.get('/scans')
  return data
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
