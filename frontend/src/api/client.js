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

export default apiClient
