// Turns any axios error into a small structured object the UI can render
// directly: {status, message, retryable}. Also owns the one cross-cutting
// side effect that isn't specific to any screen - bouncing to /login once
// the token is expired or rejected.

function extractMessage(error) {
  const data = error.response?.data

  if (typeof data === 'string' && data.trim()) return data

  // FastAPI sends `detail` as a plain string for most errors, but as a list
  // of {loc, msg, type} objects for 422 validation failures.
  if (Array.isArray(data?.detail)) {
    return data.detail.map((d) => d.msg).filter(Boolean).join('; ') || 'Validation failed.'
  }
  if (typeof data?.detail === 'string' && data.detail.trim()) return data.detail

  if (typeof data?.message === 'string' && data.message.trim()) return data.message

  if (!error.response) return 'Network error - unable to reach the server.'

  return error.message || 'Something went wrong.'
}

export function handleApiError(error) {
  const status = error.response?.status ?? null

  if (status === 401) {
    localStorage.removeItem('access_token')
    if (window.location.pathname !== '/login') {
      window.location.assign('/login')
    }
    return { status, message: 'Your session has expired. Please log in again.', retryable: false }
  }

  // No response at all (network down, CORS, server unreachable) and 5xx
  // server errors are worth letting the user retry; other 4xx are a
  // problem with the request itself that retrying won't fix.
  const retryable = !error.response || status >= 500

  return { status, message: extractMessage(error), retryable }
}
