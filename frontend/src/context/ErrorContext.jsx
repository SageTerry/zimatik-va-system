import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { registerApiErrorHandler } from '../api/client'
import Toast from '../components/Toast'

const ErrorContext = createContext(null)

// Module-level rather than per-provider state - a provider only ever mounts
// once for the app's lifetime, and this keeps ids stable across any
// StrictMode double-render in dev.
let nextToastId = 0

export function ErrorProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const dismiss = useCallback((id) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const push = useCallback((type, message) => {
    setToasts((current) => {
      // A single failure often fans out into several rejected requests at
      // once (e.g. the dashboard's parallel fetches all failing the same
      // way when the backend is down) - avoid stacking identical toasts.
      if (current.some((toast) => toast.type === type && toast.message === message)) return current
      return [...current, { id: ++nextToastId, type, message }]
    })
  }, [])

  const showError = useCallback((message) => push('error', message), [push])
  const showSuccess = useCallback((message) => push('success', message), [push])
  const showWarning = useCallback((message) => push('warning', message), [push])

  // Lets the axios client (which lives outside the React tree) surface a
  // toast for any API error automatically, without every call site needing
  // its own try/catch.
  useEffect(() => {
    registerApiErrorHandler((parsedError) => showError(parsedError.message))
    return () => registerApiErrorHandler(null)
  }, [showError])

  return (
    <ErrorContext.Provider value={{ showError, showSuccess, showWarning }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col items-end gap-3">
        {toasts.map((toast) => (
          <Toast key={toast.id} type={toast.type} message={toast.message} onDismiss={() => dismiss(toast.id)} />
        ))}
      </div>
    </ErrorContext.Provider>
  )
}

export function useError() {
  const ctx = useContext(ErrorContext)
  if (!ctx) throw new Error('useError must be used within an ErrorProvider')
  return ctx
}
