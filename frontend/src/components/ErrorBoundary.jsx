import { Component } from 'react'
import Button from './Button'

// Catches crashes in the render tree beneath it (React error boundaries only
// catch render/lifecycle errors, not async or event-handler errors - those
// go through errorHandler.js/ErrorContext instead) and shows a recoverable
// screen instead of a blank page.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error('Unhandled component error:', error, info)
  }

  render() {
    if (!this.state.hasError) return this.props.children

    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-paper px-6 text-center">
        <h1 className="font-display text-display text-ink">Something went wrong</h1>
        <p className="max-w-md font-body text-ink-2">
          An unexpected error occurred. Try refreshing the page, or head back to the dashboard.
        </p>
        <div className="mt-2 flex gap-3">
          <Button variant="primary" onClick={() => window.location.reload()}>
            Refresh
          </Button>
          <Button variant="secondary" onClick={() => window.location.assign('/')}>
            Go home
          </Button>
        </div>
      </div>
    )
  }
}
