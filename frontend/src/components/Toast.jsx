import { useEffect } from 'react'
import { CheckCircleIcon, WarnCircleIcon, XCircleIcon } from '../lib/icons'

const AUTO_DISMISS_MS = 5000

const TOAST_STYLES = {
  error: { icon: XCircleIcon, accentClassName: 'border-severity-high/30 text-severity-high' },
  success: { icon: CheckCircleIcon, accentClassName: 'border-severity-resolved/30 text-severity-resolved' },
  warning: { icon: WarnCircleIcon, accentClassName: 'border-severity-medium/30 text-severity-medium' },
}

export default function Toast({ type = 'error', message, onDismiss }) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, AUTO_DISMISS_MS)
    return () => clearTimeout(timer)
  }, [onDismiss])

  const style = TOAST_STYLES[type] ?? TOAST_STYLES.error
  const Icon = style.icon

  return (
    <div
      role="alert"
      className={`radius-a flex w-80 max-w-[calc(100vw-2rem)] items-start gap-3 border bg-surface p-4 shadow-card-hover ${style.accentClassName}`}
    >
      <Icon size={20} strokeWidth={2} className="mt-0.5 flex-shrink-0" />
      <p className="flex-1 font-body text-sm text-ink">{message}</p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss"
        className="flex-shrink-0 cursor-pointer font-body text-lg leading-none text-ink-3 transition-colors hover:text-ink"
      >
        &times;
      </button>
    </div>
  )
}
