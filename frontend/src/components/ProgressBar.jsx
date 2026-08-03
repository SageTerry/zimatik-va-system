const SEVERITY_FILL = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  resolved: 'bg-severity-resolved',
  info: 'bg-severity-info',
}

export default function ProgressBar({ value = 0, max = 1, severity = 'info', height = 8, className = '' }) {
  const pct = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0

  return (
    <div
      className={`w-full overflow-hidden rounded-full bg-sunken ${className}`}
      style={{ height }}
      role="progressbar"
      aria-valuenow={Math.round(pct * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className={`h-full rounded-full transition-all duration-300 ${SEVERITY_FILL[severity] ?? SEVERITY_FILL.info}`}
        style={{ width: `${pct * 100}%` }}
      />
    </div>
  )
}
