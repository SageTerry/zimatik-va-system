const SEVERITY_STYLES = {
  critical: 'text-severity-critical border-severity-critical',
  high: 'text-severity-high border-severity-high',
  medium: 'text-severity-medium border-severity-medium',
  low: 'text-severity-low border-severity-low',
  resolved: 'text-severity-resolved border-severity-resolved',
  info: 'text-severity-info border-severity-info',
}

export default function Badge({ severity = 'info', children, className = '' }) {
  return (
    <span
      className={`radius-c inline-flex items-center gap-1 border bg-transparent px-2.5 py-0.5 font-body text-xs font-bold uppercase tracking-wide ${
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
      } ${className}`}
    >
      {children}
    </span>
  )
}
