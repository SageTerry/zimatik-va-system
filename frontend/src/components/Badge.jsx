const SEVERITY_STYLES = {
  critical: 'text-severity-critical bg-severity-critical/10',
  high: 'text-severity-high bg-severity-high/10',
  medium: 'text-severity-medium bg-severity-medium/10',
  low: 'text-severity-low bg-severity-low/10',
  resolved: 'text-severity-resolved bg-severity-resolved/10',
  info: 'text-severity-info bg-severity-info/10',
}

export default function Badge({ severity = 'info', children, className = '' }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-body text-xs font-semibold uppercase tracking-wide ${
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
      } ${className}`}
    >
      {children}
    </span>
  )
}
