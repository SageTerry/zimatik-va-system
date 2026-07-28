import { useId } from 'react'

const SEVERITY_STROKE = {
  critical: 'stroke-severity-critical',
  high: 'stroke-severity-high',
  medium: 'stroke-severity-medium',
  low: 'stroke-severity-low',
  resolved: 'stroke-severity-resolved',
  info: 'stroke-severity-info',
}

// Progress is drawn as an outline stroke over a proportional width rather
// than a filled bar - severity colors never fill a shape in this design
// system, only outline it.
export default function ProgressBar({ value = 0, max = 1, severity = 'info', height = 14, className = '' }) {
  const filterId = `progress-wobble-${useId()}`
  const pct = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0
  const fillWidth = pct > 0 ? Math.max(4, pct * 198) : 0

  return (
    <svg
      viewBox="0 0 200 16"
      preserveAspectRatio="none"
      style={{ height }}
      className={`w-full ${className}`}
    >
      <defs>
        <filter id={filterId}>
          <feTurbulence type="fractalNoise" baseFrequency="0.05 0.3" numOctaves="1" seed="5" result="noise" />
          <feDisplacementMap in="SourceGraphic" in2="noise" scale="1" />
        </filter>
      </defs>
      <g filter={`url(#${filterId})`}>
        <rect x="1" y="1" width="198" height="14" rx="7" fill="none" className="stroke-line-strong" strokeWidth="2" />
        {pct > 0 && (
          <rect
            x="1"
            y="1"
            width={fillWidth}
            height="14"
            rx="7"
            fill="none"
            strokeWidth="2.5"
            className={SEVERITY_STROKE[severity] ?? SEVERITY_STROKE.info}
          />
        )}
      </g>
    </svg>
  )
}
