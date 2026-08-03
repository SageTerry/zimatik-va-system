function IconBase({ size = 20, strokeWidth = 2, className = '', children }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

export function ShieldIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z" />
    </IconBase>
  )
}

export function ShieldCheckIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z" />
      <path d="M8.5 12l2.3 2.3L15.5 9.5" />
    </IconBase>
  )
}

export function RadarIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <path d="M12 12l5.5-5.5" />
    </IconBase>
  )
}

export function TargetIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1.5" />
    </IconBase>
  )
}

export function CheckCircleIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8 12.3l2.6 2.6L16.2 9" />
    </IconBase>
  )
}

export function WarnCircleIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 8v5" />
      <path d="M12 16.2v.1" />
    </IconBase>
  )
}

export function XCircleIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M9 9l6 6" />
      <path d="M15 9l-6 6" />
    </IconBase>
  )
}

export function SearchIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="M15.3 15.3L20 20" />
    </IconBase>
  )
}

export function ScanIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8" />
      <path d="M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8" />
      <path d="M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16" />
      <path d="M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16" />
      <path d="M4 12h16" />
    </IconBase>
  )
}

export function ChevronRightIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M9 5.5l6.5 6.5-6.5 6.5" />
    </IconBase>
  )
}

export function ChevronDownIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M5.5 9l6.5 6.5L18.5 9" />
    </IconBase>
  )
}

export function ChevronLeftIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M15 5.5L8.5 12l6.5 6.5" />
    </IconBase>
  )
}

export function PlusIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </IconBase>
  )
}

export function CheckmarkIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M5 13l4 4L19 7" />
    </IconBase>
  )
}

export function UploadIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M12 15.5V4" />
      <path d="M7.5 8.5L12 4l4.5 4.5" />
      <path d="M4 15.5v3A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5v-3" />
    </IconBase>
  )
}

export function SmartphoneIcon(props) {
  return (
    <IconBase {...props}>
      <rect x="7" y="3" width="10" height="18" rx="1.5" />
      <path d="M11 18h2" />
    </IconBase>
  )
}

export function GridIcon(props) {
  return (
    <IconBase {...props}>
      <rect x="3.5" y="3.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="13" y="3.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="3.5" y="13" width="7.5" height="7.5" rx="1.5" />
      <rect x="13" y="13" width="7.5" height="7.5" rx="1.5" />
    </IconBase>
  )
}

export function ListIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M8 6h12" />
      <path d="M8 12h12" />
      <path d="M8 18h12" />
      <path d="M4 6h.01" />
      <path d="M4 12h.01" />
      <path d="M4 18h.01" />
    </IconBase>
  )
}

export function CodeIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M9 8l-4 4 4 4" />
      <path d="M15 8l4 4-4 4" />
    </IconBase>
  )
}

export function DocumentIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M7 3.5h7l3.5 3.5V19a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 19V5A1.5 1.5 0 0 1 7 3.5z" />
      <path d="M14 3.5V7a1.5 1.5 0 0 0 1.5 1.5H19" />
      <path d="M8.5 12.5h7" />
      <path d="M8.5 16h7" />
    </IconBase>
  )
}

export function GearIcon(props) {
  return (
    <IconBase {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3.5v2.2M12 18.3v2.2M4.5 12h2.2M17.3 12h2.2M6.6 6.6l1.6 1.6M15.8 15.8l1.6 1.6M17.4 6.6l-1.6 1.6M8.2 15.8l-1.6 1.6" />
    </IconBase>
  )
}

export function LogoutIcon(props) {
  return (
    <IconBase {...props}>
      <path d="M9 4H6.5A1.5 1.5 0 0 0 5 5.5v13A1.5 1.5 0 0 0 6.5 20H9" />
      <path d="M14 15l4.5-3-4.5-3" />
      <path d="M18.5 12h-10" />
    </IconBase>
  )
}
