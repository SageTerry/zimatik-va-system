// Shared display config for VACE's normalized enums (see backend app/models/finding.py).

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

// Maps a finding's severity_normalized value onto a Badge `severity` variant.
export const SEVERITY_BADGE = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
}

export const TOOL_OPTIONS = ['NESSUS', 'SONARQUBE', 'ZAP']

export const REMEDIATION_STATUS_OPTIONS = [
  'OPEN',
  'IN_PROGRESS',
  'REMEDIATED',
  'RISK_ACCEPTED',
  'FALSE_POSITIVE',
  'WONT_FIX',
]

// Remediation status is a different axis from severity, but reuses the same
// Badge component/palette rather than introducing a second visual language.
// red=OPEN, yellow=IN_PROGRESS, green=every other (closed/accepted) status.
export const REMEDIATION_STATUS_BADGE = {
  OPEN: 'high',
  IN_PROGRESS: 'medium',
  REMEDIATED: 'resolved',
  RISK_ACCEPTED: 'resolved',
  FALSE_POSITIVE: 'resolved',
  WONT_FIX: 'resolved',
}

// Same palette as REMEDIATION_STATUS_BADGE, expressed as classes for a
// <select> rather than a <span> (Badge itself isn't a form control).
export const REMEDIATION_STATUS_SELECT_CLASSES = {
  OPEN: 'text-severity-high border-severity-high',
  IN_PROGRESS: 'text-severity-medium border-severity-medium',
  REMEDIATED: 'text-severity-resolved border-severity-resolved',
  RISK_ACCEPTED: 'text-severity-resolved border-severity-resolved',
  FALSE_POSITIVE: 'text-severity-resolved border-severity-resolved',
  WONT_FIX: 'text-severity-resolved border-severity-resolved',
}
