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

// Remediation status is a different axis from severity, but reuses the same
// Badge component/palette rather than introducing a second visual language.
export const REMEDIATION_STATUS_BADGE = {
  OPEN: 'high',
  IN_PROGRESS: 'info',
  REMEDIATED: 'resolved',
  RISK_ACCEPTED: 'info',
  FALSE_POSITIVE: 'resolved',
  WONT_FIX: 'resolved',
}
