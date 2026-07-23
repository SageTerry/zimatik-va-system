// Shared display config for VACE's normalized enums (see backend app/models/finding.py).

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export const SEVERITY_STYLES = {
  CRITICAL: {
    text: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    dot: 'bg-red-500',
    chart: '#ef4444',
  },
  HIGH: {
    text: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    dot: 'bg-orange-500',
    chart: '#f97316',
  },
  MEDIUM: {
    text: 'text-yellow-400',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    dot: 'bg-yellow-500',
    chart: '#eab308',
  },
  LOW: {
    text: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    dot: 'bg-blue-500',
    chart: '#3b82f6',
  },
  INFO: {
    text: 'text-gray-400',
    bg: 'bg-gray-500/10',
    border: 'border-gray-500/30',
    dot: 'bg-gray-500',
    chart: '#6b7280',
  },
}

export const TOOL_OPTIONS = ['NESSUS', 'SONARQUBE', 'ZAP']

export const REMEDIATION_STATUS_STYLES = {
  OPEN: 'text-red-300 bg-red-500/10 border-red-500/30',
  IN_PROGRESS: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30',
  REMEDIATED: 'text-green-300 bg-green-500/10 border-green-500/30',
  RISK_ACCEPTED: 'text-purple-300 bg-purple-500/10 border-purple-500/30',
  FALSE_POSITIVE: 'text-gray-300 bg-gray-500/10 border-gray-500/30',
  WONT_FIX: 'text-gray-400 bg-gray-600/10 border-gray-600/30',
}
