import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getFindingById } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import { REMEDIATION_STATUS_STYLES, SEVERITY_STYLES } from '../lib/constants'

function Field({ label, value }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-200">{value}</dd>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-800/40 p-6">
      <h2 className="mb-4 text-lg font-semibold text-white">{title}</h2>
      {children}
    </div>
  )
}

export default function FindingDetail() {
  // Keyed by id so navigating between findings remounts this view instead of
  // reusing state: loading/error/finding all start fresh instead of needing
  // to be reset imperatively inside the effect.
  const { id } = useParams()
  return <FindingDetailView key={id} id={id} />
}

function FindingDetailView({ id }) {
  const navigate = useNavigate()
  const [finding, setFinding] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    getFindingById(id)
      .then((data) => {
        if (!cancelled) setFinding(data)
      })
      .catch((err) => {
        if (!cancelled) {
          setError(
            err.response?.status === 404 ? 'Finding not found.' : err.message || 'Failed to load finding',
          )
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [id])

  const backButton = (
    <button
      onClick={() => navigate('/findings')}
      className="inline-flex items-center gap-1.5 text-sm text-gray-400 transition hover:text-gray-200"
    >
      ← Back to findings
    </button>
  )

  if (loading) {
    return (
      <div className="space-y-4">
        {backButton}
        <div className="flex h-64 items-center justify-center text-gray-400">Loading finding…</div>
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div className="space-y-4">
        {backButton}
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-red-300">
          {error || 'Finding not found.'}
        </div>
      </div>
    )
  }

  const severityStyle = SEVERITY_STYLES[finding.severity_normalized] ?? SEVERITY_STYLES.INFO
  const statusStyle = REMEDIATION_STATUS_STYLES[finding.remediation_status] ?? REMEDIATION_STATUS_STYLES.OPEN

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        {backButton}
        <div className="flex flex-wrap gap-3">
          <ReportDownloadButton
            label="Export as PDF"
            getPayload={() => ({ finding_ids: [finding.id] })}
          />
          <ReportDownloadButton
            label="Export Full Scan Report"
            getPayload={() => ({ scan_id: finding.scan_id })}
            className="inline-flex items-center gap-2 rounded-md border border-gray-700 px-4 py-2 text-sm font-medium text-gray-400 transition hover:border-gray-600 hover:text-gray-200 disabled:cursor-not-allowed disabled:opacity-50"
          />
        </div>
      </div>

      <div>
        <div className="flex flex-wrap items-center gap-3">
          <span
            className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${severityStyle.bg} ${severityStyle.text} ${severityStyle.border}`}
          >
            {finding.severity_normalized}
          </span>
          <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${statusStyle}`}>
            {finding.remediation_status.replace(/_/g, ' ')}
          </span>
          {finding.is_duplicate && (
            <span className="inline-flex items-center rounded-full border border-gray-600 bg-gray-700/40 px-3 py-1 text-xs font-semibold text-gray-300">
              Duplicate
            </span>
          )}
        </div>
        <h1 className="mt-3 text-2xl font-bold text-white">{finding.title}</h1>
        <p className="mt-1 text-sm text-gray-400">
          {finding.tool_source} · reported {new Date(finding.created_at).toLocaleString()}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Section title="Description">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-300">
              {finding.description || 'No description provided.'}
            </p>
          </Section>

          <Section title="Evidence">
            <dl className="space-y-4">
              <Field label="Detection Method" value={finding.detection_method} />
              <Field
                label="Confidence"
                value={finding.confidence != null ? `${Math.round(finding.confidence * 100)}%` : null}
              />
              <Field label="False Positive Risk" value={finding.false_positive_risk} />
              {finding.proof_of_concept && (
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                    Proof of Concept
                  </dt>
                  <dd className="mt-1">
                    <pre className="whitespace-pre-wrap break-words rounded-md bg-gray-950 p-3 text-xs text-gray-300">
                      {finding.proof_of_concept}
                    </pre>
                  </dd>
                </div>
              )}
            </dl>
          </Section>

          <Section title="Remediation">
            <dl className="space-y-4">
              <Field label="Recommended Fix" value={finding.recommended_fix} />
              <Field label="Effort Level" value={finding.effort_level} />
              <Field label="Mitigation" value={finding.mitigation} />
              <Field label="Business Context" value={finding.business_context} />
            </dl>
          </Section>
        </div>

        <div className="space-y-6">
          <Section title="Location">
            <dl className="space-y-4">
              <Field label="Type" value={finding.location_type} />
              <Field label="Host" value={finding.host} />
              <Field label="Service" value={finding.service} />
              <Field label="Port" value={finding.port} />
              <Field label="Code File" value={finding.code_file} />
              <Field label="Code Line" value={finding.code_line} />
              <Field label="URL" value={finding.url} />
              <Field label="Parameter" value={finding.parameter} />
            </dl>
          </Section>

          <Section title="Identity & Scoring">
            <dl className="space-y-4">
              <Field label="CVE" value={finding.cve_id} />
              <Field label="CWE" value={finding.cwe_id} />
              <Field label="OWASP Category" value={finding.owasp_category} />
              <Field label="CVSS v3" value={finding.cvss_v3} />
              <Field label="CVSS v4" value={finding.cvss_v4} />
              <Field label="EPSS Score" value={finding.epss_score} />
            </dl>
          </Section>

          <Section title="Metadata">
            <dl className="space-y-4">
              <Field label="Finding ID" value={finding.id} />
              <Field label="Scan ID" value={finding.scan_id} />
              <Field label="Native ID" value={finding.tool_finding_id} />
              <Field label="Tags" value={finding.tags?.length > 0 ? finding.tags.join(', ') : null} />
              <Field label="Last Updated" value={new Date(finding.updated_at).toLocaleString()} />
            </dl>
          </Section>
        </div>
      </div>
    </div>
  )
}
