import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getFindingById } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Card from './Card'
import Badge from './Badge'
import { REMEDIATION_STATUS_BADGE, SEVERITY_BADGE } from '../lib/constants'
import { ChevronLeftIcon } from '../lib/icons'

function Field({ label, value }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div>
      <dt className="font-body text-xs uppercase tracking-wide text-ink-3">{label}</dt>
      <dd className="mt-1 font-body text-sm text-ink">{value}</dd>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <Card>
      <h2 className="mb-4 font-display text-heading text-ink">{title}</h2>
      {children}
    </Card>
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
      className="inline-flex cursor-pointer items-center gap-1.5 font-body text-sm font-medium text-ink-2 transition-colors hover:text-ink"
    >
      <ChevronLeftIcon size={16} strokeWidth={2.5} />
      Back to findings
    </button>
  )

  if (loading) {
    return (
      <div className="space-y-4">
        {backButton}
        <div className="flex h-64 items-center justify-center font-body text-ink-2">Loading finding…</div>
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div className="space-y-4">
        {backButton}
        <div className="radius-a border border-severity-high p-6 font-body text-severity-high">
          {error || 'Finding not found.'}
        </div>
      </div>
    )
  }

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
          />
        </div>
      </div>

      <div>
        <div className="flex flex-wrap items-center gap-3">
          <Badge severity={SEVERITY_BADGE[finding.severity_normalized] ?? 'info'}>
            {finding.severity_normalized}
          </Badge>
          <Badge severity={REMEDIATION_STATUS_BADGE[finding.remediation_status] ?? 'info'}>
            {finding.remediation_status.replace(/_/g, ' ')}
          </Badge>
          {finding.is_duplicate && <Badge severity="low">Duplicate</Badge>}
        </div>
        <h1 className="mt-3 font-display text-display text-ink">{finding.title}</h1>
        <p className="mt-1 font-body text-ink-2">
          {finding.tool_source} · reported {new Date(finding.created_at).toLocaleString()}
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Section title="Description">
            <p className="whitespace-pre-wrap font-body text-sm leading-relaxed text-ink-2">
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
                  <dt className="font-body text-xs uppercase tracking-wide text-ink-3">Proof of Concept</dt>
                  <dd className="mt-1">
                    <pre className="radius-b whitespace-pre-wrap break-words border border-line bg-sunken p-3 font-body text-xs text-ink-2">
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
