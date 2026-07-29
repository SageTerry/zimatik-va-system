import { useEffect, useState } from 'react'
import { deleteCredentials, getCredentials, saveCredentials, testConnection } from '../api/client'
import Card from './Card'
import Badge from './Badge'
import Button from './Button'

function StatusBadge({ configured }) {
  return configured ? (
    <Badge severity="resolved">✓ Configured</Badge>
  ) : (
    <Badge severity="low">✗ Not configured</Badge>
  )
}

function emptyValues(fields) {
  return Object.fromEntries(fields.map((f) => [f.key, '']))
}

// FastAPI returns `detail` as a plain string for HTTPException, but as an
// array of {msg, loc, ...} objects for Pydantic validation errors (422) -
// rendering that array directly as a JSX child crashes React, so normalize
// it to a string first.
function extractErrorMessage(err, fallback) {
  const detail = err.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((d) => d.msg || JSON.stringify(d)).join('; ')
  return err.message || fallback
}

function CredentialCard({ tool, title, description, fields }) {
  const [values, setValues] = useState(() => emptyValues(fields))
  const [configured, setConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testState, setTestState] = useState({ status: 'idle', message: '' })
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    getCredentials(tool)
      .then((data) => {
        if (cancelled) return
        if (data) {
          setConfigured(true)
          setValues((prev) => ({ ...prev, base_url: data.base_url }))
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Failed to load credential status')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [tool])

  function handleChange(key, value) {
    setValues((prev) => ({ ...prev, [key]: value }))
  }

  async function handleSave(e) {
    e.preventDefault()
    setError(null)
    setSaving(true)
    setTestState({ status: 'idle', message: '' })
    try {
      await saveCredentials(tool, {
        base_url: values.base_url,
        api_key: values.api_key,
        api_secret: values.api_secret || null,
      })
      setConfigured(true)
      // The API never echoes keys back - clear them from the form so it
      // doesn't look like the old value is still sitting there.
      setValues((prev) => ({ ...prev, api_key: '', api_secret: '' }))
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to save credentials'))
    } finally {
      setSaving(false)
    }
  }

  async function handleTest() {
    setTestState({ status: 'testing', message: '' })
    try {
      const result = await testConnection(tool)
      setTestState({ status: result.success ? 'success' : 'failed', message: result.message })
    } catch (err) {
      setTestState({
        status: 'failed',
        message: extractErrorMessage(err, 'Test failed'),
      })
    }
  }

  async function handleDelete() {
    if (!window.confirm(`Remove stored ${title} credentials? You'll need to re-enter them to reconnect.`)) {
      return
    }
    setError(null)
    try {
      await deleteCredentials(tool)
      setConfigured(false)
      setTestState({ status: 'idle', message: '' })
      setValues(emptyValues(fields))
    } catch (err) {
      setError(err.message || 'Failed to delete credentials')
    }
  }

  const canSave = !saving && fields.every((f) => !f.required || values[f.key])

  return (
    <Card>
      <div className="mb-1 flex items-center justify-between gap-3">
        <h2 className="font-display text-heading text-ink">{title}</h2>
        <StatusBadge configured={configured} />
      </div>
      <p className="mb-5 font-body text-sm text-ink-2">{description}</p>

      {loading ? (
        <p className="font-body text-sm text-ink-3">Loading…</p>
      ) : (
        <form onSubmit={handleSave} className="space-y-4">
          {fields.map((field) => (
            <div key={field.key}>
              <label className="mb-1 block font-body text-xs uppercase tracking-wide text-ink-3">
                {field.label}
              </label>
              <input
                type={field.secret ? 'password' : 'text'}
                value={values[field.key] ?? ''}
                onChange={(e) => handleChange(field.key, e.target.value)}
                placeholder={field.placeholder}
                autoComplete="off"
                className="radius-b w-full border border-line-strong bg-transparent px-3 py-2 font-body text-sm text-ink focus:border-ink-2 focus:outline-none"
              />
              {field.key !== 'base_url' && configured && (
                <p className="mt-1 font-body text-xs text-ink-3">Not shown for security - re-enter to update.</p>
              )}
            </div>
          ))}

          {error && <p className="font-body text-sm text-severity-high">{error}</p>}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <Button type="submit" variant="primary" disabled={!canSave}>
              {saving ? 'Saving…' : 'Save Credentials'}
            </Button>

            <Button
              type="button"
              variant="secondary"
              onClick={handleTest}
              disabled={!configured || testState.status === 'testing'}
            >
              Test Connection
            </Button>

            {configured && (
              <button
                type="button"
                onClick={handleDelete}
                className="ml-auto font-body text-sm text-severity-high transition-colors hover:text-severity-critical"
              >
                Clear credentials
              </button>
            )}
          </div>

          {testState.status !== 'idle' && (
            <p
              className={`font-body text-sm ${
                testState.status === 'success'
                  ? 'text-severity-resolved'
                  : testState.status === 'failed'
                    ? 'text-severity-high'
                    : 'text-ink-2'
              }`}
            >
              {testState.status === 'testing' && '⏳ Testing connection…'}
              {testState.status === 'success' && `✓ ${testState.message}`}
              {testState.status === 'failed' && `✗ ${testState.message}`}
            </p>
          )}
        </form>
      )}
    </Card>
  )
}

export default function SettingsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-display text-ink">Settings</h1>
        <p className="mt-1 font-body text-ink-2">
          Configure the scanner credentials VACE uses to import findings from Nessus, SonarQube, and ZAP.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <CredentialCard
          tool="NESSUS"
          title="Nessus"
          description="Vulnerability scanner used for network/host findings. Requires an API access key and secret key (Nessus UI: Settings → My Account → API Keys)."
          fields={[
            { key: 'base_url', label: 'Base URL', placeholder: 'https://nessus.internal:8834', required: true },
            { key: 'api_key', label: 'Access Key', required: true },
            { key: 'api_secret', label: 'Secret Key', secret: true, required: true },
          ]}
        />
        <CredentialCard
          tool="SONARQUBE"
          title="SonarQube"
          description="Static analysis scanner used for code-level findings. Requires a user token (SonarQube UI: My Account → Security → Generate Token)."
          fields={[
            { key: 'base_url', label: 'Base URL', placeholder: 'https://sonarqube.internal:9000', required: true },
            { key: 'api_key', label: 'Token', secret: true, required: true },
          ]}
        />
        <CredentialCard
          tool="ZAP"
          title="OWASP ZAP"
          description="Web application scanner used for URL-based findings. Point this at a running ZAP daemon; the API key is optional and only needed if the daemon was started with api.disablekey=false."
          fields={[
            { key: 'base_url', label: 'Base URL', placeholder: 'http://localhost:8090', required: true },
            { key: 'api_key', label: 'API Key (optional)', secret: true, required: false },
          ]}
        />
      </div>
    </div>
  )
}
