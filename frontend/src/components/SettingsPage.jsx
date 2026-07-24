import { useEffect, useState } from 'react'
import { deleteCredentials, getCredentials, saveCredentials, testConnection } from '../api/client'

function StatusBadge({ configured }) {
  return configured ? (
    <span className="inline-flex items-center gap-1 rounded-full border border-green-500/30 bg-green-500/10 px-2.5 py-0.5 text-xs font-semibold text-green-400">
      ✓ Configured
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full border border-gray-600 bg-gray-700/40 px-2.5 py-0.5 text-xs font-semibold text-gray-400">
      ✗ Not configured
    </span>
  )
}

function emptyValues(fields) {
  return Object.fromEntries(fields.map((f) => [f.key, '']))
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
      setError(err.response?.data?.detail || err.message || 'Failed to save credentials')
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
        message: err.response?.data?.detail || err.message || 'Test failed',
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
    <div className="rounded-lg border border-gray-800 bg-gray-800/40 p-6">
      <div className="mb-1 flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        <StatusBadge configured={configured} />
      </div>
      <p className="mb-5 text-sm text-gray-400">{description}</p>

      {loading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : (
        <form onSubmit={handleSave} className="space-y-4">
          {fields.map((field) => (
            <div key={field.key}>
              <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-gray-500">
                {field.label}
              </label>
              <input
                type={field.secret ? 'password' : 'text'}
                value={values[field.key] ?? ''}
                onChange={(e) => handleChange(field.key, e.target.value)}
                placeholder={field.placeholder}
                autoComplete="off"
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
              />
              {field.key !== 'base_url' && configured && (
                <p className="mt-1 text-xs text-gray-500">Not shown for security - re-enter to update.</p>
              )}
            </div>
          ))}

          {error && <p className="text-sm text-red-400">{error}</p>}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              type="submit"
              disabled={!canSave}
              className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save Credentials'}
            </button>

            <button
              type="button"
              onClick={handleTest}
              disabled={!configured || testState.status === 'testing'}
              className="inline-flex items-center gap-2 rounded-md border border-gray-700 px-4 py-2 text-sm font-medium text-gray-200 transition hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Test Connection
            </button>

            {configured && (
              <button
                type="button"
                onClick={handleDelete}
                className="ml-auto text-sm text-red-400 transition hover:text-red-300"
              >
                Clear credentials
              </button>
            )}
          </div>

          {testState.status !== 'idle' && (
            <p
              className={`text-sm ${
                testState.status === 'success'
                  ? 'text-green-400'
                  : testState.status === 'failed'
                    ? 'text-red-400'
                    : 'text-gray-400'
              }`}
            >
              {testState.status === 'testing' && '⏳ Testing connection…'}
              {testState.status === 'success' && `✓ ${testState.message}`}
              {testState.status === 'failed' && `✗ ${testState.message}`}
            </p>
          )}
        </form>
      )}
    </div>
  )
}

export default function SettingsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="mt-1 text-sm text-gray-400">
          Configure the scanner credentials VACE uses to import findings from Nessus and SonarQube.
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
      </div>
    </div>
  )
}
