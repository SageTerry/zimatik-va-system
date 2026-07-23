import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { getStats } from '../api/client'
import { SEVERITY_ORDER, SEVERITY_STYLES } from '../lib/constants'

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-800/40 p-6">
      <p className="text-sm font-medium uppercase tracking-wide text-gray-400">{label}</p>
      <p className={`mt-2 text-3xl font-bold ${accent ?? 'text-white'}`}>{value}</p>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    getStats()
      .then((data) => {
        if (!cancelled) setStats(data)
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Failed to load stats')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <div className="flex h-64 items-center justify-center text-gray-400">Loading dashboard…</div>
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-red-300">
        Failed to load stats: {error}
      </div>
    )
  }

  const chartData = SEVERITY_ORDER.map((severity) => ({
    name: severity,
    value: stats.by_severity?.[severity] ?? 0,
    color: SEVERITY_STYLES[severity].chart,
  })).filter((entry) => entry.value > 0)

  const toolEntries = Object.entries(stats.by_tool ?? {})

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Overview</h1>
        <p className="mt-1 text-sm text-gray-400">
          Consolidated vulnerability posture across all connected scanners.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Findings" value={stats.total_findings} />
        <StatCard label="Affected Hosts" value={stats.affected_hosts} />
        <StatCard
          label="Critical + High"
          value={(stats.by_severity?.CRITICAL ?? 0) + (stats.by_severity?.HIGH ?? 0)}
          accent="text-red-400"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="rounded-lg border border-gray-800 bg-gray-800/40 p-6 lg:col-span-2">
          <h2 className="mb-4 text-lg font-semibold text-white">Findings by Severity</h2>
          {chartData.length === 0 ? (
            <p className="text-gray-500">No findings recorded yet.</p>
          ) : (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius="55%"
                    outerRadius="80%"
                    paddingAngle={2}
                  >
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
                    itemStyle={{ color: '#e5e7eb' }}
                    labelStyle={{ color: '#9ca3af' }}
                  />
                  <Legend
                    itemSorter={false}
                    formatter={(value) => <span className="text-gray-300">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-800/40 p-6">
          <h2 className="mb-4 text-lg font-semibold text-white">By Severity</h2>
          <ul className="space-y-3">
            {SEVERITY_ORDER.map((severity) => {
              const count = stats.by_severity?.[severity] ?? 0
              const style = SEVERITY_STYLES[severity]
              return (
                <li key={severity} className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm text-gray-300">
                    <span className={`h-2.5 w-2.5 rounded-full ${style.dot}`} />
                    {severity}
                  </span>
                  <span className={`font-semibold ${style.text}`}>{count}</span>
                </li>
              )
            })}
          </ul>

          {toolEntries.length > 0 && (
            <>
              <h2 className="mb-3 mt-6 text-lg font-semibold text-white">By Tool</h2>
              <ul className="space-y-2">
                {toolEntries.map(([tool, count]) => (
                  <li key={tool} className="flex items-center justify-between text-sm">
                    <span className="text-gray-300">{tool}</span>
                    <span className="font-semibold text-white">{count}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>

      <Link
        to="/findings"
        className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-500"
      >
        View all findings →
      </Link>
    </div>
  )
}
