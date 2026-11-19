import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import api from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import type { AnalysisStatus } from '../types/analysis'

export default function AnalysisProgress() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [analysis, setAnalysis] = useState<AnalysisStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return

    const poll = async () => {
      try {
        const res = await api.get(`/analyses/${id}`)
        setAnalysis(res.data)

        if (res.data.status === 'COMPLETED') {
          navigate(`/analysis/${id}`, { replace: true })
          return
        }
        if (res.data.status === 'FAILED') {
          return // Stay on page to show error
        }
      } catch {
        setError('Failed to fetch analysis status')
        return
      }
    }

    poll()
    const interval = setInterval(poll, 3000)
    return () => clearInterval(interval)
  }, [id, navigate])

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-sm text-red-400">{error}</div>
      </div>
    )
  }

  if (!analysis) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-sm text-sentinel-muted">Loading…</div>
      </div>
    )
  }

  const stages = [
    { key: 'QUEUED', label: 'Queued', desc: 'Waiting to start' },
    { key: 'RUNNING', label: 'Analyzing', desc: 'Decompiling and scanning APK' },
    { key: 'COMPLETED', label: 'Complete', desc: 'Analysis finished' },
  ]

  const currentIdx = stages.findIndex(s => s.key === analysis.status)

  return (
    <div>
      <h1 className="text-lg font-semibold text-sentinel-text mb-5">Analysis Progress</h1>

      <div className="max-w-xl">
        {/* APK info */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-sentinel-text font-medium">
              {analysis.original_filename}
            </span>
            <StatusBadge status={analysis.status} />
          </div>
          <div className="text-xs text-sentinel-muted font-mono">
            SHA-256: {analysis.sha256}
          </div>
        </div>

        {/* Progress stages */}
        <div className="space-y-0">
          {stages.map((stage, idx) => {
            const isActive = idx === currentIdx
            const isDone = idx < currentIdx || analysis.status === 'COMPLETED'
            const isFailed = analysis.status === 'FAILED' && idx === 1

            return (
              <div key={stage.key} className="flex items-start gap-3 relative">
                {/* Connector line */}
                {idx < stages.length - 1 && (
                  <div
                    className={`absolute left-[11px] top-[24px] w-px h-8 ${
                      isDone ? 'bg-green-500' : 'bg-sentinel-border'
                    }`}
                  />
                )}

                {/* Dot */}
                <div className="relative z-10 mt-0.5">
                  <div
                    className={`w-6 h-6 rounded-full border-2 flex items-center justify-center text-xs ${
                      isFailed
                        ? 'border-red-500 bg-red-500/20 text-red-400'
                        : isDone
                          ? 'border-green-500 bg-green-500/20 text-green-400'
                          : isActive
                            ? 'border-sentinel-accent bg-sentinel-accent/20 text-sentinel-accent'
                            : 'border-sentinel-border text-sentinel-muted'
                    }`}
                  >
                    {isFailed ? '✕' : isDone ? '✓' : isActive ? '●' : '○'}
                  </div>
                </div>

                {/* Label */}
                <div className="pb-8">
                  <div
                    className={`text-sm font-medium ${
                      isActive || isDone ? 'text-sentinel-text' : 'text-sentinel-muted'
                    }`}
                  >
                    {stage.label}
                    {isActive && analysis.status === 'RUNNING' && (
                      <span className="ml-2 text-xs text-sentinel-accent animate-pulse">
                        in progress…
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-sentinel-muted">{stage.desc}</div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Error message */}
        {analysis.status === 'FAILED' && analysis.error_message && (
          <div className="mt-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
            {analysis.error_message}
          </div>
        )}
      </div>
    </div>
  )
}
