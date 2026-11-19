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
  const [cancelError, setCancelError] = useState<string | null>(null)
  const [cancelRequested, setCancelRequested] = useState(false)

  const cancelScan = async () => {
    if (!id) return
    setCancelError(null)
    setCancelRequested(true)
    try {
      await api.post(`/analyses/${id}/cancel`)
    } catch (e: any) {
      setCancelRequested(false)
      setCancelError(e?.response?.data?.detail || 'Could not cancel this scan')
    }
  }

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
        if (res.data.status === 'FAILED' || res.data.status === 'CANCELLED') {
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
          {(analysis.status === 'QUEUED' || analysis.status === 'RUNNING') && !cancelRequested && (
            <button
              onClick={cancelScan}
              className="mt-3 px-3 py-1.5 rounded border border-red-500/40 text-xs text-red-400 hover:bg-red-500/10"
            >
              Cancel scan
            </button>
          )}
          {cancelRequested && analysis.status !== 'CANCELLED' && (
            <p className="mt-3 text-xs text-sentinel-muted">Cancelling scan…</p>
          )}
          {cancelError && <p className="mt-2 text-xs text-red-400">{cancelError}</p>}
        </div>

        {/* Live scan percentage */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <div className="flex items-center justify-between gap-3 mb-2">
            <span className="text-sm text-sentinel-text font-medium">Estimated scan progress</span>
            <span className="text-sm font-mono text-sentinel-accent">
              {analysis.progress_percent}%
            </span>
          </div>
          <div
            role="progressbar"
            aria-label="APK scan progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={analysis.progress_percent}
            className="h-2 overflow-hidden rounded bg-sentinel-border"
          >
            <div
              className={`h-full rounded transition-all duration-500 ${analysis.status === 'FAILED' ? 'bg-red-500' : analysis.status === 'CANCELLED' ? 'bg-gray-500' : 'bg-sentinel-accent'}`}
              style={{ width: `${Math.max(0, Math.min(100, analysis.progress_percent))}%` }}
            />
          </div>
          <div className="mt-2 text-xs text-sentinel-muted">{analysis.progress_stage}</div>
          <div className="mt-4 space-y-2 border-t border-sentinel-border pt-3">
            {(analysis.progress_tasks || []).map(task => (
              <div key={task.id} className="flex items-center gap-2 text-xs">
                <span className={
                  task.status === 'completed'
                    ? 'text-green-400'
                    : task.status === 'in_progress'
                        ? 'text-sentinel-accent animate-pulse'
                        : task.status === 'failed'
                          ? 'text-red-400'
                          : task.status === 'cancelled'
                            ? 'text-yellow-400'
                            : 'text-sentinel-muted'
                }>
                  {task.status === 'completed' ? '✓' : task.status === 'in_progress' ? '●' : task.status === 'failed' ? '✕' : task.status === 'cancelled' ? '■' : '○'}
                </span>
                <span className={task.status === 'pending' ? 'text-sentinel-muted' : 'text-sentinel-text'}>
                  {task.label}
                </span>
                {(task.status === 'in_progress' || task.status === 'failed' || task.status === 'cancelled') && (
                  <span className="text-sentinel-muted">{task.status.replace('_', ' ')}</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Progress stages */}
        <div className="space-y-0">
          {stages.map((stage, idx) => {
            const isActive = idx === currentIdx
            const isDone = idx < currentIdx || analysis.status === 'COMPLETED'
            const isFailed = (analysis.status === 'FAILED' || analysis.status === 'CANCELLED') && idx === 1

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
        {(analysis.status === 'FAILED' || analysis.status === 'CANCELLED') && analysis.error_message && (
          <div className="mt-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
            {analysis.error_message}
          </div>
        )}
      </div>
    </div>
  )
}
