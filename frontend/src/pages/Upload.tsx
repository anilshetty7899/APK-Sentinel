import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'

export default function Upload() {
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [enableDynamic, setEnableDynamic] = useState(false)
  const [dynamicAvailable, setDynamicAvailable] = useState(false)
  const [dynamicConfigured, setDynamicConfigured] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const MAX_SIZE_MB = 100

  useEffect(() => {
    api.get('/health')
      .then(res => {
        setDynamicAvailable(Boolean(res.data?.dynamic_analysis_available))
        setDynamicConfigured(Boolean(res.data?.dynamic_analysis_configured))
      })
      .catch(() => {
        setDynamicAvailable(false)
        setDynamicConfigured(false)
      })
  }, [])

  const validateFile = (f: File): string | null => {
    if (!f.name.toLowerCase().endsWith('.apk')) {
      return 'Only .apk files are accepted'
    }
    if (f.size > MAX_SIZE_MB * 1024 * 1024) {
      return `File exceeds maximum size of ${MAX_SIZE_MB} MB`
    }
    if (f.size === 0) {
      return 'File is empty'
    }
    return null
  }

  const handleFile = (f: File) => {
    const err = validateFile(f)
    if (err) {
      setError(err)
      setFile(null)
      return
    }
    setError(null)
    setFile(f)
  }

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }, [])

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(true)
  }, [])

  const onDragLeave = useCallback(() => setDragging(false), [])

  const handleUpload = async () => {
    if (!file) return
    setUploading(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)
    formData.append('enable_dynamic_analysis', String(enableDynamic))

    try {
      const res = await api.post('/analyses', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      navigate(`/analysis/${res.data.id}/progress`)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail || 'Upload failed'
      setError(msg)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div>
      <h1 className="text-lg font-semibold text-sentinel-text mb-5">Upload APK</h1>

      <div className="max-w-xl">
        {/* Drop zone */}
        <div
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          className={`border-2 border-dashed rounded-lg p-10 text-center transition-colors cursor-pointer ${
            dragging
              ? 'border-sentinel-accent bg-sentinel-accent/5'
              : 'border-sentinel-border hover:border-sentinel-muted'
          }`}
          onClick={() => document.getElementById('file-input')?.click()}
        >
          <div className="text-3xl mb-2 opacity-40">⬆</div>
          <p className="text-sm text-sentinel-text mb-1">
            Drop an APK file here or click to browse
          </p>
          <p className="text-xs text-sentinel-muted">
            .apk files only · max {MAX_SIZE_MB} MB
          </p>
          <input
            id="file-input"
            type="file"
            accept=".apk"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) handleFile(f)
            }}
          />
        </div>

        <label className={`mt-4 flex items-start gap-3 rounded border border-sentinel-border bg-sentinel-surface p-4 ${dynamicAvailable ? 'cursor-pointer' : 'cursor-not-allowed opacity-70'}`}>
          <input type="checkbox" checked={enableDynamic} disabled={!dynamicAvailable} onChange={e => setEnableDynamic(e.target.checked)} className="mt-0.5 accent-blue-500" />
          <span>
            <span className="block text-sm text-sentinel-text">Enable Dynamic Analysis</span>
            <span className="mt-1 block text-xs text-sentinel-muted">
              {dynamicAvailable
                ? 'Runs the app in a configured Android runtime. An available isolated device is required.'
                : dynamicConfigured
                  ? 'The runtime service is configured. Dynamic scans remain disabled until an Android emulator or device is connected.'
                  : 'Dynamic runtime service is not configured. Static analysis remains available.'}
            </span>
          </span>
        </label>

        {/* Error */}
        {error && (
          <div className="mt-3 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
            {error}
          </div>
        )}

        {/* File info */}
        {file && !error && (
          <div className="mt-4 bg-sentinel-surface border border-sentinel-border rounded p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-sentinel-text font-medium truncate">
                {file.name}
              </span>
              <button
                onClick={() => setFile(null)}
                className="text-xs text-sentinel-muted hover:text-red-400 transition-colors"
              >
                Remove
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-sentinel-muted">Size: </span>
                <span className="text-sentinel-text font-mono">
                  {(file.size / 1024 / 1024).toFixed(2)} MB
                </span>
              </div>
              <div>
                <span className="text-sentinel-muted">Type: </span>
                <span className="text-sentinel-text font-mono">
                  {file.type || 'application/octet-stream'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Upload button */}
        {file && !error && (
          <button
            onClick={handleUpload}
            disabled={uploading}
            className="mt-4 w-full py-2.5 bg-sentinel-accent text-white text-sm font-medium rounded
                       hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {uploading ? 'Uploading…' : 'Analyze APK'}
          </button>
        )}

        {/* Disclaimer */}
        <p className="mt-4 text-[10px] text-sentinel-muted leading-relaxed">
          Static analysis only. Uploaded APKs are not installed or executed.
          The APK is decoded and decompiled inside an isolated container for analysis.
        </p>
      </div>
    </div>
  )
}
