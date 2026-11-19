import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import api from '../api/client'
import RiskGauge from '../components/RiskGauge'
import ScoreBreakdown from '../components/ScoreBreakdown'
import FindingsTable from '../components/FindingsTable'
import { StatusBadge, SeverityBadge } from '../components/StatusBadge'
import type {
  AnalysisResults as AnalysisResultsType,
  AnalysisReportResponse,
  AnalysisStatus,
  AiReport,
  ScoreContribution,
} from '../types/analysis'

export default function AnalysisResults() {
  const { id } = useParams<{ id: string }>()
  const [status, setStatus] = useState<AnalysisStatus | null>(null)
  const [results, setResults] = useState<AnalysisResultsType | null>(null)
  const [report, setReport] = useState<AnalysisReportResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [showWhyScore, setShowWhyScore] = useState(false)

  useEffect(() => {
    if (!id) return
    Promise.all([
      api.get(`/analyses/${id}`),
      api.get(`/analyses/${id}/results`),
      api.get(`/analyses/${id}/report`),
    ])
      .then(([statusRes, resultsRes, reportRes]) => {
        setStatus(statusRes.data)
        setResults(resultsRes.data)
        setReport(reportRes.data)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-sm text-sentinel-muted">Loading results…</div>
      </div>
    )
  }

  if (!status || !results) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-sm text-red-400">Failed to load analysis results</div>
      </div>
    )
  }

  const r = results.results
  const score = r?.score
  const guidance = r?.user_guidance
  const virustotal = r?.virustotal

  // Collect all contributions for "Why this score?"
  const allContributions: ScoreContribution[] = score
    ? Object.values(score.breakdown).flatMap(cat => cat.contributions)
    : []

  const aiReport = report?.report_available
    ? (report.ai_report as AiReport)
    : null
  const aiError = report?.ai_report && 'error' in report.ai_report
    ? report.ai_report as { error: string; detail: string; note: string }
    : null

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold text-sentinel-text">
            {status.original_filename}
          </h1>
          {r?.apk && (
            <p className="text-xs text-sentinel-muted mt-0.5 font-mono">
              {r.apk.package}
            </p>
          )}
        </div>
        <StatusBadge status={status.status} />
      </div>

      <section className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
        <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">Analysis Coverage</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <MetaItem label="Static Analysis" value="Completed" />
          <MetaItem label="Dynamic Analysis" value={status.dynamic_status.replace('_', ' ')} />
          <MetaItem label="Coverage" value={r?.analysis_coverage?.overall || 'STATIC_ONLY'} />
          {r?.dynamic_score && <MetaItem label="Dynamic Risk Score" value={`${r.dynamic_score.total}/100`} />}
        </div>
        {status.dynamic_error && <p className="mt-3 text-xs text-yellow-400">Dynamic analysis could not be completed: {status.dynamic_error}</p>}
        {r?.dynamic_findings && r.dynamic_findings.length > 0 && (
          <div className="mt-4 space-y-2">
            <h3 className="text-xs font-semibold text-sentinel-text">Runtime Findings ({r.dynamic_findings.length})</h3>
            {r.dynamic_findings.map(f => <article key={f.id} className="rounded bg-sentinel-bg p-3 text-xs">
              <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><strong>{f.title}</strong><span className="text-sentinel-muted">Confidence: {f.confidence}</span></div>
              <p className="mt-2 text-sentinel-muted">{f.description}</p>
              <pre className="mt-2 whitespace-pre-wrap text-[10px] text-sentinel-muted">{JSON.stringify(f.evidence, null, 2)}</pre>
              <p className="mt-2 text-sentinel-accent">{f.recommendation}</p>
            </article>)}
          </div>
        )}
        {r?.correlated_findings && r.correlated_findings.length > 0 && (
          <div className="mt-4 rounded border border-sentinel-accent/30 p-3">
            <h3 className="text-xs font-semibold text-sentinel-accent mb-2">Correlated Static and Runtime Evidence ({r.correlated_findings.length})</h3>
            {r.correlated_findings.map(f => <p key={f.id} className="text-xs text-sentinel-muted">{f.title}: runtime evidence matched an embedded static network indicator.</p>)}
          </div>
        )}
      </section>

      {/* Metadata bar */}
      <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <MetaItem label="SHA-256" value={status.sha256} mono truncate />
          <MetaItem
            label="File Size"
            value={`${(status.file_size / 1024 / 1024).toFixed(2)} MB`}
          />
          <MetaItem
            label="Analyzed"
            value={
              status.completed_at
                ? new Date(status.completed_at).toLocaleString()
                : '—'
            }
          />
          {r?.apk && (
            <MetaItem
              label="Target SDK"
              value={r.apk.target_sdk?.toString() || '—'}
            />
          )}
        </div>
        {r?.apk && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mt-3 pt-3 border-t border-sentinel-border">
            <MetaItem label="Version" value={`${r.apk.version_name || '—'} (${r.apk.version_code || '—'})`} />
            <MetaItem label="Min SDK" value={r.apk.min_sdk?.toString() || '—'} />
            <MetaItem label="Package" value={r.apk.package} mono />
            <MetaItem label="Label" value={r.apk.application_label || '—'} />
          </div>
        )}
      </div>

      {guidance && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <h2 className="text-sm font-semibold text-sentinel-text">Should I install this APK?</h2>
            <span className={`px-2 py-1 rounded border text-xs font-semibold ${
              guidance.recommendation === 'AVOID'
                ? 'text-red-400 border-red-500/40 bg-red-500/10'
                : guidance.recommendation === 'USE CAUTION'
                  ? 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10'
                  : 'text-green-400 border-green-500/40 bg-green-500/10'
            }`}>
              {guidance.recommendation}
            </span>
          </div>
          <p className="text-xs leading-relaxed text-sentinel-text">{guidance.summary}</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div>
              <h3 className="text-xs font-semibold text-green-400 mb-2">Positive signals</h3>
              {guidance.pros.length ? (
                <ul className="space-y-1 text-xs text-sentinel-muted">
                  {guidance.pros.map((item, i) => <li key={i}>• {item}</li>)}
                </ul>
              ) : <p className="text-xs text-sentinel-muted">No positive signals recorded.</p>}
            </div>
            <div>
              <h3 className="text-xs font-semibold text-orange-400 mb-2">Risks to consider</h3>
              {guidance.cons.length ? (
                <ul className="space-y-1 text-xs text-sentinel-muted">
                  {guidance.cons.map((item, i) => <li key={i}>• {item}</li>)}
                </ul>
              ) : <p className="text-xs text-sentinel-muted">No specific concerns were identified by these checks.</p>}
            </div>
          </div>
          <p className="mt-3 pt-3 border-t border-sentinel-border text-[10px] text-sentinel-muted">
            {guidance.notice}
          </p>
        </div>
      )}

      {virustotal && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
              VirusTotal hash report
            </h2>
            {virustotal.status === 'found' && virustotal.report_url && (
              <a href={virustotal.report_url} target="_blank" rel="noopener noreferrer"
                className="text-xs text-sentinel-accent hover:underline">
                Open report ↗
              </a>
            )}
          </div>
          {virustotal.status === 'found' ? (
            <>
              <p className="text-xs text-sentinel-text mb-3">
                Report for this exact SHA-256. Last analyzed: {virustotal.last_analysis_date
                  ? new Date(virustotal.last_analysis_date).toLocaleString()
                  : 'date unavailable'}.
              </p>
              <div className="flex flex-wrap gap-4 text-xs mb-3">
                <span className="text-red-400">Malicious: {virustotal.stats?.malicious ?? 0}</span>
                <span className="text-yellow-400">Suspicious: {virustotal.stats?.suspicious ?? 0}</span>
                <span className="text-green-400">Undetected: {virustotal.stats?.undetected ?? 0}</span>
                <span className="text-sentinel-muted">Engines: {virustotal.total_engines ?? 0}</span>
              </div>
              {(virustotal.threat_classification?.suggested_threat_label ||
                virustotal.threat_classification?.popular_threat_category?.length ||
                virustotal.threat_classification?.popular_threat_name?.length ||
                virustotal.names?.length || virustotal.tags?.length) && (
                <div className="mb-3 space-y-1 text-xs text-sentinel-muted">
                  {virustotal.threat_classification?.suggested_threat_label && (
                    <p>Threat label: {virustotal.threat_classification.suggested_threat_label}</p>
                  )}
                  {!!virustotal.threat_classification?.popular_threat_category?.length && (
                    <p>Categories: {virustotal.threat_classification.popular_threat_category
                      .map(item => `${item.value} (${item.count})`).join(', ')}</p>
                  )}
                  {!!virustotal.threat_classification?.popular_threat_name?.length && (
                    <p>Threat families: {virustotal.threat_classification.popular_threat_name
                      .map(item => `${item.value} (${item.count})`).join(', ')}</p>
                  )}
                  {!!virustotal.names?.length && <p>Known file names: {virustotal.names.join(', ')}</p>}
                  {!!virustotal.tags?.length && <p>Tags: {virustotal.tags.join(', ')}</p>}
                </div>
              )}
              {!!virustotal.detections?.length && (
                <details className="text-xs">
                  <summary className="cursor-pointer text-sentinel-accent">
                    View flagged engines ({virustotal.detection_count})
                  </summary>
                  <div className="mt-2 max-h-48 overflow-y-auto space-y-1">
                    {virustotal.detections.map((detection, i) => (
                      <div key={`${detection.engine}-${i}`} className="flex justify-between gap-3 text-sentinel-muted">
                        <span>{detection.engine}</span>
                        <span className="text-right">{detection.result || detection.category}</span>
                      </div>
                    ))}
                  </div>
                </details>
              )}
              <p className="mt-3 text-[10px] text-sentinel-muted">
                This is VirusTotal’s saved report; it may be older than this APK Sentinel scan.
              </p>
            </>
          ) : (
            <p className="text-xs text-sentinel-muted">
              {virustotal.status === 'not_found'
                ? 'No saved VirusTotal report exists for this hash. APK Sentinel completed its own static scan.'
                : virustotal.status === 'not_configured'
                  ? 'VirusTotal lookup is not configured. APK Sentinel completed its own static scan.'
                  : virustotal.status === 'quota_exceeded'
                    ? 'VirusTotal quota was reached. APK Sentinel completed its own static scan.'
                    : 'VirusTotal could not be reached. APK Sentinel completed its own static scan.'}
            </p>
          )}
        </div>
      )}

      {/* Score + Breakdown */}
      {score && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="bg-sentinel-surface border border-sentinel-border rounded p-6 flex items-center justify-center">
            <RiskGauge score={score.total} level={score.level} />
          </div>
          <div className="md:col-span-2 bg-sentinel-surface border border-sentinel-border rounded p-4">
            <ScoreBreakdown breakdown={score.breakdown} />
            <button
              onClick={() => setShowWhyScore(!showWhyScore)}
              className="mt-4 text-xs text-sentinel-accent hover:underline"
            >
              {showWhyScore ? 'Hide' : 'Show'} "Why this score?" ({allContributions.length} rules)
            </button>
          </div>
        </div>
      )}

      {/* Why this score? */}
      {showWhyScore && allContributions.length > 0 && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <FindingsTable contributions={allContributions} title="Why This Score?" />
        </div>
      )}

      {/* Component Attack Surface */}
      {r?.component_summary && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
            Component Attack Surface
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { label: 'Activities', total: r.component_summary.total_activities, exported: r.component_summary.exported_activities },
              { label: 'Services', total: r.component_summary.total_services, exported: r.component_summary.exported_services },
              { label: 'Receivers', total: r.component_summary.total_receivers, exported: r.component_summary.exported_receivers },
              { label: 'Providers', total: r.component_summary.total_providers, exported: r.component_summary.exported_providers },
            ].map(c => (
              <div key={c.label} className="text-center">
                <div className="text-lg font-bold font-mono text-sentinel-text">{c.total}</div>
                <div className="text-[10px] text-sentinel-muted">{c.label}</div>
                {c.exported > 0 && (
                  <div className="text-[10px] text-yellow-400 mt-0.5">{c.exported} exported</div>
                )}
              </div>
            ))}
            <div className="text-center">
              <div className="text-lg font-bold font-mono text-risk-high">
                {r.component_summary.unprotected_exported}
              </div>
              <div className="text-[10px] text-sentinel-muted">Unprotected</div>
            </div>
          </div>
        </div>
      )}

      {/* Permissions */}
      {r?.permissions && r.permissions.length > 0 && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
            Permissions ({r.permissions.length})
          </h3>
          <div className="space-y-1">
            {r.permissions.map((p, i) => (
              <div key={i} className="flex items-center justify-between py-1 text-xs">
                <span className="font-mono text-sentinel-text">{p.name}</span>
                <SeverityBadge severity={p.classification} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Certificate */}
      {r?.certificate && r.certificate.sha256_fingerprint && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
            Certificate Information
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
            <MetaItem label="SHA-256" value={r.certificate.sha256_fingerprint} mono truncate />
            {r.certificate.sha1_fingerprint && (
              <MetaItem label="SHA-1" value={r.certificate.sha1_fingerprint} mono truncate />
            )}
            {r.certificate.issuer && <MetaItem label="Issuer" value={r.certificate.issuer} />}
            {r.certificate.subject && <MetaItem label="Subject" value={r.certificate.subject} />}
            {r.certificate.signature_scheme && (
              <MetaItem label="Scheme" value={r.certificate.signature_scheme} />
            )}
          </div>
        </div>
      )}

      {/* Network Indicators */}
      {r?.network_indicators && r.network_indicators.length > 0 && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
            Network Indicators ({r.network_indicators.length})
          </h3>
          <div className="max-h-48 overflow-y-auto space-y-1">
            {r.network_indicators.slice(0, 50).map((ni, i) => (
              <div key={i} className="flex items-center justify-between py-1 text-xs">
                <span className="font-mono text-sentinel-text truncate mr-2">{ni.indicator}</span>
                <span className="text-sentinel-muted shrink-0">{ni.type}</span>
              </div>
            ))}
            {r.network_indicators.length > 50 && (
              <div className="text-xs text-sentinel-muted text-center pt-1">
                +{r.network_indicators.length - 50} more
              </div>
            )}
          </div>
        </div>
      )}

      {/* Potential Secrets */}
      {r?.potential_secrets && r.potential_secrets.length > 0 && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
            Potential Hardcoded Secrets ({r.potential_secrets.length})
          </h3>
          <div className="space-y-2">
            {r.potential_secrets.map((s, i) => (
              <div key={i} className="bg-sentinel-bg rounded px-3 py-2 text-xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-orange-400 font-medium">{s.type}</span>
                  <span className="text-sentinel-muted">{s.confidence}</span>
                </div>
                <code className="text-[10px] text-sentinel-muted bg-sentinel-border/50 px-1 py-0.5 rounded">
                  {s.redacted_evidence}
                </code>
                <div className="text-[10px] text-sentinel-muted mt-1">
                  {s.source_file}:{s.line}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Security Assessment */}
      <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
        <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
          AI Security Assessment
        </h3>
        {aiReport ? (
          <div className="space-y-4 text-xs text-sentinel-text">
            <div>
              <h4 className="text-sentinel-muted font-medium mb-1">Executive Summary</h4>
              <p className="leading-relaxed">{aiReport.executive_summary}</p>
            </div>
            <div>
              <h4 className="text-sentinel-muted font-medium mb-1">Risk Assessment</h4>
              <p className="leading-relaxed">{aiReport.risk_assessment}</p>
            </div>
            {aiReport.key_findings?.length > 0 && (
              <div>
                <h4 className="text-sentinel-muted font-medium mb-2">Key Findings</h4>
                <div className="space-y-2">
                  {aiReport.key_findings.map((f, i) => (
                    <div key={i} className="bg-sentinel-bg rounded px-3 py-2">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-medium">{f.title}</span>
                      </div>
                      <p className="text-sentinel-muted leading-relaxed">{f.description}</p>
                      {f.recommendation && (
                        <p className="text-sentinel-accent mt-1">→ {f.recommendation}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {aiReport.recommended_actions?.length > 0 && (
              <div>
                <h4 className="text-sentinel-muted font-medium mb-1">Recommended Actions</h4>
                <ul className="list-disc list-inside text-sentinel-muted space-y-0.5">
                  {aiReport.recommended_actions.map((a, i) => (
                    <li key={i}>{a}</li>
                  ))}
                </ul>
              </div>
            )}
            {aiReport.limitations && (
              <div>
                <h4 className="text-sentinel-muted font-medium mb-1">Limitations</h4>
                <p className="text-sentinel-muted leading-relaxed">{aiReport.limitations}</p>
              </div>
            )}
          </div>
        ) : aiError ? (
          <div className="px-3 py-2 bg-yellow-500/10 border border-yellow-500/30 rounded text-xs text-yellow-400">
            <p className="font-medium">{aiError.error}</p>
            <p className="text-yellow-400/70 mt-0.5">{aiError.note}</p>
          </div>
        ) : (
          <p className="text-xs text-sentinel-muted">
            AI report not available for this analysis.
          </p>
        )}
      </div>

      {/* Disclaimer */}
      <div className="px-4 py-3 bg-sentinel-surface/50 border border-sentinel-border rounded text-[10px] text-sentinel-muted leading-relaxed">
        <strong>Disclaimer:</strong> This report is based on static analysis only. Static analysis
        identifies security indicators and patterns but cannot by itself prove malicious intent.
        Findings represent observed characteristics and potential risks, not confirmed threats.
        The risk score is a deterministic assessment of security indicators and should be
        interpreted in context. The AI assessment explains findings but does not determine the score.
      </div>
    </div>
  )
}

function MetaItem({
  label,
  value,
  mono = false,
  truncate = false,
}: {
  label: string
  value: string
  mono?: boolean
  truncate?: boolean
}) {
  return (
    <div>
      <span className="text-sentinel-muted">{label}: </span>
      <span
        className={`text-sentinel-text ${mono ? 'font-mono' : ''} ${truncate ? 'truncate block' : ''}`}
        title={truncate ? value : undefined}
      >
        {value}
      </span>
    </div>
  )
}
