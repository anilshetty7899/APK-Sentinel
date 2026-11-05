import type { RiskLevel, AnalysisStatusType, Severity } from '../types/analysis'

interface StatusBadgeProps {
  status: AnalysisStatusType
}

const statusStyles: Record<AnalysisStatusType, string> = {
  QUEUED: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
  RUNNING: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  COMPLETED: 'bg-green-500/10 text-green-400 border-green-500/30',
  FAILED: 'bg-red-500/10 text-red-400 border-red-500/30',
  CANCELLED: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-xs font-medium rounded border ${statusStyles[status] || statusStyles.QUEUED}`}
    >
      {status === 'RUNNING' && (
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full mr-1.5 animate-pulse" />
      )}
      {status}
    </span>
  )
}

interface RiskBadgeProps {
  level: RiskLevel | null | undefined
  score?: number | null
}

const riskStyles: Record<RiskLevel, string> = {
  LOW: 'risk-bg-low risk-low',
  MODERATE: 'risk-bg-moderate risk-moderate',
  MEDIUM: 'risk-bg-medium risk-medium',
  HIGH: 'risk-bg-high risk-high',
  CRITICAL: 'risk-bg-critical risk-critical',
}

export function RiskBadge({ level, score }: RiskBadgeProps) {
  if (!level) return <span className="text-xs text-sentinel-muted">—</span>

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded border ${riskStyles[level] || ''}`}
    >
      {score != null && <span className="font-mono">{Math.round(score)}</span>}
      {level}
    </span>
  )
}

interface SeverityBadgeProps {
  severity: Severity | string
}

const severityStyles: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  INFO: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
  HIGH_RISK: 'bg-red-500/10 text-red-400 border-red-500/30',
  DANGEROUS: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  SPECIAL: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  NORMAL: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 text-[11px] font-medium rounded border ${severityStyles[severity] || severityStyles.INFO}`}
    >
      {severity}
    </span>
  )
}
