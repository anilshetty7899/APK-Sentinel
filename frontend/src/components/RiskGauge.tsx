import type { RiskLevel } from '../types/analysis'

interface RiskGaugeProps {
  score: number
  level: RiskLevel
}

const levelColors: Record<RiskLevel, string> = {
  LOW: '#22c55e',
  MODERATE: '#84cc16',
  MEDIUM: '#eab308',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
}

export default function RiskGauge({ score, level }: RiskGaugeProps) {
  const color = levelColors[level] || levelColors.MEDIUM
  const circumference = 2 * Math.PI * 54
  const filled = (score / 100) * circumference
  const offset = circumference - filled

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          {/* Background track */}
          <circle
            cx="60" cy="60" r="54"
            fill="none"
            stroke="#23262f"
            strokeWidth="8"
          />
          {/* Score arc */}
          <circle
            cx="60" cy="60" r="54"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1s ease-out' }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold font-mono" style={{ color }}>
            {Math.round(score)}
          </span>
          <span className="text-[10px] text-sentinel-muted mt-0.5">/ 100</span>
        </div>
      </div>
      <div className="mt-2 text-center">
        <span
          className="text-xs font-semibold tracking-wider uppercase px-3 py-1 rounded border"
          style={{
            color,
            backgroundColor: `${color}15`,
            borderColor: `${color}40`,
          }}
        >
          {level}
        </span>
        <p className="text-[10px] text-sentinel-muted mt-1.5">
          Static Security Risk Score
        </p>
      </div>
    </div>
  )
}
