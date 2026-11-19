import { useState } from 'react'
import { SeverityBadge } from './StatusBadge'
import type { ScoreContribution } from '../types/analysis'

interface FindingsTableProps {
  contributions: ScoreContribution[]
  title?: string
}

export default function FindingsTable({ contributions, title = 'Findings' }: FindingsTableProps) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  if (!contributions.length) {
    return (
      <div className="text-sm text-sentinel-muted py-4 text-center">
        No findings in this category
      </div>
    )
  }

  // Sort by points descending
  const sorted = [...contributions].sort((a, b) => b.points - a.points)

  const toggle = (idx: number) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  return (
    <div>
      <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-2">
        {title} ({sorted.length})
      </h3>
      <div className="border border-sentinel-border rounded overflow-hidden">
        {sorted.map((item, idx) => (
          <div
            key={`${item.rule_id}-${idx}`}
            className="border-b border-sentinel-border last:border-b-0"
          >
            <button
              onClick={() => toggle(idx)}
              className="w-full flex items-center justify-between px-3 py-2 text-left hover:bg-sentinel-hover transition-colors"
            >
              <div className="flex items-center gap-2 min-w-0">
                <SeverityBadge severity={item.severity} />
                <span className="text-xs text-sentinel-text truncate">
                  {item.explanation}
                </span>
              </div>
              <div className="flex items-center gap-2 shrink-0 ml-2">
                <span className="text-xs font-mono text-sentinel-muted">
                  +{item.points}
                </span>
                <span className="text-sentinel-muted text-xs">
                  {expanded.has(idx) ? '▲' : '▼'}
                </span>
              </div>
            </button>
            {expanded.has(idx) && (
              <div className="px-3 pb-2 pt-0 space-y-1 bg-sentinel-bg/50">
                <div className="grid grid-cols-2 gap-x-4 text-[11px]">
                  <div>
                    <span className="text-sentinel-muted">Rule: </span>
                    <span className="font-mono text-sentinel-text">{item.rule_id}</span>
                  </div>
                  <div>
                    <span className="text-sentinel-muted">Category: </span>
                    <span className="text-sentinel-text">{item.category}</span>
                  </div>
                </div>
                {item.evidence && (
                  <div className="text-[11px]">
                    <span className="text-sentinel-muted">Evidence: </span>
                    <code className="text-sentinel-text bg-sentinel-border/50 px-1 py-0.5 rounded text-[10px]">
                      {item.evidence}
                    </code>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
