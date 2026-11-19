"""Deterministic scoring for completed runtime evidence."""
from __future__ import annotations
from typing import Any
from app.config import settings
from app.services.scoring import _classify_risk_level

POINTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}


def add_dynamic_score(results: dict[str, Any], findings: list[dict[str, Any]], correlated: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    for finding in findings:
        unique.setdefault(finding["id"], finding)
    dynamic_score = float(min(100, sum(POINTS.get(f.get("severity", "INFO"), 0) for f in unique.values())))
    static = float(results.get("score", {}).get("total", 0))
    w_static, w_dynamic = settings.STATIC_SCORE_WEIGHT, settings.DYNAMIC_SCORE_WEIGHT
    if w_static < 0 or w_dynamic < 0 or abs(w_static + w_dynamic - 1.0) > 0.001:
        raise ValueError("Static and dynamic score weights must be nonnegative and sum to 1")
    weighted_total = round(static * w_static + dynamic_score * w_dynamic, 1)
    # Runtime findings can add risk, but sparse or informational telemetry
    # must not erase risk already established by static evidence.
    final = max(static, weighted_total)
    results.update({
        "dynamic_findings": list(unique.values()),
        "correlated_findings": correlated or [],
        "dynamic_score": {"total": dynamic_score, "finding_count": len(unique)},
        "combined_score": {
            "total": final,
            "weighted_total": weighted_total,
            "static_floor_applied": weighted_total < static,
            "level": _classify_risk_level(final),
            "static_weight": w_static,
            "dynamic_weight": w_dynamic,
        },
        "analysis_coverage": {"static": "COMPLETED", "dynamic": "COMPLETED", "overall": "COMPLETED"},
    })
    results["score"]["static_total"] = static
    results["score"]["dynamic_total"] = dynamic_score
    results["score"]["total"] = final
    results["score"]["level"] = _classify_risk_level(final)
    return results
