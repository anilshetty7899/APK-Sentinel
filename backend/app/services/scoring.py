"""Deterministic risk scoring engine.

The LLM NEVER calculates or overrides scores. This engine is the single
source of truth for the Static Security Risk Score.

Scoring weights prioritize code and permission evidence. The result estimates
detected static risk; it is not a safety verdict or malware classification.

Risk levels (project-defined):
  - LOW:      0–20
  - MODERATE: 21–40
  - MEDIUM:   41–60
  - HIGH:     61–80
  - CRITICAL: 81–100
"""

from __future__ import annotations

from typing import Any, Dict, List


def _classify_risk_level(score: float) -> str:
    """Map a 0-100 score to a risk level string."""
    if score <= 20:
        return "LOW"
    elif score <= 40:
        return "MODERATE"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


class ScoringEngine:
    """Deterministic, transparent risk scoring engine.

    Every score contribution is recorded with:
    - rule_id
    - category
    - severity
    - points
    - evidence
    - explanation
    """

    # Category weights (must sum to 1.0)
    WEIGHTS = {
        "permissions": 0.30,
        "code_api": 0.40,
        "components": 0.15,
        "indicators": 0.15,
    }

    # Maximum raw points per category before normalization
    MAX_RAW = {
        "permissions": 100,
        "code_api": 100,
        "components": 100,
        "indicators": 100,
    }

    def calculate_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate a deterministic risk score from analysis findings.

        Args:
            analysis_results: Raw findings JSON from the analyzer container.

        Returns:
            The analysis results dict enriched with a `score` key containing
            total, level, and a full breakdown with every contribution.
        """
        contributions: Dict[str, List[Dict[str, Any]]] = {
            "permissions": [],
            "code_api": [],
            "components": [],
            "indicators": [],
        }

        # ── Score permissions ─────────────────────────────────────────
        self._score_permissions(
            analysis_results.get("permissions", []),
            analysis_results.get("permission_correlations", []),
            contributions["permissions"],
        )

        # ── Score code/API findings ───────────────────────────────────
        self._score_apis(
            analysis_results.get("suspicious_apis", []),
            contributions["code_api"],
        )

        # ── Score component exposure ──────────────────────────────────
        self._score_components(
            analysis_results.get("components", []),
            contributions["components"],
        )

        # ── Score indicators (URLs, secrets, obfuscation) ─────────────
        self._score_indicators(
            analysis_results.get("network_indicators", []),
            analysis_results.get("potential_secrets", []),
            analysis_results.get("obfuscation", {}),
            contributions["indicators"],
        )

        # ── Compute weighted total ────────────────────────────────────
        category_scores = {}
        for cat, weight in self.WEIGHTS.items():
            raw = sum(c["points"] for c in contributions[cat])
            capped = min(raw, self.MAX_RAW[cat])
            normalized = (capped / self.MAX_RAW[cat]) * 100
            weighted = normalized * weight
            category_scores[cat] = {
                "raw_points": raw,
                "capped_points": capped,
                "normalized": round(normalized, 1),
                "weighted": round(weighted, 1),
                "max_raw": self.MAX_RAW[cat],
                "weight": weight,
                "contributions": contributions[cat],
            }

        total = sum(cs["weighted"] for cs in category_scores.values())
        total = min(round(total, 1), 100.0)
        level = _classify_risk_level(total)

        analysis_results["score"] = {
            "total": total,
            "level": level,
            "breakdown": category_scores,
        }

        return analysis_results

    # ── Permission scoring ────────────────────────────────────────────

    PERMISSION_POINTS = {
        "HIGH_RISK": 18,
        "DANGEROUS": 10,
        "SPECIAL": 14,
        "NORMAL": 0,
    }

    def _score_permissions(
        self,
        permissions: List[Dict],
        correlations: List[Dict],
        out: List[Dict],
    ) -> None:
        for perm in permissions:
            classification = perm.get("classification", "NORMAL")
            points = self.PERMISSION_POINTS.get(classification, 1)
            out.append({
                "rule_id": f"PERM_{perm.get('name', 'UNKNOWN')}",
                "category": "permissions",
                "severity": classification,
                "points": points,
                "evidence": perm.get("name", ""),
                "explanation": perm.get("description", f"Permission classified as {classification}"),
            })

        for corr in correlations:
            out.append({
                "rule_id": corr.get("rule_id", "CORR_UNKNOWN"),
                "category": "permissions",
                "severity": corr.get("severity", "HIGH"),
                "points": corr.get("points", 8),
                "evidence": corr.get("evidence", ""),
                "explanation": corr.get("description", "Suspicious permission combination"),
            })

    # ── Code/API scoring ──────────────────────────────────────────────

    API_SEVERITY_POINTS = {
        "CRITICAL": 25,
        "HIGH": 16,
        "MEDIUM": 8,
        "LOW": 2,
        "INFO": 0,
    }

    API_BEHAVIOR_POINTS = {
        "SMS": 10, "TELEPHONY": 6, "AUDIO": 10, "CAMERA": 6,
        "LOCATION": 6, "DYNAMIC_CODE_LOADING": 12,
        "PROCESS_EXECUTION": 12, "REFLECTION": 4,
    }

    def _score_apis(self, apis: List[Dict], out: List[Dict]) -> None:
        # JADX and APKTool can report the same API many times across call
        # sites, wrappers, and bundled libraries. Keep occurrence evidence,
        # but score each distinct API once so repetition cannot dominate the
        # total by itself.
        grouped: Dict[tuple[str, str], Dict[str, Any]] = {}
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for api in apis:
            category = api.get("category", "UNKNOWN")
            matched_api = api.get("matched_api", "unknown")
            key = (category, matched_api)
            group = grouped.setdefault(key, {
                "category": category,
                "matched_api": matched_api,
                "severity": api.get("severity", "MEDIUM"),
                "explanation": api.get("explanation", ""),
                "locations": [],
            })
            severity = api.get("severity", "MEDIUM")
            if severity_rank.get(severity, 2) > severity_rank.get(group["severity"], 2):
                group["severity"] = severity
            location = f"{api.get('file', 'unknown')}:{api.get('line', '?')}"
            if location not in group["locations"]:
                group["locations"].append(location)

        seen_behaviors = set()
        for api in grouped.values():
            severity = api.get("severity", "MEDIUM")
            category = api.get("category", "UNKNOWN")
            points = self.API_SEVERITY_POINTS.get(severity, 3)
            if category not in seen_behaviors:
                points += self.API_BEHAVIOR_POINTS.get(category, 0)
                seen_behaviors.add(category)
            out.append({
                "rule_id": f"API_{category}_{api.get('matched_api', 'unknown')}",
                "category": "code_api",
                "severity": severity,
                "points": points,
                "occurrences": len(api["locations"]),
                "evidence": (
                    f"{api.get('matched_api', '')} found in {len(api['locations'])} locations: "
                    + ", ".join(api["locations"][:3])
                ),
                "explanation": api.get("explanation", f"Security-sensitive API usage: {api.get('matched_api', '')}"),
            })

    # ── Component scoring ─────────────────────────────────────────────

    def _score_components(self, components: List[Dict], out: List[Dict]) -> None:
        for comp in components:
            if comp.get("exported") and not comp.get("permission_protected"):
                out.append({
                    "rule_id": f"COMP_EXPORTED_UNPROTECTED_{comp.get('type', 'unknown')}",
                    "category": "components",
                    "severity": "HIGH",
                    "points": 16,
                    "evidence": f"{comp.get('type', 'component')}: {comp.get('name', 'unknown')}",
                    "explanation": f"Exported {comp.get('type', 'component')} without permission protection",
                })
            elif comp.get("exported"):
                out.append({
                    "rule_id": f"COMP_EXPORTED_{comp.get('type', 'unknown')}",
                    "category": "components",
                    "severity": "MEDIUM",
                    "points": 5,
                    "evidence": f"{comp.get('type', 'component')}: {comp.get('name', 'unknown')}",
                    "explanation": f"Exported {comp.get('type', 'component')} (permission protected)",
                })

    # ── Indicator scoring ─────────────────────────────────────────────

    def _score_indicators(
        self,
        network: List[Dict],
        secrets: List[Dict],
        obfuscation: Dict,
        out: List[Dict],
    ) -> None:
        # Secrets are high-value indicators
        for secret in secrets:
            out.append({
                "rule_id": f"SECRET_{secret.get('type', 'unknown')}",
                "category": "indicators",
                "severity": "HIGH",
                "points": 12,
                "evidence": secret.get("redacted_evidence", "[REDACTED]"),
                "explanation": f"Potential hardcoded secret: {secret.get('type', 'unknown')}",
            })

        # Network indicators scored mildly (presence alone isn't malicious)
        if network:
            out.append({
                "rule_id": "NET_INDICATORS_PRESENT",
                "category": "indicators",
                "severity": "LOW",
                "points": min(2 + len(network), 12),
                "evidence": f"{len(network)} network indicators found",
                "explanation": "Embedded network destinations are present; their reputation and runtime use are not verified",
            })

        # Obfuscation score contributes to indicators
        obf_score = obfuscation.get("score", 0)
        if obf_score > 60:
            out.append({
                "rule_id": "OBF_HIGH",
                "category": "indicators",
                "severity": "MEDIUM",
                "points": 12,
                "evidence": f"Obfuscation score: {obf_score}/100",
                "explanation": "High obfuscation level detected (note: legitimate apps also use R8/ProGuard)",
            })
        elif obf_score > 30:
            out.append({
                "rule_id": "OBF_MODERATE",
                "category": "indicators",
                "severity": "LOW",
                "points": 3,
                "evidence": f"Obfuscation score: {obf_score}/100",
                "explanation": "Moderate obfuscation detected",
            })
