"""Link runtime observations to matching static network indicators."""
from __future__ import annotations
from typing import Any


def correlate_findings(static_results: dict[str, Any], runtime_findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    indicators = [str(item.get("indicator", "")).lower() for item in static_results.get("network_indicators", []) if isinstance(item, dict)]
    correlated: list[dict[str, Any]] = []
    output = []
    for finding in runtime_findings:
        evidence_text = " ".join(str(v) for v in finding.get("evidence", {}).values()).lower()
        matches = [indicator for indicator in indicators if indicator and indicator in evidence_text]
        item = dict(finding)
        if matches:
            item["correlated_static_evidence"] = matches
            item["sources"] = ["static", "dynamic"]
            correlated.append(item)
        output.append(item)
    return output, correlated
