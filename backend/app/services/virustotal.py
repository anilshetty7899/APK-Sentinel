"""Optional VirusTotal hash lookup. This module never uploads APK bytes."""

from __future__ import annotations

from datetime import datetime, timezone
from math import ceil
from typing import Any

import httpx

from app.config import settings
from app.utils.logging import logger


async def lookup_hash(sha256: str) -> dict[str, Any]:
    """Return a normalized public VirusTotal report for a SHA-256, if enabled."""
    if not settings.VIRUSTOTAL_LOOKUP_ENABLED or not settings.VIRUSTOTAL_API_KEY:
        return {"status": "not_configured", "source": "VirusTotal"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
    except httpx.HTTPError as exc:
        logger.warning("VirusTotal hash lookup unavailable | error=%s", str(exc))
        return {"status": "unavailable", "source": "VirusTotal"}

    if response.status_code == 404:
        return {"status": "not_found", "source": "VirusTotal"}
    if response.status_code == 429:
        return {"status": "quota_exceeded", "source": "VirusTotal"}
    if response.status_code in (401, 403):
        logger.warning("VirusTotal hash lookup rejected | status=%s", response.status_code)
        return {"status": "unavailable", "source": "VirusTotal"}
    if response.status_code != 200:
        logger.warning("VirusTotal hash lookup failed | status=%s", response.status_code)
        return {"status": "unavailable", "source": "VirusTotal"}

    try:
        payload = response.json()
        attributes = payload["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        logger.warning("VirusTotal returned an invalid file report")
        return {"status": "unavailable", "source": "VirusTotal"}

    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    detections = [
        {
            "engine": engine,
            "category": item.get("category", "unknown"),
            "result": item.get("result"),
        }
        for engine, item in results.items()
        if item.get("category") in {"malicious", "suspicious"}
    ]
    detections.sort(key=lambda item: (item["category"] != "malicious", item["engine"].lower()))

    reported_sha256 = str(attributes.get("sha256", "")).lower()
    if reported_sha256 and reported_sha256 != sha256.lower():
        logger.warning("VirusTotal hash lookup returned a mismatched SHA-256")
        return {"status": "unavailable", "source": "VirusTotal"}

    date_value = attributes.get("last_analysis_date")
    analysis_date = None
    if isinstance(date_value, (int, float)):
        try:
            analysis_date = datetime.fromtimestamp(date_value, timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            pass

    return {
        "status": "found",
        "source": "VirusTotal",
        "sha256": reported_sha256 or sha256.lower(),
        "last_analysis_date": analysis_date,
        "stats": stats,
        "detections": detections,
        "detection_count": len(detections),
        "total_engines": sum(value for value in stats.values() if isinstance(value, int)),
        "tags": (attributes.get("tags") or [])[:20],
        "names": (attributes.get("names") or [])[:10],
        "threat_classification": attributes.get("popular_threat_classification"),
        "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def build_user_guidance(results: dict[str, Any], reputation: dict[str, Any]) -> dict[str, Any]:
    """Turn scan evidence into a plain-language recommendation and tradeoffs."""
    score = results.get("score", {})
    local_score = float(score.get("total", 0) or 0)
    local_level = str(score.get("level", "LOW"))
    stats = reputation.get("stats") or {}
    vt_malicious = int(stats.get("malicious", 0) or 0)
    vt_suspicious = int(stats.get("suspicious", 0) or 0)
    vt_total = int(reputation.get("total_engines", 0) or 0)
    strong_consensus = vt_malicious >= max(3, ceil(vt_total * 0.05)) if vt_total else False

    if strong_consensus:
        recommendation = "AVOID"
        summary = (
            f"VirusTotal reports {vt_malicious} malicious detections out of {vt_total} engines. "
            "Do not install this APK unless you have a trusted, verified reason."
        )
    elif vt_malicious or vt_suspicious:
        recommendation = "USE CAUTION"
        summary = (
            f"VirusTotal has {vt_malicious} malicious and {vt_suspicious} suspicious detections. "
            "Review the findings and verify the APK source before installing."
        )
    elif local_score >= 61:
        recommendation = "AVOID"
        summary = f"APK Sentinel found substantial static risk ({local_score:.0f}/100). Avoid installing unless you can verify the behavior."
    elif local_score >= 41:
        recommendation = "USE CAUTION"
        summary = f"APK Sentinel found notable static risks ({local_score:.0f}/100). Review the capabilities below before installing."
    else:
        recommendation = "NO MAJOR INDICATORS FOUND"
        summary = "These scans found no major risk indicators. That is not proof that the APK is safe to install."

    pros: list[str] = []
    cons: list[str] = []
    if reputation.get("status") == "found":
        if vt_malicious == 0 and vt_suspicious == 0 and vt_total > 0:
            pros.append(f"No engines flagged this exact file in the saved VirusTotal report ({vt_total} engines checked).")
        else:
            cons.append(f"VirusTotal flagged this exact file: {vt_malicious} malicious, {vt_suspicious} suspicious.")
    permissions = [
        item.get("name", "")
        for item in results.get("permissions", [])
        if item.get("classification") in {"DANGEROUS", "HIGH_RISK", "SPECIAL"}
    ]
    if permissions:
        cons.append("Sensitive permissions requested: " + ", ".join(list(dict.fromkeys(permissions))[:8]) + ".")
    else:
        pros.append("No dangerous or special permissions were identified in the manifest.")

    apis = results.get("suspicious_apis", [])
    behaviors = list(dict.fromkeys(
        str(item.get("matched_api", item.get("category", "sensitive API")))
        for item in apis
    ))
    if behaviors:
        cons.append("Sensitive code/API patterns found: " + ", ".join(behaviors[:8]) + ".")
    else:
        pros.append("No sensitive API patterns were detected by the current static rules.")

    unprotected = int((results.get("component_summary") or {}).get("unprotected_exported", 0) or 0)
    if unprotected:
        cons.append(f"{unprotected} exported component(s) lack permission protection.")
    else:
        pros.append("No unprotected exported components were identified.")

    if results.get("network_indicators"):
        cons.append(
            f"{len(results['network_indicators'])} embedded network indicator(s) were found; their reputation and runtime use were not checked."
        )

    return {
        "recommendation": recommendation,
        "summary": summary,
        "pros": pros,
        "cons": cons,
        "static_score": local_score,
        "static_level": local_level,
        "notice": "This is a risk-based recommendation, not a guarantee of safety. Static analysis does not execute the APK.",
    }
