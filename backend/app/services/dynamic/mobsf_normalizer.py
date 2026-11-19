"""Normalize runtime report evidence into APK-Sentinel finding records."""
from __future__ import annotations
import hashlib
import re
from typing import Any

SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "WARNING": "MEDIUM", "MEDIUM": "MEDIUM", "INFO": "INFO", "LOW": "LOW"}
SECRET = re.compile(r"(?i)(authorization|token|password|secret|api[_-]?key)(\s*[:=]\s*)([^\s,;&]+)")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
URL_CREDENTIALS = re.compile(r"(https?://)[^/@\s]+:[^/@\s]+@", re.I)
QUERY_VALUE = re.compile(r"([?&][^=&#\s]+)=([^&#\s]*)")
INTERNAL_ENGINE_NAME = re.compile(r"(?i)mobile security framework|mobsf(?:-powered)?")


def _clean(value: Any) -> str:
    text = str(value or "")
    text = SECRET.sub(r"\1\2[REDACTED]", text)
    text = URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)
    text = QUERY_VALUE.sub(r"\1=[REDACTED]", text)
    text = EMAIL.sub("[REDACTED_EMAIL]", text)
    text = INTERNAL_ENGINE_NAME.sub("internal analysis service", text)
    return text[:4000]


def normalize_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract only report entries with source text/evidence; deduplicate by stable key."""
    findings: dict[str, dict[str, Any]] = {}
    candidates: list[tuple[str, Any]] = []
    for section in ("findings", "network_security", "behaviour", "behavior", "tls_tests"):
        value = report.get(section)
        if isinstance(value, list):
            candidates.extend((section, item) for item in value)
        elif isinstance(value, dict):
            for key, entries in value.items():
                if isinstance(entries, list):
                    candidates.extend((str(key), item) for item in entries)
                elif isinstance(entries, dict):
                    candidates.append((str(key), entries))
    # The service's report also contains raw runtime telemetry sections.
    # Recording an observed URL/API invocation alone is not a vulnerability, so
    # these are normalized as informational evidence only.
    for section in ("urls", "domains", "droidmon", "apimon", "clipboard"):
        values = report.get(section)
        if isinstance(values, dict):
            values = list(values.items())
        if isinstance(values, list):
            for value in values[:250]:
                if section == "clipboard":
                    candidates.append((section, {"title": "Clipboard access observed", "evidence": "Clipboard content was present; captured content redacted.", "severity": "INFO", "description": "Clipboard data was observed during runtime testing. Its content is redacted and access alone does not establish a vulnerability."}))
                    continue
                if isinstance(value, (str, int, float)):
                    is_http = section == "urls" and str(value).strip().lower().startswith("http://")
                    candidates.append((section, {
                        "title": "Unencrypted HTTP endpoint observed" if is_http else f"Runtime {section.replace('_', ' ')} observation",
                        "evidence": _clean(value),
                        "severity": "MEDIUM" if is_http else "INFO",
                        "description": "An HTTP endpoint was observed at runtime, so this request did not use TLS. The captured report does not establish whether sensitive data was transmitted." if is_http else "This behavior was observed during runtime testing. Observation alone does not establish a vulnerability.",
                        "recommendation": "Use HTTPS for this endpoint and assess the data exchanged." if is_http else "Review this runtime observation in its application context.",
                    }))
                elif isinstance(value, (tuple, list)) and len(value) >= 2:
                    candidates.append((section, {"title": f"Runtime {section.replace('_', ' ')} observation", "evidence": _clean(value), "severity": "INFO", "description": "This behavior was observed during runtime testing. Observation alone does not establish a vulnerability."}))
                elif isinstance(value, dict):
                    value = dict(value)
                    value.setdefault("title", f"Runtime {section.replace('_', ' ')} observation")
                    value.setdefault("severity", "INFO")
                    value.setdefault("description", "This behavior was observed during runtime testing. Observation alone does not establish a vulnerability.")
                    value.setdefault("evidence", value.get("data") or value.get("api") or value.get("url") or value.get("domain") or value.get("value"))
                    candidates.append((section, value))

    for category, item in candidates:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence") or item.get("description") or item.get("issue") or item.get("data")
        title = item.get("title") or item.get("name") or item.get("type")
        if not evidence or not title:
            continue
        severity_raw = str(item.get("severity", "INFO")).upper()
        severity = SEVERITY.get(severity_raw, "INFO")
        raw_evidence = item.get("evidence")
        source = {k: _clean(v) for k, v in item.items() if isinstance(v, (str, int, float))}
        source["evidence"] = _clean(raw_evidence)
        key = hashlib.sha256(f"{category}|{title}|{_clean(evidence)}".encode()).hexdigest()[:16]
        findings[key] = {
            "id": f"dynamic-{key}", "source": "dynamic", "category": category.lower(),
            "title": _clean(title), "severity": severity,
            "confidence": "HIGH" if item.get("evidence") else "MEDIUM",
            "description": _clean(item.get("description") or title), "evidence": source,
            "recommendation": _clean(item.get("recommendation") or item.get("remediation") or "Review this observed runtime behavior."),
        }
    return list(findings.values())
