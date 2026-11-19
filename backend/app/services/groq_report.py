"""Groq LLM integration for AI security report generation.

The LLM receives only structured analysis findings — never raw APK data
or large amounts of decompiled source. It explains the deterministic
results and generates a professional report. It NEVER calculates or
overrides the risk score.

If the Groq API fails, static analysis results and the deterministic
score remain fully available.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.config import settings
from app.utils.logging import logger

SYSTEM_PROMPT = """You are a professional Android security analyst. You are given structured 
static analysis findings from an automated APK scanner. Your role is to EXPLAIN the findings 
and generate a professional security assessment report.

CRITICAL RULES:
1. You MUST NOT calculate, modify, or override the risk score. The score is deterministic and pre-calculated.
2. You MUST clearly distinguish between:
   - OBSERVED FACT: Something directly detected in the APK
   - INTERPRETATION: Your professional analysis of what it could mean
   - POTENTIAL RISK: What could happen if the finding is exploited
3. You MUST NEVER state that an APK is definitively malware based solely on static indicators.
4. You MUST acknowledge the limitations of static analysis.
5. DO NOT include any actual secret values in your report — use only the redacted versions provided.

Generate a JSON report with these sections:
{
  "executive_summary": "2-3 sentence overview",
  "risk_assessment": "Overall risk assessment referencing the pre-calculated score",
  "key_findings": [
    {
      "title": "Finding title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "observed_fact|interpretation|potential_risk",
      "description": "Detailed explanation",
      "evidence": "Specific evidence from the analysis",
      "implication": "What this could mean for security",
      "recommendation": "Suggested action"
    }
  ],
  "security_implications": "Overall security implications discussion",
  "recommended_actions": ["Action 1", "Action 2"],
  "limitations": "Clear statement about static analysis limitations"
}"""


async def generate_report(
    analysis_results: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Generate an AI security report from structured analysis findings.

    Args:
        analysis_results: Scored analysis findings JSON.

    Returns:
        Parsed AI report dict, or None if generation fails.

    Raises:
        Exception: If the Groq API call fails (caller handles gracefully).
    """
    if not settings.GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set — skipping AI report generation")
        return None

    from groq import Groq

    # Prepare a trimmed payload — send findings, not raw source code
    payload = {
        "apk": analysis_results.get("apk", {}),
        "permissions": analysis_results.get("permissions", []),
        "permission_correlations": analysis_results.get("permission_correlations", []),
        "components": analysis_results.get("components", []),
        "component_summary": analysis_results.get("component_summary", {}),
        "suspicious_apis": analysis_results.get("suspicious_apis", []),
        "network_indicators": _truncate_list(
            analysis_results.get("network_indicators", []), max_items=30
        ),
        "potential_secrets": analysis_results.get("potential_secrets", []),
        "obfuscation": analysis_results.get("obfuscation", {}),
        "certificate": analysis_results.get("certificate", {}),
        "score": analysis_results.get("score", {}),
    }

    client = Groq(api_key=settings.GROQ_API_KEY)

    response = client.chat.completions.create(
        model=settings.GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Analyze the following APK static analysis findings and generate "
                    "a professional security assessment report:\n\n"
                    f"```json\n{json.dumps(payload, indent=2)}\n```"
                ),
            },
        ],
        response_format={"type": "json_object"},
        temperature=0.3,
        max_tokens=4096,
    )

    content = response.choices[0].message.content
    if content:
        report = json.loads(content)
        logger.info("AI report generated successfully")
        return report

    return None


def _truncate_list(items: list, max_items: int = 30) -> list:
    """Truncate a list to avoid sending excessive data to the LLM."""
    if len(items) <= max_items:
        return items
    return items[:max_items] + [{"_truncated": f"{len(items) - max_items} more items"}]
