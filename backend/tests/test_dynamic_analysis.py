"""Unit checks for deterministic runtime normalization and scoring."""
from app.services.dynamic.dynamic_scoring import add_dynamic_score
from app.services.dynamic.finding_correlator import correlate_findings
from app.services.dynamic.mobsf_normalizer import normalize_report


def test_runtime_score_deduplicates_and_does_not_reduce_static_risk():
    findings = [
        {"id": "same", "severity": "HIGH"},
        {"id": "same", "severity": "HIGH"},
        {"id": "info", "severity": "INFO"},
    ]
    results = {"score": {"total": 40, "level": "MODERATE"}}
    scored = add_dynamic_score(results, findings)
    assert scored["dynamic_score"]["total"] == 15
    assert scored["score"]["total"] == 40
    assert scored["combined_score"]["weighted_total"] == 33.8
    assert scored["combined_score"]["static_floor_applied"] is True
    assert scored["analysis_coverage"]["dynamic"] == "COMPLETED"


def test_runtime_evidence_can_raise_the_combined_score():
    findings = [{"id": f"critical-{i}", "severity": "CRITICAL"} for i in range(4)]
    results = {"score": {"total": 60, "level": "MEDIUM"}}
    scored = add_dynamic_score(results, findings)
    assert scored["dynamic_score"]["total"] == 100
    assert scored["score"]["total"] == 70
    assert scored["combined_score"]["static_floor_applied"] is False


def test_runtime_report_only_normalizes_evidence_and_redacts_secrets():
    findings = normalize_report({
        "urls": ["https://example.test/path?token=abcd"],
        "tls_tests": [{"title": "MobSF cleartext traffic", "severity": "high", "evidence": "Observed HTTP endpoint"}],
    })
    assert len(findings) == 2
    assert "abcd" not in str(findings)
    assert "mobsf" not in str(findings).lower()
    assert {item["severity"] for item in findings} == {"INFO", "HIGH"}


def test_correlation_requires_matching_static_indicator():
    results = {"network_indicators": [{"indicator": "example.test"}]}
    findings = [{"id": "runtime-1", "evidence": {"url": "https://example.test/api"}}]
    normalized, correlated = correlate_findings(results, findings)
    assert normalized[0]["sources"] == ["static", "dynamic"]
    assert correlated[0]["correlated_static_evidence"] == ["example.test"]
