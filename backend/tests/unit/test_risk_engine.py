"""
Unit tests for deterministic risk scoring and rationale generation.
"""
from app.analysis.risk.engine import RiskEngine
from app.models import (
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
)


def test_critical_finding_risk_score():
    engine = RiskEngine()
    f = Finding(
        title="Unauthenticated Remote Code Execution",
        category=FindingCategory.SAST,
        severity=FindingSeverity.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        cvss_score=9.8,
    )
    score, rationale = engine.score_finding(f)
    assert score >= 9.0
    assert "CVSS v3 base score (9.8)" in rationale


def test_low_severity_finding_risk_score():
    engine = RiskEngine()
    f = Finding(
        title="Server Banner Disclosed",
        category=FindingCategory.DAST,
        severity=FindingSeverity.LOW,
        confidence=ConfidenceLevel.HIGH,
    )
    score, rationale = engine.score_finding(f)
    assert score <= 4.0
    assert "LOW severity" in rationale


def test_direct_vs_transitive_dependency_weight():
    engine = RiskEngine()
    f = Finding(
        title="Vulnerable Component",
        category=FindingCategory.DEPENDENCY,
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        cvss_score=8.0,
    )

    score_direct, _ = engine.score_finding(f, is_direct_dep=True)
    score_transitive, _ = engine.score_finding(f, is_direct_dep=False)

    assert score_direct > score_transitive
    assert score_direct == 8.0  # 8.0 * 1.0 * 1.0
    assert score_transitive == 6.4  # 8.0 * 0.8 * 1.0


def test_exposed_secret_multiplier():
    engine = RiskEngine()
    f = Finding(
        title="Exposed AWS Access Key",
        category=FindingCategory.SECRET,
        severity=FindingSeverity.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
    )
    score, rationale = engine.score_finding(f)
    assert score == 10.0  # capped at 10.0 (9.0 * 1.25 = 11.25 -> 10.0)
    assert "Exposed plaintext secret" in rationale


def test_confidence_weighting():
    engine = RiskEngine()
    f_high = Finding(
        title="SQLi Pattern",
        category=FindingCategory.SAST,
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceLevel.HIGH,
    )
    f_low = Finding(
        title="SQLi Pattern",
        category=FindingCategory.SAST,
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceLevel.LOW,
    )

    score_high, _ = engine.score_finding(f_high)
    score_low, _ = engine.score_finding(f_low)

    assert score_high > score_low
