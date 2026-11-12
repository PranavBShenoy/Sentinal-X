"""
Unit tests for finding normalization and fingerprint deduplication.
"""
from app.analysis.normalization.normalizer import FindingNormalizer
from app.models import ConfidenceLevel, FindingSeverity


def test_fingerprint_deterministic_and_stable():
    fp1 = FindingNormalizer.compute_fingerprint(
        source_tool="semgrep",
        rule_id="python.sqlalchemy.sqli",
        location="app/api/users.py:42",
    )
    fp2 = FindingNormalizer.compute_fingerprint(
        source_tool="semgrep",
        rule_id="python.sqlalchemy.sqli",
        location="app/api/users.py:42",
    )
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256


def test_fingerprint_differentiates_distinct_findings():
    fp1 = FindingNormalizer.compute_fingerprint(
        source_tool="semgrep",
        rule_id="python.sqlalchemy.sqli",
        location="app/api/users.py:42",
    )
    fp2 = FindingNormalizer.compute_fingerprint(
        source_tool="semgrep",
        rule_id="python.sqlalchemy.sqli",
        location="app/api/users.py:88",
    )
    assert fp1 != fp2


def test_severity_mapping():
    assert FindingNormalizer.map_severity("CRITICAL") == FindingSeverity.CRITICAL
    assert FindingNormalizer.map_severity("ERROR") == FindingSeverity.HIGH
    assert FindingNormalizer.map_severity("WARNING") == FindingSeverity.MEDIUM
    assert FindingNormalizer.map_severity("INFO") == FindingSeverity.INFO
    assert FindingNormalizer.map_severity("UNKNOWN") == FindingSeverity.MEDIUM


def test_confidence_mapping():
    assert FindingNormalizer.map_confidence("HIGH") == ConfidenceLevel.HIGH
    assert FindingNormalizer.map_confidence("MEDIUM") == ConfidenceLevel.MEDIUM
    assert FindingNormalizer.map_confidence("TENTATIVE") == ConfidenceLevel.LOW
