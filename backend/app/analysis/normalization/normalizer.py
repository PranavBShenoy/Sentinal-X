"""
Finding Normalization Service.

Transforms scanner-specific result schemas into the unified Finding data model.
Computes stable deduplication fingerprints across rescans.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from app.models import (
    ConfidenceLevel,
    FindingSeverity,
)


class FindingNormalizer:
    """Normalizes raw scanner outputs into the standard SENTINEL-X Finding schema."""

    @staticmethod
    def compute_fingerprint(
        source_tool: str,
        rule_id: str,
        location: str,
        secondary_id: Optional[str] = None,
    ) -> str:
        """
        Compute a stable SHA-256 fingerprint for a finding.
        Used to track finding status and deduplicate across repeated scans.
        """
        raw = f"{source_tool.lower()}:{rule_id.lower()}:{location.strip().lower()}"
        if secondary_id:
            raw += f":{secondary_id.strip().lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def map_severity(raw_severity: str) -> FindingSeverity:
        """Map heterogeneous scanner severity strings to unified FindingSeverity."""
        val = raw_severity.strip().upper()
        if val in ("CRITICAL", "BLOCKER"):
            return FindingSeverity.CRITICAL
        elif val in ("HIGH", "ERROR"):
            return FindingSeverity.HIGH
        elif val in ("MEDIUM", "MODERATE", "WARNING", "WARN"):
            return FindingSeverity.MEDIUM
        elif val in ("LOW", "NOTICE", "NOTE"):
            return FindingSeverity.LOW
        elif val in ("INFO", "INFORMATIONAL", "NEGLIGIBLE"):
            return FindingSeverity.INFO
        return FindingSeverity.MEDIUM

    @staticmethod
    def map_confidence(raw_confidence: str) -> ConfidenceLevel:
        """Map scanner confidence levels."""
        val = raw_confidence.strip().upper()
        if val in ("HIGH", "CERTAIN"):
            return ConfidenceLevel.HIGH
        elif val in ("MEDIUM", "LIKELY"):
            return ConfidenceLevel.MEDIUM
        elif val in ("LOW", "TENTATIVE"):
            return ConfidenceLevel.LOW
        return ConfidenceLevel.UNKNOWN
