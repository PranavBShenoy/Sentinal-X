"""
Open Source Vulnerabilities (OSV) Database API Client.

Integrates with the Google OSV API (https://api.osv.dev/v1) to query
up-to-date vulnerability intelligence for open-source software dependencies.
Includes caching, batching, rate-limiting defenses, and safe fallbacks.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

OSV_BASE_URL = "https://api.osv.dev/v1"


@dataclass
class OSVVulnerability:
    """Normalized vulnerability record from OSV."""

    id: str
    summary: str
    details: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    published: Optional[str] = None
    modified: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_ranges: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


class OSVClient:
    """HTTP client for OSV.dev REST API with in-memory caching."""

    def __init__(self, timeout_seconds: int = 15) -> None:
        self.timeout = timeout_seconds
        # In-memory LRU-like cache for session
        self._cache: Dict[str, List[OSVVulnerability]] = {}

    def query_package(
        self,
        name: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        purl: Optional[str] = None,
    ) -> List[OSVVulnerability]:
        """
        Query vulnerabilities for a single package.

        Uses in-memory cache to avoid duplicate remote requests.
        """
        cache_key = purl or f"{ecosystem}:{name}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        payload: Dict[str, Any] = {}
        if purl:
            payload["package"] = {"purl": purl}
        else:
            pkg: Dict[str, Any] = {"name": name}
            if ecosystem:
                pkg["ecosystem"] = ecosystem
            payload["package"] = pkg

        if version:
            payload["version"] = version

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{OSV_BASE_URL}/query", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = self._parse_vulns(data.get("vulns", []))
                    self._cache[cache_key] = vulns
                    return vulns
                elif resp.status_code == 404:
                    self._cache[cache_key] = []
                    return []
                elif resp.status_code == 429:
                    logger.warning("OSV API rate limit encountered", package=name)
                    return []
                else:
                    logger.warning("OSV API returned non-200 status", status=resp.status_code, package=name)
                    return []
        except Exception as e:
            logger.warning("Failed to reach OSV API", error=str(e), package=name)
            return []

    def query_batch(
        self,
        queries: List[Dict[str, Any]],
    ) -> List[List[OSVVulnerability]]:
        """
        Query a batch of packages via POST /v1/querybatch.

        queries: list of dicts with keys e.g. {"package": {"name": ..., "ecosystem": ...}, "version": ...}
        """
        if not queries:
            return []

        try:
            with httpx.Client(timeout=self.timeout * 2) as client:
                resp = client.post(f"{OSV_BASE_URL}/querybatch", json={"queries": queries})
                if resp.status_code == 200:
                    results = resp.json().get("results", [])
                    batch_out = []
                    for item in results:
                        batch_out.append(self._parse_vulns(item.get("vulns", [])))
                    return batch_out
                else:
                    logger.warning("OSV batch query returned status", status=resp.status_code)
                    return [[] for _ in queries]
        except Exception as e:
            logger.warning("Failed to execute OSV batch query", error=str(e))
            return [[] for _ in queries]

    def _parse_vulns(self, raw_list: List[Dict[str, Any]]) -> List[OSVVulnerability]:
        """Convert raw OSV response records into normalized dataclass."""
        out: List[OSVVulnerability] = []
        for v in raw_list:
            vuln_id = v.get("id", "UNKNOWN")
            summary = v.get("summary") or v.get("details", "")[:200]
            details = v.get("details")
            aliases = v.get("aliases", [])

            fixed_versions: List[str] = []
            affected_ranges: List[str] = []

            for aff in v.get("affected", []):
                for r in aff.get("ranges", []):
                    r_type = r.get("type", "")
                    events = r.get("events", [])
                    range_str = f"{r_type}: " + ", ".join(f"{k}={val}" for ev in events for k, val in ev.items())
                    affected_ranges.append(range_str)
                    for ev in events:
                        if "fixed" in ev:
                            fixed_versions.append(ev["fixed"])

            # CVSS / Severity
            severity_str = None
            cvss_score = None
            for sev in v.get("severity", []):
                score_str = sev.get("score")
                if score_str:
                    severity_str = score_str
                    # Parse CVSS score if present
                    if "/" in score_str:
                        # Vector string
                        pass
                    else:
                        try:
                            cvss_score = float(score_str)
                        except ValueError:
                            pass

            references = [ref.get("url") for ref in v.get("references", []) if ref.get("url")]

            out.append(
                OSVVulnerability(
                    id=vuln_id,
                    summary=summary,
                    details=details,
                    aliases=aliases,
                    published=v.get("published"),
                    modified=v.get("modified"),
                    severity=severity_str,
                    cvss_score=cvss_score,
                    affected_ranges=affected_ranges,
                    fixed_versions=fixed_versions,
                    references=references,
                )
            )
        return out
