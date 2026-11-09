"""
Finding Correlation Engine.

Cross-references findings from multiple scanning tools (SAST, Secret, SBOM/Grype, Trivy, DAST)
to consolidate duplicate detections, cross-validate hypotheses, and link source-code usage
to vulnerable third-party dependencies.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from app.core.database import db_session
from app.core.logging import get_logger
from app.models import Finding, FindingCategory, FindingStatus

logger = get_logger(__name__)


class FindingCorrelator:
    """Correlates and deduplicates findings across diverse tools."""

    def correlate(self, assessment_id: str) -> Dict[str, Any]:
        """
        Run multi-tool correlation for an assessment.

        1. Deduplicates identical CVEs reported by both Grype and Trivy.
        2. Links SAST code findings with vulnerable dependencies if the package is referenced.
        3. Annotates correlated findings with cross-tool provenance.
        """
        with db_session() as db:
            findings = (
                db.query(Finding)
                .filter(Finding.assessment_id == assessment_id)
                .all()
            )

            if not findings:
                return {"correlated_count": 0, "deduped_count": 0}

            # Group dependency vulnerabilities by (CVE, component)
            cve_map: Dict[str, List[Finding]] = {}
            for f in findings:
                if f.category == FindingCategory.DEPENDENCY and f.cve_ids:
                    for cve in f.cve_ids:
                        key = f"{cve}:{f.component or ''}".lower()
                        cve_map.setdefault(key, []).append(f)

            deduped_count = 0
            seen_duplicates: Set[str] = set()
            # Consolidate duplicate scanner reports (e.g. Grype, Trivy, and OSV all detecting same CVE on package)
            for key, group in cve_map.items():
                active_in_group = [f for f in group if f.id not in seen_duplicates and f.status != FindingStatus.SUPPRESSED]
                if len(active_in_group) > 1:
                    # Choose primary deterministically
                    primary = active_in_group[0]
                    for duplicate in active_in_group[1:]:
                        seen_duplicates.add(duplicate.id)
                        # Preserve cross-scanner provenance and evidence in primary finding
                        new_evidence = dict(primary.raw_evidence or {})
                        sources = list(new_evidence.get("additional_sources", []))
                        sources.append({
                            "tool": duplicate.source_tool,
                            "rule_id": duplicate.rule_id,
                            "severity": duplicate.severity.value,
                            "cvss_score": duplicate.cvss_score,
                            "evidence": duplicate.raw_evidence,
                        })
                        new_evidence["additional_sources"] = sources
                        primary.raw_evidence = new_evidence

                        # Enrich primary with any better metadata from duplicate
                        if primary.cvss_score is None and duplicate.cvss_score is not None:
                            primary.cvss_score = duplicate.cvss_score
                        if not primary.fixed_version and duplicate.fixed_version:
                            primary.fixed_version = duplicate.fixed_version

                        # Mark duplicate as SUPPRESSED with traceable audit reason
                        duplicate.status = FindingStatus.SUPPRESSED
                        duplicate.suppression_reason = (
                            f"Correlated duplicate of {primary.source_tool} finding {primary.id} "
                            f"(shared vulnerability identifier {key.split(':')[0].upper()})"
                        )
                        deduped_count += 1

            # Correlate SAST file paths with vulnerable components
            sast_findings = [f for f in findings if f.category == FindingCategory.SAST]
            dep_findings = [f for f in findings if f.category == FindingCategory.DEPENDENCY]

            correlated_links = 0
            for dep in dep_findings:
                if not dep.component:
                    continue
                comp_name = dep.component.lower()
                for sast in sast_findings:
                    # If SAST code snippet or file path references the vulnerable component
                    snippet = (sast.code_snippet or "").lower()
                    if comp_name in snippet or f"import {comp_name}" in snippet:
                        correlated_links += 1
                        sast.description = (
                            f"{sast.description}\n\n[Correlation] Code snippet actively references "
                            f"vulnerable dependency '{dep.component}' ({', '.join(dep.cve_ids or [])})."
                        )
                        # Boost confidence
                        sast.confidence = "HIGH"

            return {
                "total_findings": len(findings),
                "deduped_duplicates": deduped_count,
                "sast_dependency_links": correlated_links,
            }
