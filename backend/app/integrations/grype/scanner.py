"""
Grype Dependency Vulnerability Scanner.

Scans Software Bill of Materials (SBOM) or direct filesystems for known CVEs/vulnerabilities.
Matches vulnerable components against security advisories and associates them with SBOM items.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.core.subprocess_utils import run_command
from app.models import (
    CheckStatus,
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    SbomComponent,
    ScanJob,
    ScanJobStatus,
)

logger = get_logger(__name__)
settings = get_settings()


class GrypeScanner:
    """Wrapper for Anchore Grype vulnerability scanner."""

    def __init__(self, grype_path: Optional[str] = None) -> None:
        self.grype_path = grype_path or settings.GRYPE_PATH

    def is_available(self) -> bool:
        """Check if grype is installed and on PATH."""
        return shutil.which(self.grype_path) is not None

    def get_version(self) -> Optional[str]:
        """Get Grype version string."""
        if not self.is_available():
            return None
        res = run_command([self.grype_path, "version"], timeout_seconds=10, tool_name="grype-version")
        if res.succeeded and res.stdout:
            for line in res.stdout.splitlines():
                if "Version:" in line:
                    return line.split(":", 1)[1].strip()
            return res.stdout.splitlines()[0].strip()[:90]
        return None

    def scan(
        self,
        assessment_id: str,
        target_path: str,
        scan_job_id: Optional[str] = None,
        is_sbom: bool = True,
    ) -> Dict[str, Any]:
        """
        Scan SBOM or workspace directory with Grype.

        target_path: Path to SBOM file or workspace directory
        is_sbom: True if target_path points to an SBOM file (e.g. cyclonedx json)
        """
        if not self.is_available():
            msg = (
                f"Grype binary '{self.grype_path}' is not installed or not found on PATH. "
                "Download from https://github.com/anchore/grype or install via container image."
            )
            logger.warning("Grype not available", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
                execution_time=0.0,
            )
            return {
                "tool": "grype",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        version = self.get_version() or "unknown"
        target_dir = Path(target_path).parent if os.path.isfile(target_path) else Path(target_path)
        output_file = target_dir / ".sentinelx_grype_output.json"

        # Build command: grype sbom:<path> -o json --file <output>
        input_target = f"sbom:{target_path}" if is_sbom else f"dir:{target_path}"
        args = [
            self.grype_path,
            input_target,
            "-o",
            "json",
            "--file",
            str(output_file),
            "-q",
        ]

        logger.info("Executing Grype scan", assessment_id=assessment_id, target=input_target)
        sub_res = run_command(
            args=args,
            timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
            tool_name="grype",
            cwd=str(target_dir),
        )

        exec_duration = sub_res.duration_seconds

        if sub_res.timed_out:
            msg = f"Grype scan timed out after {settings.SCANNER_TIMEOUT_SECONDS} seconds."
            logger.error("Grype timed out", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.TIMED_OUT,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "grype", "status": "TIMED_OUT", "check_status": "ERROR", "findings_count": 0, "error": msg}

        raw_data: Dict[str, Any] = {}
        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        raw_data = json.loads(content)
            except Exception as e:
                msg = f"Failed to parse Grype JSON output: {str(e)}"
                self._record_scan_result(
                    assessment_id=assessment_id,
                    scan_job_id=scan_job_id,
                    status=ScanJobStatus.FAILED,
                    check_status=CheckStatus.ERROR,
                    error_message=msg,
                    execution_time=exec_duration,
                    tool_version=version,
                )
                return {"tool": "grype", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}
        elif not sub_res.succeeded:
            msg = f"Grype execution failed (exit code {sub_res.exit_code}): {sub_res.stderr[:300]}"
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "grype", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}

        matches = raw_data.get("matches", [])
        findings_created = self._persist_findings(
            assessment_id=assessment_id,
            matches=matches,
        )

        total_findings = len(matches)
        check_st = CheckStatus.FAILED if total_findings > 0 else CheckStatus.PASSED

        self._record_scan_result(
            assessment_id=assessment_id,
            scan_job_id=scan_job_id,
            status=ScanJobStatus.COMPLETED,
            check_status=check_st,
            tool_version=version,
            execution_time=exec_duration,
            findings_count=total_findings,
            raw_output_path=str(output_file) if output_file.exists() else None,
        )

        return {
            "tool": "grype",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": check_st.value,
            "findings_count": total_findings,
            "version": version,
        }

    def _persist_findings(
        self,
        assessment_id: str,
        matches: List[Dict[str, Any]],
    ) -> int:
        """Persist Grype vulnerability matches as Finding records and link to SbomComponents."""
        created_count = 0
        with db_session() as db:
            for item in matches:
                vuln = item.get("vulnerability", {})
                artifact = item.get("artifact", {})

                vuln_id = vuln.get("id", "VULN-UNKNOWN")
                raw_severity = str(vuln.get("severity", "Medium")).upper()

                # Severity mapping
                if raw_severity == "CRITICAL":
                    severity = FindingSeverity.CRITICAL
                elif raw_severity == "HIGH":
                    severity = FindingSeverity.HIGH
                elif raw_severity in ("MEDIUM", "MODERATE"):
                    severity = FindingSeverity.MEDIUM
                elif raw_severity in ("LOW", "NEGLIGIBLE"):
                    severity = FindingSeverity.LOW
                else:
                    severity = FindingSeverity.INFO

                pkg_name = artifact.get("name", "unknown-package")
                pkg_version = artifact.get("version", "")
                pkg_purl = artifact.get("purl", "")

                # Fix versions
                fix_info = vuln.get("fix", {})
                fix_versions = fix_info.get("versions", [])
                fixed_ver = ", ".join(fix_versions) if fix_versions else None

                # CVSS
                cvss_list = vuln.get("cvss", [])
                cvss_score = None
                if cvss_list and isinstance(cvss_list, list):
                    first_cvss = cvss_list[0]
                    if isinstance(first_cvss, dict):
                        metrics = first_cvss.get("metrics", {})
                        cvss_score = metrics.get("baseScore")

                description = vuln.get("description") or f"Vulnerability {vuln_id} affects {pkg_name} {pkg_version}."

                # Fingerprint
                fp_src = f"grype:{vuln_id}:{pkg_name}:{pkg_version}"
                fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()

                existing = (
                    db.query(Finding)
                    .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == fingerprint)
                    .first()
                )
                if existing:
                    existing.last_seen_at = datetime.now(timezone.utc)
                    continue

                cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else []
                related_vulns = item.get("relatedVulnerabilities", [])
                for rel in related_vulns:
                    rel_id = rel.get("id")
                    if rel_id and rel_id.startswith("CVE-") and rel_id not in cve_ids:
                        cve_ids.append(rel_id)

                finding = Finding(
                    assessment_id=assessment_id,
                    fingerprint=fingerprint,
                    title=f"Vulnerable Dependency: {pkg_name} ({vuln_id})",
                    description=description,
                    category=FindingCategory.DEPENDENCY,
                    subcategory="KNOWN_CVE",
                    severity=severity,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="grype",
                    rule_id=vuln_id,
                    component=pkg_name,
                    affected_version=pkg_version,
                    fixed_version=fixed_ver,
                    cvss_score=cvss_score,
                    cve_ids=cve_ids,
                    advisory_ids=[vuln_id] if not vuln_id.startswith("CVE-") else [],
                    raw_evidence={
                        "vulnerability_id": vuln_id,
                        "package": pkg_name,
                        "version": pkg_version,
                        "purl": pkg_purl,
                        "fixed_in": fixed_ver,
                        "urls": vuln.get("urls", []),
                    },
                )
                db.add(finding)
                created_count += 1

                # Update matching SbomComponent vulnerability matches if present
                if pkg_purl:
                    sbom_comp = (
                        db.query(SbomComponent)
                        .filter(
                            SbomComponent.assessment_id == assessment_id,
                            SbomComponent.purl == pkg_purl,
                        )
                        .first()
                    )
                    if sbom_comp:
                        current_matches = list(sbom_comp.vulnerability_matches or [])
                        if vuln_id not in [m.get("id") for m in current_matches if isinstance(m, dict)]:
                            current_matches.append({
                                "id": vuln_id,
                                "severity": severity.value,
                                "fixed_version": fixed_ver,
                            })
                            sbom_comp.vulnerability_matches = current_matches

        return created_count

    def _record_scan_result(
        self,
        assessment_id: str,
        scan_job_id: Optional[str],
        status: ScanJobStatus,
        check_status: CheckStatus,
        error_message: Optional[str] = None,
        tool_version: Optional[str] = None,
        execution_time: float = 0.0,
        findings_count: int = 0,
        raw_output_path: Optional[str] = None,
    ) -> None:
        """Update or insert ScanJob record."""
        with db_session() as db:
            job = None
            if scan_job_id:
                job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if not job:
                job = (
                    db.query(ScanJob)
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "grype")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="grype",
                )
                db.add(job)

            job.status = status
            job.check_status = check_status
            job.error_message = error_message
            job.tool_version = tool_version[:99] if tool_version else None
            job.execution_time_seconds = execution_time
            job.findings_count = findings_count
            if raw_output_path:
                job.raw_output_path = raw_output_path
            job.completed_at = datetime.now(timezone.utc)
