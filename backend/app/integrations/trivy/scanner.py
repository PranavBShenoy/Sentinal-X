"""
Trivy Filesystem, Dependency, Container, and Configuration Scanner.

Scans the repository for known vulnerabilities and configuration/IaC issues.
Handles both dependency vulnerabilities and Dockerfile/configuration misconfigurations.
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
    ScanJob,
    ScanJobStatus,
)

logger = get_logger(__name__)
settings = get_settings()


class TrivyScanner:
    """Wrapper for Aqua Security Trivy CLI scanner."""

    def __init__(self, trivy_path: Optional[str] = None) -> None:
        self.trivy_path = trivy_path or settings.TRIVY_PATH

    def is_available(self) -> bool:
        """Check if trivy is installed and on PATH."""
        return shutil.which(self.trivy_path) is not None

    def get_version(self) -> Optional[str]:
        """Get Trivy version string."""
        if not self.is_available():
            return None
        res = run_command([self.trivy_path, "--version"], timeout_seconds=10, tool_name="trivy-version")
        if res.succeeded:
            return res.stdout.strip().split("\n")[0]
        return None

    def scan(
        self,
        assessment_id: str,
        workspace_path: str,
        scan_job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute Trivy filesystem scan on the workspace.

        Extracts both Vulnerabilities and Misconfigurations (Dockerfile, YAML, IaC).
        """
        if not self.is_available():
            msg = (
                f"Trivy binary '{self.trivy_path}' is not installed or not found on PATH. "
                "Download from https://github.com/aquasecurity/trivy or install via apt/rpm/brew."
            )
            logger.warning("Trivy not available", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
                execution_time=0.0,
            )
            return {
                "tool": "trivy",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        version = self.get_version() or "unknown"
        output_file = Path(workspace_path) / ".sentinelx_trivy_output.json"

        # Trivy fs scan command
        args = [
            self.trivy_path,
            "fs",
            "--format",
            "json",
            "--output",
            str(output_file),
            "--quiet",
            str(workspace_path),
        ]

        logger.info("Executing Trivy scan", assessment_id=assessment_id, workspace=workspace_path)
        sub_res = run_command(
            args=args,
            timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
            tool_name="trivy",
            cwd=workspace_path,
        )

        exec_duration = sub_res.duration_seconds

        if sub_res.timed_out:
            msg = f"Trivy scan timed out after {settings.SCANNER_TIMEOUT_SECONDS} seconds."
            logger.error("Trivy timed out", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.TIMED_OUT,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "trivy", "status": "TIMED_OUT", "check_status": "ERROR", "findings_count": 0, "error": msg}

        raw_data: Dict[str, Any] = {}
        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        raw_data = json.loads(content)
            except Exception as e:
                msg = f"Failed to parse Trivy JSON output: {str(e)}"
                self._record_scan_result(
                    assessment_id=assessment_id,
                    scan_job_id=scan_job_id,
                    status=ScanJobStatus.FAILED,
                    check_status=CheckStatus.ERROR,
                    error_message=msg,
                    execution_time=exec_duration,
                    tool_version=version,
                )
                return {"tool": "trivy", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}
        elif not sub_res.succeeded:
            msg = f"Trivy execution failed (exit code {sub_res.exit_code}): {sub_res.stderr[:300]}"
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "trivy", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}

        results = raw_data.get("Results", [])
        findings_created = self._persist_findings(
            assessment_id=assessment_id,
            results=results,
            workspace_path=workspace_path,
        )

        check_st = CheckStatus.FAILED if findings_created > 0 else CheckStatus.PASSED

        self._record_scan_result(
            assessment_id=assessment_id,
            scan_job_id=scan_job_id,
            status=ScanJobStatus.COMPLETED,
            check_status=check_st,
            tool_version=version,
            execution_time=exec_duration,
            findings_count=findings_created,
            raw_output_path=str(output_file) if output_file.exists() else None,
        )

        return {
            "tool": "trivy",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": check_st.value,
            "findings_count": findings_created,
            "version": version,
        }

    def _persist_findings(
        self,
        assessment_id: str,
        results: List[Dict[str, Any]],
        workspace_path: str,
    ) -> int:
        """Persist both dependency vulnerabilities and misconfigurations from Trivy."""
        created_count = 0
        with db_session() as db:
            for section in results:
                target = section.get("Target", "")
                if workspace_path and target.startswith(workspace_path):
                    target = os.path.relpath(target, workspace_path)

                target_type = section.get("Type", "")

                # 1. Dependency vulnerabilities
                for vuln in section.get("Vulnerabilities", []) or []:
                    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                    raw_severity = str(vuln.get("Severity", "MEDIUM")).upper()

                    if raw_severity == "CRITICAL":
                        severity = FindingSeverity.CRITICAL
                    elif raw_severity == "HIGH":
                        severity = FindingSeverity.HIGH
                    elif raw_severity == "MEDIUM":
                        severity = FindingSeverity.MEDIUM
                    elif raw_severity == "LOW":
                        severity = FindingSeverity.LOW
                    else:
                        severity = FindingSeverity.INFO

                    pkg_name = vuln.get("PkgName", "unknown-package")
                    installed_ver = vuln.get("InstalledVersion", "")
                    fixed_ver = vuln.get("FixedVersion")

                    fp_src = f"trivy:vuln:{vuln_id}:{pkg_name}:{installed_ver}"
                    fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()

                    # Deduplicate within assessment
                    existing = (
                        db.query(Finding)
                        .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == fingerprint)
                        .first()
                    )
                    if existing:
                        existing.last_seen_at = datetime.now(timezone.utc)
                        continue

                    title = vuln.get("Title") or f"Vulnerability {vuln_id} in {pkg_name}"
                    desc = vuln.get("Description") or f"{pkg_name} {installed_ver} is affected by {vuln_id}."

                    finding = Finding(
                        assessment_id=assessment_id,
                        fingerprint=fingerprint,
                        title=f"{pkg_name}: {title}",
                        description=desc,
                        category=FindingCategory.DEPENDENCY,
                        subcategory="PACKAGE_VULNERABILITY",
                        severity=severity,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="trivy",
                        rule_id=vuln_id,
                        file_path=target,
                        component=pkg_name,
                        affected_version=installed_ver,
                        fixed_version=fixed_ver,
                        cve_ids=[vuln_id] if vuln_id.startswith("CVE-") else [],
                        raw_evidence={
                            "target": target,
                            "type": target_type,
                            "primary_url": vuln.get("PrimaryURL"),
                            "cvss": vuln.get("CVSS"),
                        },
                    )
                    db.add(finding)
                    created_count += 1

                # 2. Misconfigurations (e.g. Dockerfile issues, insecure settings)
                for misconf in section.get("Misconfigurations", []) or []:
                    rule_id = misconf.get("ID", "MISCONF")
                    title = misconf.get("Title", "Configuration Issue")
                    raw_severity = str(misconf.get("Severity", "MEDIUM")).upper()

                    if raw_severity == "CRITICAL":
                        severity = FindingSeverity.CRITICAL
                    elif raw_severity == "HIGH":
                        severity = FindingSeverity.HIGH
                    elif raw_severity == "MEDIUM":
                        severity = FindingSeverity.MEDIUM
                    elif raw_severity == "LOW":
                        severity = FindingSeverity.LOW
                    else:
                        severity = FindingSeverity.INFO

                    fp_src = f"trivy:misconf:{rule_id}:{target}"
                    fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()

                    existing = (
                        db.query(Finding)
                        .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == fingerprint)
                        .first()
                    )
                    if existing:
                        existing.last_seen_at = datetime.now(timezone.utc)
                        continue

                    category = (
                        FindingCategory.CONTAINER
                        if "docker" in target.lower()
                        else FindingCategory.CONFIGURATION
                    )

                    resolution = misconf.get("Resolution", "")
                    desc = misconf.get("Description", "")
                    msg = misconf.get("Message", "")
                    full_desc = f"{title}\n\n{desc}\n\nEvidence: {msg}" if msg else f"{title}\n\n{desc}"

                    finding = Finding(
                        assessment_id=assessment_id,
                        fingerprint=fingerprint,
                        title=f"Misconfiguration: {title}",
                        description=full_desc,
                        category=category,
                        subcategory="SECURITY_MISCONFIGURATION",
                        severity=severity,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="trivy",
                        rule_id=rule_id,
                        file_path=target,
                        raw_evidence={
                            "id": rule_id,
                            "target": target,
                            "resolution": resolution,
                            "message": msg,
                            "references": misconf.get("References", []),
                        },
                    )
                    db.add(finding)
                    created_count += 1

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
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "trivy")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="trivy",
                )
                db.add(job)

            job.status = status
            job.check_status = check_status
            job.error_message = error_message
            job.tool_version = tool_version
            job.execution_time_seconds = execution_time
            job.findings_count = findings_count
            if raw_output_path:
                job.raw_output_path = raw_output_path
            job.completed_at = datetime.now(timezone.utc)
