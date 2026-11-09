"""
OSV (Open Source Vulnerabilities) Dependency Scanner.

Uses the official Google osv-scanner binary with native offline databases
to detect known CVEs and security advisories in package dependencies and lockfiles.
Matches findings against SBOM components and records normalized findings.
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


class OSVScanner:
    """Wrapper for Google OSV-Scanner CLI binary."""

    def __init__(self, osv_path: Optional[str] = None) -> None:
        self.osv_path = osv_path or settings.OSV_PATH

    def is_available(self) -> bool:
        """Check if osv-scanner binary is installed and executable."""
        return shutil.which(self.osv_path) is not None

    def get_version(self) -> Optional[str]:
        """Get OSV-Scanner version string."""
        if not self.is_available():
            return None
        res = run_command([self.osv_path, "--version"], timeout_seconds=10, tool_name="osv-version")
        if res.succeeded and res.stdout:
            for line in res.stdout.splitlines():
                if "osv-scanner version:" in line:
                    return line.split(":", 1)[1].strip()
            return res.stdout.splitlines()[0].strip()
        return None

    def scan(
        self,
        assessment_id: str,
        target_path: str,
        scan_job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scan workspace directory or lockfile for known vulnerabilities using osv-scanner.
        """
        if not self.is_available():
            msg = (
                f"OSV-Scanner binary '{self.osv_path}' is not installed or not found on PATH. "
                "Download from https://github.com/google/osv-scanner/releases or install via container image."
            )
            logger.warning("OSV-Scanner not available", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
                execution_time=0.0,
            )
            return {
                "tool": "osv-scanner",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        version = self.get_version() or "unknown"
        target_dir = Path(target_path).parent if os.path.isfile(target_path) else Path(target_path)
        output_file = target_dir / ".sentinelx_osv_output.json"

        # Build command: osv-scanner scan source --offline-vulnerabilities --data-source native --no-resolve --format json --output-file <file> <path>
        args = [
            self.osv_path,
            "scan",
            "source",
            "--offline-vulnerabilities",
            "--data-source",
            "native",
            "--no-resolve",
            "--format",
            "json",
            "--output-file",
            str(output_file),
            str(target_path),
        ]

        logger.info("Executing OSV-Scanner scan", assessment_id=assessment_id, target=target_path)
        sub_res = run_command(
            args=args,
            timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
            tool_name="osv-scanner",
            cwd=str(target_dir),
        )

        exec_duration = sub_res.duration_seconds

        if sub_res.timed_out:
            msg = f"OSV-Scanner scan timed out after {settings.SCANNER_TIMEOUT_SECONDS} seconds."
            logger.error("OSV-Scanner timed out", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.TIMED_OUT,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "osv-scanner", "status": "TIMED_OUT", "check_status": "ERROR", "findings_count": 0, "error": msg}

        combined_output = sub_res.stdout + sub_res.stderr

        # Handle exit code 128: distinguish genuine missing manifest vs extraction errors
        if sub_res.exit_code == 128:
            if "Error during extraction" in combined_output or "could not extract" in combined_output:
                msg = f"OSV-Scanner failed to extract package manifest: {combined_output[:300].strip()}"
                logger.error("OSV extraction failure", error=msg)
                self._record_scan_result(
                    assessment_id=assessment_id,
                    scan_job_id=scan_job_id,
                    status=ScanJobStatus.FAILED,
                    check_status=CheckStatus.ERROR,
                    error_message=msg,
                    execution_time=exec_duration,
                    tool_version=version,
                )
                return {"tool": "osv-scanner", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}
            elif "No package sources found" in combined_output:
                logger.info("OSV-Scanner found no package sources in target", target=target_path)
                self._record_scan_result(
                    assessment_id=assessment_id,
                    scan_job_id=scan_job_id,
                    status=ScanJobStatus.COMPLETED,
                    check_status=CheckStatus.PASSED,
                    tool_version=version,
                    execution_time=exec_duration,
                    findings_count=0,
                )
                return {
                    "tool": "osv-scanner",
                    "status": ScanJobStatus.COMPLETED.value,
                    "check_status": CheckStatus.PASSED.value,
                    "findings_count": 0,
                    "version": version,
                }

        raw_data: Dict[str, Any] = {}
        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        raw_data = json.loads(content)
            except Exception as e:
                msg = f"Failed to parse OSV-Scanner JSON output: {str(e)}"
                logger.error("OSV JSON parse failure", error=str(e))
                self._record_scan_result(
                    assessment_id=assessment_id,
                    scan_job_id=scan_job_id,
                    status=ScanJobStatus.FAILED,
                    check_status=CheckStatus.ERROR,
                    error_message=msg,
                    execution_time=exec_duration,
                    tool_version=version,
                )
                return {"tool": "osv-scanner", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}
        elif sub_res.exit_code not in (0, 1):
            msg = f"OSV-Scanner execution failed (exit code {sub_res.exit_code}): {(sub_res.stdout + sub_res.stderr)[:300]}"
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "osv-scanner", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}

        results = raw_data.get("results", [])
        self._persist_findings(
            assessment_id=assessment_id,
            results=results,
        )

        total_findings = sum(len(p.get("vulnerabilities", [])) for r in results for p in r.get("packages", []))
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
            "tool": "osv-scanner",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": check_st.value,
            "findings_count": total_findings,
            "version": version,
        }

    def _persist_findings(
        self,
        assessment_id: str,
        results: List[Dict[str, Any]],
    ) -> int:
        """Persist OSV vulnerability matches as Finding records and link to SbomComponents."""
        created_count = 0
        with db_session() as db:
            for result_entry in results:
                source_info = result_entry.get("source", {})
                source_path = source_info.get("path", "")

                for pkg_entry in result_entry.get("packages", []):
                    pkg = pkg_entry.get("package", {})
                    pkg_name = pkg.get("name", "unknown-package")
                    pkg_version = pkg.get("version", "")
                    pkg_purl = pkg.get("purl", "")

                    # Map group severity by vulnerability ID
                    group_severity_map: Dict[str, float] = {}
                    for grp in pkg_entry.get("groups", []):
                        max_sev_str = grp.get("max_severity")
                        max_sev_val = None
                        if max_sev_str:
                            try:
                                max_sev_val = float(max_sev_str)
                            except ValueError:
                                pass
                        for gid in grp.get("ids", []) + grp.get("aliases", []):
                            if max_sev_val is not None:
                                group_severity_map[gid] = max(group_severity_map.get(gid, 0.0), max_sev_val)

                    for vuln in pkg_entry.get("vulnerabilities", []):
                        vuln_id = vuln.get("id", "OSV-UNKNOWN")
                        summary = vuln.get("summary") or vuln.get("details", "")[:200]
                        details = vuln.get("details") or summary

                        aliases = vuln.get("aliases", [])
                        cve_ids = [a for a in aliases if a.startswith("CVE-")]
                        if vuln_id.startswith("CVE-") and vuln_id not in cve_ids:
                            cve_ids.append(vuln_id)

                        advisory_ids = [vuln_id] if not vuln_id.startswith("CVE-") else []
                        for a in aliases:
                            if not a.startswith("CVE-") and a not in advisory_ids:
                                advisory_ids.append(a)

                        # Determine CVSS score and severity
                        cvss_score: Optional[float] = None
                        if vuln_id in group_severity_map:
                            cvss_score = group_severity_map[vuln_id]
                        else:
                            for a in aliases:
                                if a in group_severity_map:
                                    cvss_score = group_severity_map[a]
                                    break

                        # Parse from vuln.severity array if not found in groups
                        if cvss_score is None:
                            for sev in vuln.get("severity", []):
                                score_val = sev.get("score")
                                if score_val:
                                    if "/" in score_val:
                                        # CVSS vector string — approximate or inspect CVSS 3.x
                                        pass
                                    else:
                                        try:
                                            cvss_score = float(score_val)
                                            break
                                        except ValueError:
                                            pass

                        # Determine severity tier
                        db_spec = vuln.get("database_specific", {})
                        db_sev = str(db_spec.get("severity", "")).upper()

                        if cvss_score is not None:
                            if cvss_score >= 9.0:
                                severity = FindingSeverity.CRITICAL
                            elif cvss_score >= 7.0:
                                severity = FindingSeverity.HIGH
                            elif cvss_score >= 4.0:
                                severity = FindingSeverity.MEDIUM
                            elif cvss_score > 0.0:
                                severity = FindingSeverity.LOW
                            else:
                                severity = FindingSeverity.INFO
                        elif db_sev in ("CRITICAL",):
                            severity = FindingSeverity.CRITICAL
                        elif db_sev in ("HIGH",):
                            severity = FindingSeverity.HIGH
                        elif db_sev in ("MEDIUM", "MODERATE"):
                            severity = FindingSeverity.MEDIUM
                        elif db_sev in ("LOW",):
                            severity = FindingSeverity.LOW
                        else:
                            severity = FindingSeverity.MEDIUM

                        # Fixed versions extraction
                        fixed_versions: List[str] = []
                        for aff in vuln.get("affected", []):
                            for rng in aff.get("ranges", []):
                                for ev in rng.get("events", []):
                                    if "fixed" in ev:
                                        fixed_versions.append(ev["fixed"])
                        fixed_ver = ", ".join(sorted(set(fixed_versions))) if fixed_versions else None

                        # Fingerprint
                        fp_src = f"osv:{vuln_id}:{pkg_name}:{pkg_version}"
                        fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()

                        existing = (
                            db.query(Finding)
                            .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == fingerprint)
                            .first()
                        )
                        if existing:
                            existing.last_seen_at = datetime.now(timezone.utc)
                            continue

                        finding = Finding(
                            assessment_id=assessment_id,
                            fingerprint=fingerprint,
                            title=f"OSV Advisory: {pkg_name} ({vuln_id})",
                            description=details[:2000] if details else summary,
                            category=FindingCategory.DEPENDENCY,
                            subcategory="KNOWN_CVE" if cve_ids else "SECURITY_ADVISORY",
                            severity=severity,
                            status=FindingStatus.OPEN,
                            confidence=ConfidenceLevel.HIGH,
                            source_tool="osv-scanner",
                            rule_id=vuln_id,
                            component=pkg_name,
                            affected_version=pkg_version,
                            fixed_version=fixed_ver,
                            cvss_score=cvss_score,
                            cve_ids=cve_ids,
                            advisory_ids=advisory_ids,
                            file_path=source_path if source_path else None,
                            raw_evidence={
                                "vuln_id": vuln_id,
                                "package": pkg_name,
                                "version": pkg_version,
                                "purl": pkg_purl,
                                "fixed_in": fixed_ver,
                                "cvss_score": cvss_score,
                                "references": [r.get("url") for r in vuln.get("references", []) if r.get("url")][:5],
                            },
                        )
                        db.add(finding)
                        created_count += 1

                        # Update matching SbomComponent
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
                                        "source": "osv-scanner",
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
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "osv-scanner")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="osv-scanner",
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
