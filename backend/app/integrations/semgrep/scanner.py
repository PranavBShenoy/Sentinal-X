"""
Semgrep Static Application Security Testing (SAST) Scanner.

Runs Semgrep on target repository workspaces using safe subprocess execution.
If Semgrep is not installed on the system, records CheckStatus.BLOCKED
with clear instructions rather than inventing results or failing silently.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.core.secret_redactor import redact
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


class SemgrepScanner:
    """Wrapper for Semgrep CLI scanner."""

    def __init__(self, semgrep_path: Optional[str] = None) -> None:
        self.semgrep_path = semgrep_path or settings.SEMGREP_PATH

    def is_available(self) -> bool:
        """Check if the semgrep binary is installed and executable."""
        return shutil.which(self.semgrep_path) is not None

    def get_version(self) -> Optional[str]:
        """Get Semgrep version string."""
        if not self.is_available():
            return None
        res = run_command([self.semgrep_path, "--version"], timeout_seconds=10, tool_name="semgrep-version")
        if res.succeeded:
            return res.stdout.strip()
        return None

    def scan(self, assessment_id: str, workspace_path: str, scan_job_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute Semgrep SAST scan on the workspace.

        Handles:
        - Tool availability checks (BLOCKED status if missing)
        - Argument array execution (no shell string formatting)
        - Secret redaction in output and code snippets
        - Normalization to Finding models
        """
        start_time = datetime.now(timezone.utc)

        # 1. Check tool availability
        if not self.is_available():
            msg = (
                f"Semgrep binary '{self.semgrep_path}' is not installed or not found on PATH. "
                "Install via 'pip install semgrep' or ensure it is available in the container environment."
            )
            logger.warning("Semgrep not available", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
                execution_time=0.0,
                findings_count=0,
            )
            return {
                "tool": "semgrep",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        # 1b. Check offline rules availability
        rules_path = settings.SEMGREP_RULES_PATH
        if not os.path.exists(rules_path):
            msg = f"Semgrep bundled rules file '{rules_path}' not found. Offline rules are required for safe execution."
            logger.error("Semgrep rules missing", rules_path=rules_path)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
                execution_time=0.0,
                findings_count=0,
            )
            return {
                "tool": "semgrep",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        version = self.get_version() or "unknown"
        output_file = Path(workspace_path) / ".sentinelx_semgrep_output.json"

        # Build command with explicit bundled rules path
        args = [
            self.semgrep_path,
            "--config",
            rules_path,
            "--json",
            "--output",
            str(output_file),
            "--no-git-ignore",
            "--quiet",
            str(workspace_path),
        ]

        logger.info("Executing Semgrep scan", assessment_id=assessment_id, workspace=workspace_path)
        sub_res = run_command(
            args=args,
            timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
            tool_name="semgrep",
            cwd=workspace_path,
        )

        exec_duration = sub_res.duration_seconds

        if sub_res.timed_out:
            msg = f"Semgrep scan timed out after {settings.SCANNER_TIMEOUT_SECONDS} seconds."
            logger.error("Semgrep timed out", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.TIMED_OUT,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                findings_count=0,
                tool_version=version,
            )
            return {"tool": "semgrep", "status": "TIMED_OUT", "check_status": "ERROR", "findings_count": 0, "error": msg}

        # Semgrep returns 0 on clean/findings, 1 on finding (when --error configured), >1 on crash
        raw_data: Dict[str, Any] = {}
        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
            except Exception as e:
                logger.error("Failed to parse Semgrep JSON output", error=str(e))
                msg = f"Malformed Semgrep JSON output: {str(e)}"
                self._record_scan_result(
                    assessment_id=assessment_id,
                    scan_job_id=scan_job_id,
                    status=ScanJobStatus.FAILED,
                    check_status=CheckStatus.ERROR,
                    error_message=msg,
                    execution_time=exec_duration,
                    findings_count=0,
                    tool_version=version,
                )
                return {"tool": "semgrep", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}
        elif not sub_res.succeeded and sub_res.stderr:
            clean_stderr = redact(sub_res.stderr)
            msg = f"Semgrep execution failed (exit code {sub_res.exit_code}): {clean_stderr[:400]}"
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                findings_count=0,
                tool_version=version,
            )
            return {"tool": "semgrep", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}

        # Parse findings from results
        results = raw_data.get("results", [])
        findings_created = self._persist_findings(
            assessment_id=assessment_id,
            results=results,
            workspace_path=workspace_path,
            raw_output_path=str(output_file) if output_file.exists() else None,
        )

        total_findings = len(results)
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
            "tool": "semgrep",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": check_st.value,
            "findings_count": total_findings,
            "version": version,
            "rules_path": rules_path,
        }

    def _persist_findings(
        self,
        assessment_id: str,
        results: List[Dict[str, Any]],
        workspace_path: str,
        raw_output_path: Optional[str] = None,
    ) -> int:
        """Normalize and persist Semgrep findings into the database."""
        created_count = 0
        with db_session() as db:
            for item in results:
                check_id = item.get("check_id", "semgrep-rule")
                extra = item.get("extra", {})
                message = extra.get("message", "Potential security issue detected")
                semgrep_severity = str(extra.get("severity", "WARNING")).upper()

                # Severity mapping
                if semgrep_severity in ("ERROR", "CRITICAL"):
                    severity = FindingSeverity.HIGH
                elif semgrep_severity == "WARNING":
                    severity = FindingSeverity.MEDIUM
                elif semgrep_severity == "INFO":
                    severity = FindingSeverity.LOW
                else:
                    severity = FindingSeverity.MEDIUM

                path = item.get("path", "")
                # Normalize relative path
                if workspace_path and path.startswith(workspace_path):
                    path = os.path.relpath(path, workspace_path)

                start = item.get("start", {})
                end = item.get("end", {})
                line_start = start.get("line")
                line_end = end.get("line", line_start)

                raw_snippet = extra.get("lines", "")
                if not raw_snippet or raw_snippet == "requires login":
                    full_file_path = Path(workspace_path) / path if workspace_path else Path(path)
                    if full_file_path.exists() and full_file_path.is_file() and line_start:
                        try:
                            with open(full_file_path, "r", encoding="utf-8", errors="ignore") as src_f:
                                all_lines = src_f.readlines()
                                l_start = max(0, line_start - 1)
                                l_end = max(l_start + 1, (line_end or line_start))
                                raw_snippet = "".join(all_lines[l_start:l_end]).strip()
                        except Exception:
                            raw_snippet = ""
                code_snippet = redact(raw_snippet)

                # Subcategory detection from rule id
                subcategory = "SAST_PATTERN"
                rule_lower = check_id.lower()
                if "sql" in rule_lower or "sqli" in rule_lower:
                    subcategory = "SQL_INJECTION"
                elif "xss" in rule_lower:
                    subcategory = "CROSS_SITE_SCRIPTING"
                elif "crypto" in rule_lower or "hash" in rule_lower:
                    subcategory = "INSECURE_CRYPTOGRAPHY"
                elif "traversal" in rule_lower or "path" in rule_lower:
                    subcategory = "PATH_TRAVERSAL"
                elif "exec" in rule_lower or "command" in rule_lower or "eval" in rule_lower:
                    subcategory = "COMMAND_INJECTION"

                # Fingerprint for deduplication
                fp_src = f"semgrep:{check_id}:{path}:{line_start}"
                fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()

                metadata = extra.get("metadata", {})
                cve_list = metadata.get("cve", [])
                if isinstance(cve_list, str):
                    cve_list = [cve_list]

                # Check if finding already exists in this assessment
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
                    title=f"{check_id.split('.')[-1].replace('-', ' ').title()}",
                    description=message,
                    category=FindingCategory.SAST,
                    subcategory=subcategory,
                    severity=severity,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.MEDIUM,
                    source_tool="semgrep",
                    rule_id=check_id,
                    file_path=path,
                    line_start=line_start,
                    line_end=line_end,
                    cve_ids=cve_list,
                    code_snippet=code_snippet if code_snippet else None,
                    raw_evidence={"metadata": metadata, "extra": {k: v for k, v in extra.items() if k != "lines"}},
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
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "semgrep")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="semgrep",
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
