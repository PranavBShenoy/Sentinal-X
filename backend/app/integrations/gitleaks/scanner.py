"""
Gitleaks Secret Detection Scanner.

Detects hardcoded secrets, tokens, private keys, and credentials.
CRITICAL SECURITY RULE: Never store raw secrets in logs, database, reports, or AI prompts.
Only store masked representations (e.g. 'ghp_****xyz').
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
from app.core.secret_redactor import mask_secret, redact
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


class GitleaksScanner:
    """Wrapper for Gitleaks CLI scanner."""

    def __init__(self, gitleaks_path: Optional[str] = None) -> None:
        self.gitleaks_path = gitleaks_path or settings.GITLEAKS_PATH

    def is_available(self) -> bool:
        """Check if gitleaks is installed and on PATH."""
        return shutil.which(self.gitleaks_path) is not None

    def get_version(self) -> Optional[str]:
        """Get Gitleaks version string."""
        if not self.is_available():
            return None
        res = run_command([self.gitleaks_path, "version"], timeout_seconds=10, tool_name="gitleaks-version")
        if res.succeeded:
            return res.stdout.strip()
        return None

    def scan(
        self,
        assessment_id: str,
        workspace_path: str,
        scan_job_id: Optional[str] = None,
        scan_git_history: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute Gitleaks secret detection on the workspace.

        Handles:
        - Tool availability (CheckStatus.BLOCKED if missing)
        - Subprocess execution without shell interpolation
        - Secret redaction: raw match strings are permanently masked before persisting
        - Remediation instructions for exposed credentials
        """
        if not self.is_available():
            msg = (
                f"Gitleaks binary '{self.gitleaks_path}' is not installed or not found on PATH. "
                "Download from https://github.com/gitleaks/gitleaks or include in container image."
            )
            logger.warning("Gitleaks not available", assessment_id=assessment_id)
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
                "tool": "gitleaks",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        version = self.get_version() or "unknown"
        import tempfile
        output_file = Path(tempfile.gettempdir()) / f"sentinelx_gitleaks_{assessment_id}.json"

        # Build args
        has_git = (Path(workspace_path) / ".git").is_dir()
        args = [
            self.gitleaks_path,
            "detect",
            "--source",
            str(workspace_path),
            "--report-format",
            "json",
            "--report-path",
            str(output_file),
            "--verbose",
        ]

        if not has_git or not scan_git_history:
            args.append("--no-git")

        logger.info("Executing Gitleaks scan", assessment_id=assessment_id, workspace=workspace_path)
        sub_res = run_command(
            args=args,
            timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
            tool_name="gitleaks",
            cwd=workspace_path,
        )

        exec_duration = sub_res.duration_seconds

        if sub_res.timed_out:
            msg = f"Gitleaks scan timed out after {settings.SCANNER_TIMEOUT_SECONDS} seconds."
            logger.error("Gitleaks timed out", assessment_id=assessment_id)
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
            return {"tool": "gitleaks", "status": "TIMED_OUT", "check_status": "ERROR", "findings_count": 0, "error": msg}

        # Gitleaks exit code: 0 = no leaks, 1 = leaks found, 2+ = error
        raw_items: List[Dict[str, Any]] = []
        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        raw_items = json.loads(content)
            except Exception as e:
                logger.error("Failed to parse Gitleaks output", error=str(e))
                msg = f"Malformed Gitleaks JSON: {str(e)}"
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
                return {"tool": "gitleaks", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}
        elif sub_res.exit_code > 1:
            clean_stderr = redact(sub_res.stderr)
            msg = f"Gitleaks execution failed (exit code {sub_res.exit_code}): {clean_stderr[:300]}"
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
            return {"tool": "gitleaks", "status": "FAILED", "check_status": "ERROR", "findings_count": 0, "error": msg}

        # Persist findings with masked secrets
        findings_created = self._persist_findings(
            assessment_id=assessment_id,
            items=raw_items,
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
            "tool": "gitleaks",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": check_st.value,
            "findings_count": findings_created,
            "version": version,
        }

    def _persist_findings(
        self,
        assessment_id: str,
        items: List[Dict[str, Any]],
        workspace_path: str,
    ) -> int:
        """Persist Gitleaks findings into DB, masking all secrets."""
        created_count = 0
        with db_session() as db:
            for item in items:
                rule_id = item.get("RuleID", "exposed-secret")
                desc = item.get("Description", "Exposed Secret Detected")
                file_path = item.get("File", "")
                if workspace_path and file_path.startswith(workspace_path):
                    file_path = os.path.relpath(file_path, workspace_path)

                start_line = item.get("StartLine", 1)
                end_line = item.get("EndLine", start_line)

                # CRITICAL: mask secret match immediately
                raw_match = item.get("Match", "")
                masked_match = mask_secret(raw_match) if raw_match else "[REDACTED_SECRET]"

                # Fingerprint
                fp_src = f"gitleaks:{rule_id}:{file_path}:{start_line}"
                fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()

                existing = (
                    db.query(Finding)
                    .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == fingerprint)
                    .first()
                )
                if existing:
                    existing.last_seen_at = datetime.now(timezone.utc)
                    continue

                remediation_note = (
                    f"1. Revoke and rotate this {desc} immediately in your provider's dashboard.\n"
                    "2. Remove the secret from source code and replace with an environment variable.\n"
                    "3. NOTE: Deleting the secret from the latest commit does NOT remove it from Git history. "
                    "Use git-filter-repo or BFG Repo-Cleaner if the repository has been pushed to a remote."
                )

                finding = Finding(
                    assessment_id=assessment_id,
                    fingerprint=fingerprint,
                    title=f"Exposed Credential: {desc}",
                    description=(
                        f"Detected exposed credential pattern '{rule_id}' in {file_path}:{start_line}. "
                        f"Masked pattern: {masked_match}. Secrets in source code pose immediate takeover risk."
                    ),
                    category=FindingCategory.SECRET,
                    subcategory="EXPOSED_SECRET",
                    severity=FindingSeverity.CRITICAL,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="gitleaks",
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=start_line,
                    line_end=end_line,
                    code_snippet=f"# Secret match (masked for security):\n{masked_match}",
                    raw_evidence={
                        "rule_id": rule_id,
                        "description": desc,
                        "commit": item.get("Commit"),
                        "author": item.get("Author"),
                        "date": item.get("Date"),
                        "masked_match": masked_match,
                        "remediation_note": remediation_note,
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
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "gitleaks")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="gitleaks",
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
