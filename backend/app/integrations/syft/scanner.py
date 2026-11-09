"""
Syft Software Bill of Materials (SBOM) Generator.

Inventories all software packages, libraries, dependencies, and licenses.
Outputs in standard CycloneDX JSON format and stores component records in the database.
"""
from __future__ import annotations

import json
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
    DependencyEdge,
    SbomArtifact,
    SbomComponent,
    ScanJob,
    ScanJobStatus,
)

logger = get_logger(__name__)
settings = get_settings()


class SyftScanner:
    """Wrapper for Anchore Syft CLI tool."""

    def __init__(self, syft_path: Optional[str] = None) -> None:
        self.syft_path = syft_path or settings.SYFT_PATH

    def is_available(self) -> bool:
        """Check if syft is installed and on PATH."""
        return shutil.which(self.syft_path) is not None

    def get_version(self) -> Optional[str]:
        """Get Syft version string."""
        if not self.is_available():
            return None
        res = run_command([self.syft_path, "version"], timeout_seconds=10, tool_name="syft-version")
        if res.succeeded and res.stdout:
            for line in res.stdout.splitlines():
                if "Version:" in line:
                    return line.split(":", 1)[1].strip()
            return res.stdout.splitlines()[0].strip()[:90]
        return None

    def scan(
        self,
        assessment_id: str,
        workspace_path: str,
        scan_job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate CycloneDX JSON SBOM for the workspace.

        Extracts components, purls, ecosystems, and licenses.
        Persists SbomArtifact and SbomComponent records.
        """
        if not self.is_available():
            msg = (
                f"Syft binary '{self.syft_path}' is not installed or not found on PATH. "
                "Download from https://github.com/anchore/syft or install via brew/apt."
            )
            logger.warning("Syft not available", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
                execution_time=0.0,
            )
            return {
                "tool": "syft",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "component_count": 0,
                "error": msg,
            }

        version = self.get_version() or "unknown"
        output_file = Path(workspace_path) / ".sentinelx_sbom.json"

        # Syft syntax: syft dir:<path> -o cyclonedx-json=<out_file>
        args = [
            self.syft_path,
            f"dir:{workspace_path}",
            f"-o=cyclonedx-json={output_file}",
            "-q",
        ]

        logger.info("Generating SBOM with Syft", assessment_id=assessment_id, workspace=workspace_path)
        sub_res = run_command(
            args=args,
            timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
            tool_name="syft",
            cwd=workspace_path,
        )

        exec_duration = sub_res.duration_seconds

        if sub_res.timed_out:
            msg = f"Syft SBOM generation timed out after {settings.SCANNER_TIMEOUT_SECONDS} seconds."
            logger.error("Syft timed out", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.TIMED_OUT,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "syft", "status": "TIMED_OUT", "check_status": "ERROR", "component_count": 0, "error": msg}

        if not output_file.exists():
            msg = f"Syft did not produce SBOM file: {sub_res.stderr[:300]}"
            logger.error("Syft failed to generate output", assessment_id=assessment_id)
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "syft", "status": "FAILED", "check_status": "ERROR", "component_count": 0, "error": msg}

        # Parse CycloneDX JSON
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
        except Exception as e:
            msg = f"Failed to parse Syft CycloneDX output: {str(e)}"
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.ERROR,
                error_message=msg,
                execution_time=exec_duration,
                tool_version=version,
            )
            return {"tool": "syft", "status": "FAILED", "check_status": "ERROR", "component_count": 0, "error": msg}

        components = sbom_data.get("components", [])
        dependencies = sbom_data.get("dependencies", [])

        # If Syft detected 0 components on directory manifests (e.g. unpinned requirements.txt),
        # use Trivy's native CycloneDX generator to ensure complete SBOM generation
        if not components and shutil.which(settings.TRIVY_PATH):
            trivy_cmd = [
                settings.TRIVY_PATH,
                "fs",
                "--format",
                "cyclonedx",
                "--output",
                str(output_file),
                str(workspace_path),
            ]
            t_res = run_command(trivy_cmd, timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS, tool_name="trivy-cyclonedx", cwd=workspace_path)
            if t_res.succeeded and output_file.exists():
                try:
                    with open(output_file, "r", encoding="utf-8") as f:
                        sbom_data = json.load(f)
                    components = sbom_data.get("components", [])
                    dependencies = sbom_data.get("dependencies", [])
                except Exception:
                    pass

        # Persist SBOM in DB
        artifact_id, comp_count = self._persist_sbom(
            assessment_id=assessment_id,
            tool_version=version[:99] if version else "unknown",
            raw_path=str(output_file),
            components=components,
            dependencies=dependencies,
        )

        self._record_scan_result(
            assessment_id=assessment_id,
            scan_job_id=scan_job_id,
            status=ScanJobStatus.COMPLETED,
            check_status=CheckStatus.PASSED,
            tool_version=version,
            execution_time=exec_duration,
            findings_count=comp_count,
            raw_output_path=str(output_file),
        )

        return {
            "tool": "syft",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": CheckStatus.PASSED.value,
            "sbom_artifact_id": artifact_id,
            "component_count": comp_count,
            "sbom_path": str(output_file),
            "version": version,
        }

    def _persist_sbom(
        self,
        assessment_id: str,
        tool_version: str,
        raw_path: str,
        components: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
    ) -> tuple[str, int]:
        """Save SbomArtifact, SbomComponents, and DependencyEdges in database."""
        with db_session() as db:
            # Create SbomArtifact
            sbom = SbomArtifact(
                assessment_id=assessment_id,
                format="cyclonedx-json",
                tool_name="syft",
                tool_version=tool_version,
                component_count=len(components),
                artifact_path=raw_path,
            )
            db.add(sbom)
            db.flush()

            saved_purls = set()
            for comp in components:
                name = comp.get("name", "unknown")
                version = comp.get("version", "")
                purl = comp.get("purl", f"pkg:generic/{name}@{version}" if version else f"pkg:generic/{name}")

                # Ecosystem from purl: e.g. pkg:npm/... -> npm, pkg:pypi/... -> pypi
                ecosystem = "unknown"
                if purl.startswith("pkg:"):
                    parts = purl[4:].split("/")
                    if parts:
                        ecosystem = parts[0]

                # Extract licenses
                licenses_list = comp.get("licenses", [])
                license_names = []
                for lic in licenses_list:
                    if isinstance(lic, dict):
                        license_info = lic.get("license", {})
                        lic_id = license_info.get("id") or license_info.get("name")
                        if lic_id:
                            license_names.append(lic_id)
                license_expr = ", ".join(license_names) if license_names else None

                supplier = None
                supplier_info = comp.get("supplier", {})
                if isinstance(supplier_info, dict):
                    supplier = supplier_info.get("name")

                component_record = SbomComponent(
                    sbom_id=sbom.id,
                    assessment_id=assessment_id,
                    name=name,
                    version=version if version else None,
                    purl=purl,
                    ecosystem=ecosystem,
                    supplier=supplier,
                    license_expression=license_expr,
                    is_direct=None,  # Will be classified during dependency graph analysis
                )
                db.add(component_record)
                saved_purls.add(purl)

            # Persist dependency graph edges
            for dep in dependencies:
                ref = dep.get("ref", "")
                depends_on = dep.get("dependsOn", [])
                for target_ref in depends_on:
                    edge = DependencyEdge(
                        assessment_id=assessment_id,
                        source_purl=ref,
                        target_purl=target_ref,
                        relationship_type="depends_on",
                    )
                    db.add(edge)

            return str(sbom.id), len(components)

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
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "syft")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="syft",
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
