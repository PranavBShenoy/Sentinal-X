"""
Assessment Pipeline Orchestrator.

Drives the end-to-end execution of a SENTINEL-X security assessment:
1. REPOSITORY_FETCH & ANALYSIS
2. STATIC_SCANS (Semgrep, Gitleaks, Trivy)
3. SBOM_GENERATION (Syft)
4. DEPENDENCY_ANALYSIS (Grype & OSV)
5. RUNTIME_PROVISIONING (Docker isolated environment or user staging URL)
6. DYNAMIC_TESTING (OWASP ZAP & Native DAST checks)
7. CORRELATION_AND_RISK (Finding correlation, NetworkX graph, risk scoring)
8. AI_ANALYSIS (OpenRouter explanations)
9. REPORT_GENERATION (PDF, JSON, SARIF)

Supports partial completion (e.g., successful static scans even when runtime fails).
Guarantees resource cleanup in all termination paths.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.analysis.correlation.correlator import FindingCorrelator
from app.analysis.dependency_graph.builder import DependencyGraphBuilder
from app.analysis.risk.engine import RiskEngine
from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.integrations.gitleaks.scanner import GitleaksScanner
from app.integrations.grype.scanner import GrypeScanner
from app.integrations.openrouter.client import OpenRouterClient
from app.integrations.osv.scanner import OSVScanner
from app.integrations.semgrep.scanner import SemgrepScanner
from app.integrations.syft.scanner import SyftScanner
from app.integrations.trivy.scanner import TrivyScanner
from app.integrations.zap.scanner import ZapScanner
from app.models import (
    Assessment,
    AssessmentStatus,
    CheckStatus,
    RuntimeStatus,
    ScanJob,
    ScanJobStatus,
)
from app.reporting.generator import ReportGenerator
from app.runtime.docker.orchestrator import RuntimeOrchestrator
from app.services.repository_service import RepositoryService

logger = get_logger(__name__)
settings = get_settings()


def _assessment_scan_options(config: Any) -> Dict[str, bool]:
    """Normalize persisted module selections, preserving old full-scan behavior."""
    values = config if isinstance(config, dict) else {}
    defaults = {
        "enable_sast": True,
        "enable_secrets": True,
        "enable_sbom": True,
        "enable_deps": True,
        "enable_runtime": True,
        "enable_active_dast": False,
    }
    return {key: values.get(key, default) is True for key, default in defaults.items()}


class AssessmentPipeline:
    """Coordinates all scanner stages, correlation, scoring, and reports."""

    def __init__(self, assessment_id: str, request_id: str = None, authz_component=None) -> None:
        self.assessment_id = assessment_id
        self.request_id = request_id
        self.repo_service = RepositoryService()
        self.semgrep = SemgrepScanner()
        self.gitleaks = GitleaksScanner()
        self.syft = SyftScanner()
        self.grype = GrypeScanner()
        self.osv = OSVScanner()
        self.trivy = TrivyScanner()
        self.zap = ZapScanner()
        self.runtime_orch = RuntimeOrchestrator(authz_component=authz_component)
        self.correlator = FindingCorrelator()
        self.graph_builder = DependencyGraphBuilder()
        self.risk_engine = RiskEngine()
        self.ai_client = OpenRouterClient()
        self.report_gen = ReportGenerator()

    def execute(self) -> Dict[str, Any]:
        """Run the complete assessment pipeline."""
        logger.info("Executing assessment pipeline", assessment_id=self.assessment_id)
        workspace_path: Optional[str] = None
        has_partial_failures = False
        target_url: Optional[str] = None

        try:
            with db_session() as db:
                assessment = db.query(Assessment).filter(Assessment.id == self.assessment_id).first()
                stored_config = assessment.config if assessment and isinstance(assessment.config, dict) else {}
                scan_options = _assessment_scan_options(stored_config)

            self._set_status(AssessmentStatus.REPOSITORY_FETCH, "REPOSITORY_FETCH")

            # -----------------------------------------------------------
            # Stage 1: Fetch Repository Source
            # -----------------------------------------------------------
            fetch_res = self.repo_service.fetch(self.assessment_id)
            workspace_path = fetch_res["workspace_path"]
            logger.info("Repository fetched", commit=fetch_res.get("commit_sha"), workspace=workspace_path)

            # -----------------------------------------------------------
            # Stage 2: Repository Analysis
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.REPOSITORY_ANALYSIS, "REPOSITORY_ANALYSIS")

            # -----------------------------------------------------------
            # Stage 3: Static Code & Secret Analysis
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.STATIC_SCANS, "STATIC_SCANS")

            # Semgrep SAST
            if scan_options["enable_sast"]:
                semgrep_res = self.semgrep.scan(self.assessment_id, workspace_path)
                if semgrep_res.get("check_status") in (CheckStatus.BLOCKED.value, CheckStatus.ERROR.value):
                    has_partial_failures = True
                trivy_res = self.trivy.scan(self.assessment_id, workspace_path)
                if trivy_res.get("check_status") in (CheckStatus.BLOCKED.value, CheckStatus.ERROR.value):
                    has_partial_failures = True
            else:
                self._record_skipped_job("semgrep", "SAST was disabled for this assessment.")
                self._record_skipped_job("trivy", "SAST and configuration scanning were disabled for this assessment.")

            # Gitleaks Secret Detection
            if scan_options["enable_secrets"]:
                gitleaks_res = self.gitleaks.scan(self.assessment_id, workspace_path)
                if gitleaks_res.get("check_status") in (CheckStatus.BLOCKED.value, CheckStatus.ERROR.value):
                    has_partial_failures = True
            else:
                self._record_skipped_job("gitleaks", "Secret detection was disabled for this assessment.")

            # -----------------------------------------------------------
            # Stage 4: SBOM Generation
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.SBOM_GENERATION, "SBOM_GENERATION")
            sbom_path = None
            if scan_options["enable_sbom"]:
                syft_res = self.syft.scan(self.assessment_id, workspace_path)
                sbom_path = syft_res.get("sbom_path")
                if syft_res.get("check_status") in (CheckStatus.BLOCKED.value, CheckStatus.ERROR.value):
                    has_partial_failures = True
            else:
                self._record_skipped_job("syft", "SBOM generation was disabled for this assessment.")

            # -----------------------------------------------------------
            # Stage 5: Dependency Vulnerability Analysis (Grype & OSV)
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.DEPENDENCY_ANALYSIS, "DEPENDENCY_ANALYSIS")
            if scan_options["enable_deps"]:
                if sbom_path and os.path.exists(sbom_path):
                    grype_res = self.grype.scan(self.assessment_id, sbom_path, is_sbom=True)
                else:
                    # Dependency analysis can still run directly on source if
                    # SBOM generation was switched off or did not produce a file.
                    grype_res = self.grype.scan(self.assessment_id, workspace_path, is_sbom=False)
                if grype_res.get("check_status") in (CheckStatus.BLOCKED.value, CheckStatus.ERROR.value):
                    has_partial_failures = True

                osv_res = self.osv.scan(self.assessment_id, workspace_path)
                if osv_res.get("check_status") in (CheckStatus.BLOCKED.value, CheckStatus.ERROR.value):
                    has_partial_failures = True
            else:
                self._record_skipped_job("grype", "Dependency analysis was disabled for this assessment.")
                self._record_skipped_job("osv", "Dependency analysis was disabled for this assessment.")

            # -----------------------------------------------------------
            # Stage 6: Runtime Provisioning
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.RUNTIME_PROVISIONING, "RUNTIME_PROVISIONING")

            # Check if user provided an existing authorized staging URL
            with db_session() as db:
                a_record = db.query(Assessment).filter(Assessment.id == self.assessment_id).first()
                if a_record and a_record.target_url:
                    target_url = a_record.target_url
                    logger.info("Using user-supplied staging target for DAST", target_url=target_url)

            # If no staging URL provided, attempt automatic Docker runtime provisioning
            if not target_url and scan_options["enable_runtime"]:
                runtime_res = self.runtime_orch.provision(self.assessment_id, workspace_path, self.request_id)
                target_url = runtime_res.get("target_url")
                if runtime_res.get("status") not in (RuntimeStatus.RUNNING.value,):
                    has_partial_failures = True
            elif not target_url:
                self._record_skipped_job("runtime", "Isolated runtime execution was disabled for this assessment.")

            # -----------------------------------------------------------
            # Stage 7: Dynamic Security Testing (DAST)
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.DYNAMIC_TESTING, "DYNAMIC_TESTING")
            if target_url and scan_options["enable_active_dast"]:
                self.zap.scan(self.assessment_id, target_url)
            else:
                reason = (
                    "Active DAST was disabled for this assessment."
                    if not scan_options["enable_active_dast"]
                    else "Dynamic testing not assessed: no reachable target was available."
                )
                logger.info("Skipping dynamic testing", reason=reason)
                self._record_skipped_job("dast_zap", reason)

            # -----------------------------------------------------------
            # Stage 8: Correlation, Graph & Risk Scoring
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.CORRELATION_AND_RISK, "CORRELATION_AND_RISK")

            # Dependency graph
            self.graph_builder.build(self.assessment_id)

            # Finding correlation
            self.correlator.correlate(self.assessment_id)

            # Risk scoring
            risk_summary = self.risk_engine.score_all(self.assessment_id)

            # -----------------------------------------------------------
            # Stage 9: AI Analysis & Remediation
            # -----------------------------------------------------------
            self._set_status(AssessmentStatus.AI_ANALYSIS, "AI_ANALYSIS")
            self.ai_client.analyze_assessment(self.assessment_id, max_findings=5)

            # -----------------------------------------------------------
            # Stage 10: Report Generation
            # -----------------------------------------------------------
            # Persist the final outcome before report snapshots are gathered so
            # exported JSON/SARIF do not claim the assessment is still running.
            final_status = AssessmentStatus.PARTIAL if has_partial_failures else AssessmentStatus.COMPLETED
            self._set_status(final_status, "REPORT_GENERATION")
            self.report_gen.generate(self.assessment_id, format="json")
            self.report_gen.generate(self.assessment_id, format="sarif")

            self._set_status(final_status, "DONE")

            logger.info("Assessment pipeline finished successfully", final_status=final_status.value)
            return {
                "assessment_id": self.assessment_id,
                "status": final_status.value,
                "risk_summary": risk_summary,
            }

        except Exception as e:
            logger.error("Assessment pipeline failed with exception", error=str(e), exc_info=True)
            self._set_status(AssessmentStatus.FAILED, "ERROR", error_message=str(e))
            raise
        finally:
            # Mandatory cleanup: stop runtime containers
            try:
                self.runtime_orch.cleanup(self.assessment_id)
            except Exception as e:
                logger.warning("Error during runtime cleanup", error=str(e))

    def _set_status(
        self,
        status: AssessmentStatus,
        stage: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Update assessment status and stage in database."""
        with db_session() as db:
            assessment = db.query(Assessment).filter(Assessment.id == self.assessment_id).first()
            if assessment:
                assessment.status = status
                assessment.current_stage = stage
                if error_message:
                    assessment.error_message = error_message
                if status in (AssessmentStatus.COMPLETED, AssessmentStatus.PARTIAL,
                              AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
                    assessment.completed_at = datetime.now(timezone.utc)
                elif status == AssessmentStatus.REPOSITORY_FETCH and not assessment.started_at:
                    assessment.started_at = datetime.now(timezone.utc)

    def _record_skipped_job(self, tool_name: str, reason: str) -> None:
        """Record a ScanJob that was not assessed or skipped."""
        with db_session() as db:
            job = ScanJob(
                assessment_id=self.assessment_id,
                tool_name=tool_name,
                status=ScanJobStatus.SKIPPED,
                check_status=CheckStatus.NOT_ASSESSED,
                error_message=reason,
                completed_at=datetime.now(timezone.utc),
            )
            db.add(job)
