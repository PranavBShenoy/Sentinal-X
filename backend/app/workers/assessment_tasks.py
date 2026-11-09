"""
Assessment pipeline orchestration tasks.

Each Celery task corresponds to one stage of the assessment pipeline.
Tasks are designed to be:
- Idempotent where possible
- Independently retryable on transient failures
- Self-contained with proper cleanup in finally blocks
- Security-conscious: no secrets in logs, no shell string interpolation

Pipeline stages:
  CREATED → REPOSITORY_FETCH → REPOSITORY_ANALYSIS → STATIC_SCANS →
  SBOM_GENERATION → DEPENDENCY_ANALYSIS → RUNTIME_PROVISIONING →
  DYNAMIC_TESTING → FINDING_NORMALIZATION → CORRELATION_AND_RISK →
  AI_ANALYSIS → REPORT_GENERATION → COMPLETED/PARTIAL/FAILED
"""
from __future__ import annotations

import os
import shutil
import traceback
from datetime import datetime, timezone
from typing import Optional

from celery import chain, chord, group
from celery.utils.log import get_task_logger

from app.core.config import get_settings
from app.core.database import db_session
from app.models import (
    Assessment,
    AssessmentStatus,
    ScanJob,
    ScanJobStatus,
    CheckStatus,
)
from app.workers.celery_app import celery_app

settings = get_settings()
logger = get_task_logger(__name__)


def _update_assessment_status(
    assessment_id: str,
    status: AssessmentStatus,
    stage: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Update assessment status in database."""
    with db_session() as db:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if assessment:
            assessment.status = status
            if stage:
                assessment.current_stage = stage
            if error:
                assessment.error_message = error
            if status in (AssessmentStatus.COMPLETED, AssessmentStatus.PARTIAL,
                          AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
                assessment.completed_at = datetime.now(timezone.utc)


def _create_scan_job(assessment_id: str, tool_name: str) -> str:
    """Create a scan job record and return its ID."""
    with db_session() as db:
        job = ScanJob(
            assessment_id=assessment_id,
            tool_name=tool_name,
            status=ScanJobStatus.PENDING,
        )
        db.add(job)
        db.flush()
        return str(job.id)


def _update_scan_job(
    job_id: str,
    status: ScanJobStatus,
    check_status: Optional[CheckStatus] = None,
    **kwargs,
) -> None:
    """Update a scan job record."""
    with db_session() as db:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = status
            if check_status:
                job.check_status = check_status
            for k, v in kwargs.items():
                if hasattr(job, k):
                    setattr(job, k, v)
            if status in (ScanJobStatus.COMPLETED, ScanJobStatus.FAILED,
                          ScanJobStatus.TIMED_OUT, ScanJobStatus.CANCELLED):
                job.completed_at = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="app.workers.assessment_tasks.run_assessment")
def run_assessment(self, assessment_id: str) -> dict:
    """
    Orchestrate the full assessment pipeline for a given assessment ID.

    This task dispatches sub-tasks for each stage and aggregates results.
    """
    logger.info("Starting assessment pipeline", assessment_id=assessment_id)

    try:
        _update_assessment_status(
            assessment_id,
            AssessmentStatus.REPOSITORY_FETCH,
            stage="REPOSITORY_FETCH",
        )

        # Execute pipeline stages sequentially with partial completion support
        result = _run_pipeline(assessment_id)
        return result

    except Exception as exc:
        logger.error(
            "Assessment pipeline failed",
            assessment_id=assessment_id,
            error=str(exc),
        )
        _update_assessment_status(
            assessment_id,
            AssessmentStatus.FAILED,
            error=f"Pipeline error: {type(exc).__name__}",
        )
        raise


def _run_pipeline(assessment_id: str) -> dict:
    """Run all pipeline stages, preserving partial results on failure."""
    from app.services.assessment_pipeline import AssessmentPipeline

    pipeline = AssessmentPipeline(assessment_id)
    return pipeline.execute()


# ---------------------------------------------------------------------------
# Individual Stage Tasks (can be retried independently)
# ---------------------------------------------------------------------------


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.fetch_repository",
    max_retries=2,
    default_retry_delay=10,
)
def fetch_repository(self, assessment_id: str) -> dict:
    """Clone the repository at the exact commit SHA."""
    from app.services.repository_service import RepositoryService

    try:
        service = RepositoryService()
        return service.fetch(assessment_id)
    except Exception as exc:
        logger.error("Repository fetch failed", assessment_id=assessment_id, error=str(exc))
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_semgrep",
    soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS,
)
def run_semgrep(self, assessment_id: str, workspace_path: str) -> dict:
    """Run Semgrep SAST analysis."""
    from app.integrations.semgrep.scanner import SemgrepScanner

    scanner = SemgrepScanner()
    return scanner.scan(assessment_id, workspace_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_gitleaks",
    soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS,
)
def run_gitleaks(self, assessment_id: str, workspace_path: str) -> dict:
    """Run Gitleaks secret detection."""
    from app.integrations.gitleaks.scanner import GitleaksScanner

    scanner = GitleaksScanner()
    return scanner.scan(assessment_id, workspace_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_syft",
    soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS,
)
def run_syft(self, assessment_id: str, workspace_path: str) -> dict:
    """Generate SBOM using Syft."""
    from app.integrations.syft.scanner import SyftScanner

    scanner = SyftScanner()
    return scanner.scan(assessment_id, workspace_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_grype",
    soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS,
)
def run_grype(self, assessment_id: str, sbom_path: str) -> dict:
    """Run Grype vulnerability matching against SBOM."""
    from app.integrations.grype.scanner import GrypeScanner

    scanner = GrypeScanner()
    return scanner.scan(assessment_id, sbom_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_osv",
    soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS,
)
def run_osv(self, assessment_id: str, workspace_path: str) -> dict:
    """Run OSV-Scanner dependency vulnerability analysis."""
    from app.integrations.osv.scanner import OSVScanner

    scanner = OSVScanner()
    return scanner.scan(assessment_id, workspace_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_trivy",
    soft_time_limit=settings.SCANNER_TIMEOUT_SECONDS,
)
def run_trivy(self, assessment_id: str, workspace_path: str) -> dict:
    """Run Trivy filesystem and configuration scan."""
    from app.integrations.trivy.scanner import TrivyScanner

    scanner = TrivyScanner()
    return scanner.scan(assessment_id, workspace_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_zap",
    soft_time_limit=settings.DYNAMIC_TEST_TIMEOUT_SECONDS,
)
def run_zap(self, assessment_id: str, target_url: str) -> dict:
    """Run OWASP ZAP dynamic analysis."""
    from app.integrations.zap.scanner import ZapScanner

    scanner = ZapScanner()
    return scanner.scan(assessment_id, target_url)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.provision_runtime",
    soft_time_limit=settings.RUNTIME_PROVISIONING_TIMEOUT_SECONDS,
)
def provision_runtime(self, assessment_id: str, workspace_path: str) -> dict:
    """Attempt to build and start the application in an isolated environment."""
    from app.runtime.docker.orchestrator import RuntimeOrchestrator

    orchestrator = RuntimeOrchestrator()
    return orchestrator.provision(assessment_id, workspace_path)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.correlate_and_score",
)
def correlate_and_score(self, assessment_id: str) -> dict:
    """Correlate findings, build dependency graph, and compute risk scores."""
    from app.analysis.correlation.correlator import FindingCorrelator
    from app.analysis.dependency_graph.builder import DependencyGraphBuilder
    from app.analysis.risk.engine import RiskEngine

    # Build dependency graph
    graph_builder = DependencyGraphBuilder()
    graph_builder.build(assessment_id)

    # Correlate findings
    correlator = FindingCorrelator()
    correlator.correlate(assessment_id)

    # Score risks
    engine = RiskEngine()
    engine.score_all(assessment_id)

    return {"status": "completed"}


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_ai_analysis",
    soft_time_limit=120,
)
def run_ai_analysis(self, assessment_id: str) -> dict:
    """Generate AI explanations for key findings."""
    from app.integrations.openrouter.client import OpenRouterClient

    client = OpenRouterClient()
    return client.analyze_assessment(assessment_id)


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.generate_report",
)
def generate_report(self, assessment_id: str) -> dict:
    """Generate the final assessment report."""
    from app.reporting.generator import ReportGenerator

    generator = ReportGenerator()
    return generator.generate(assessment_id, format="json")


@celery_app.task(name="app.workers.assessment_tasks.cleanup_expired_workspaces")
def cleanup_expired_workspaces() -> dict:
    """Periodic task to remove expired assessment workspaces."""
    from app.runtime.cleanup.workspace_cleaner import WorkspaceCleaner

    cleaner = WorkspaceCleaner()
    return cleaner.cleanup_expired()
