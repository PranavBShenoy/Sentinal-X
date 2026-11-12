"""
Repository Fetch and Structural Analysis Service.

Safely clones target repositories into isolated workspaces, checks out exact commit SHAs,
and analyzes project architecture (languages, dependencies, Dockerfiles, frameworks, entrypoints).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.core.subprocess_utils import run_command
from app.models import Assessment, GitHubInstallation
from app.runtime.detection.detector import ProjectDetector

logger = get_logger(__name__)
settings = get_settings()


class RepositoryService:
    """Handles Git checkout and structural inspection for assessments."""

    def __init__(self) -> None:
        self.workspace_base = Path(settings.ASSESSMENT_WORKSPACE_BASE)
        self.detector = ProjectDetector()

    def fetch(self, assessment_id: str) -> Dict[str, Any]:
        """
        Fetch repository source at the specified commit SHA or branch into an isolated workspace.

        Returns {workspace_path: str, commit_sha: str, repo_analysis: dict}.
        """
        self.workspace_base.mkdir(parents=True, exist_ok=True)
        workspace_dir = self.workspace_base / assessment_id / "source"
        workspace_dir.mkdir(parents=True, exist_ok=True)

        with db_session() as db:
            assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
            if not assessment:
                raise ValueError(f"Assessment {assessment_id} not found")

            repo = assessment.repository
            if not repo:
                raise ValueError(f"No repository linked to assessment {assessment_id}")

            clone_url = repo.clone_url
            target_branch = assessment.branch or repo.default_branch or "main"
            target_sha = assessment.commit_sha

            # Check if user has GitHub App token or OAuth credentials for private repo
            auth_token = None
            installation = (
                db.query(GitHubInstallation)
                .filter(GitHubInstallation.user_id == assessment.created_by_id)
                .first()
            )
            if installation and installation.encrypted_access_token:
                try:
                    from app.core.security import decrypt_value
                    auth_token = decrypt_value(installation.encrypted_access_token)
                except Exception as e:
                    logger.warning("Could not decrypt GitHub token", error=str(e))

        if not clone_url:
            clone_url = f"https://github.com/{repo.full_name}.git"

        # Check if clone_url is a local directory (e.g. test fixture or local volume)
        if os.path.isdir(clone_url):
            import shutil
            logger.info("Using local directory fixture for assessment", path=clone_url)
            shutil.copytree(clone_url, workspace_dir, dirs_exist_ok=True)
            actual_sha = target_sha or "local-fixture-head"
        else:
            # Safe authenticated URL injection (token is never logged)
            effective_clone_url = clone_url
            if auth_token and "github.com" in clone_url:
                parsed = urlparse(clone_url)
                effective_clone_url = f"https://x-access-token:{auth_token}@{parsed.netloc}{parsed.path}"

            logger.info(
                "Cloning repository into workspace",
                repo=repo.full_name,
                assessment_id=assessment_id,
            )

            # Clone shallowly first for efficiency
            clone_args = [
                "git",
                "clone",
                "--depth",
                "50",
                "--branch",
                target_branch,
                effective_clone_url,
                str(workspace_dir),
            ]

            sub_res = run_command(
                args=clone_args,
                timeout_seconds=120,
                tool_name="git-clone",
            )

            if not sub_res.succeeded:
                # Fallback: clone default without branch if branch didn't exist
                logger.warning("Branch clone failed, attempting default clone", repo=repo.full_name)
                sub_res = run_command(
                    args=["git", "clone", "--depth", "50", effective_clone_url, str(workspace_dir)],
                    timeout_seconds=120,
                    tool_name="git-clone-default",
                )
                if not sub_res.succeeded:
                    raise RuntimeError(f"Git clone failed for {repo.full_name}: {sub_res.stderr[:200]}")

            # If a specific commit SHA was requested, checkout that exact SHA
            actual_sha = target_sha
            if target_sha:
                checkout_res = run_command(
                    ["git", "checkout", target_sha],
                    timeout_seconds=30,
                    tool_name="git-checkout",
                    cwd=str(workspace_dir),
                )
                if not checkout_res.succeeded:
                    raise RuntimeError(f"Failed to checkout requested commit {target_sha}: {checkout_res.stderr[:200]}")
            else:
                # Resolve and record HEAD commit SHA
                rev_res = run_command(
                    ["git", "rev-parse", "HEAD"],
                    timeout_seconds=10,
                    tool_name="git-rev-parse",
                    cwd=str(workspace_dir),
                )
                if rev_res.succeeded:
                    actual_sha = rev_res.stdout.strip()

        # Structural Repository Analysis
        profile = self.detector.detect(str(workspace_dir))
        analysis_data = {
            "project_type": profile.project_type,
            "confidence": profile.confidence,
            "entry_point": profile.entry_point,
            "detected_port": profile.port,
            "has_dockerfile": profile.has_dockerfile,
            "has_docker_compose": profile.has_docker_compose,
            "required_env_vars": profile.required_env_vars,
            "detected_services": profile.services,
            "package_manager": profile.package_manager,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Update assessment record in DB
        with db_session() as db:
            a = db.query(Assessment).filter(Assessment.id == assessment_id).first()
            if a:
                if actual_sha:
                    a.commit_sha = actual_sha
                a.repo_analysis = analysis_data

        return {
            "workspace_path": str(workspace_dir),
            "commit_sha": actual_sha,
            "repo_analysis": analysis_data,
        }
