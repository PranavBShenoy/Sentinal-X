"""
Workspace Cleaner Service.

Removes temporary Git workspaces, build artifacts, and expired directories
to avoid unbounded disk usage while protecting active workspaces.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Dict

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class WorkspaceCleaner:
    """Manages cleanup of temporary assessment workspace directories on disk."""

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base_dir = Path(base_dir or settings.ASSESSMENT_WORKSPACE_BASE)

    def cleanup_assessment(self, assessment_id: str) -> bool:
        """Remove a specific assessment's workspace directory."""
        target = self.base_dir / assessment_id
        if target.exists():
            try:
                shutil.rmtree(target)
                logger.info("Workspace removed", assessment_id=assessment_id, path=str(target))
                return True
            except Exception as e:
                logger.error("Failed to remove workspace", assessment_id=assessment_id, error=str(e))
                return False
        return True

    def cleanup_expired(self) -> Dict[str, int]:
        """
        Scan base workspace directory and purge folders older than max age.
        """
        if not self.base_dir.exists():
            return {"purged": 0, "skipped": 0}

        max_age_seconds = settings.ASSESSMENT_WORKSPACE_MAX_AGE_HOURS * 3600
        now = time.time()
        purged = 0
        skipped = 0

        for item in self.base_dir.iterdir():
            if item.is_dir():
                try:
                    mtime = item.stat().st_mtime
                    if (now - mtime) > max_age_seconds:
                        shutil.rmtree(item)
                        purged += 1
                        logger.info("Purged expired workspace", path=str(item))
                    else:
                        skipped += 1
                except Exception as e:
                    logger.warning("Error inspecting workspace directory", path=str(item), error=str(e))

        return {"purged": purged, "skipped": skipped}
