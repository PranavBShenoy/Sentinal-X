"""
Custom exception classes for SENTINEL-X.

These exceptions are raised by service/repository layers and translated to
HTTP responses by global exception handlers in app.main.
"""
from __future__ import annotations


class SentinelXError(Exception):
    """Base exception for all application-level errors."""
    pass


class NotFoundError(SentinelXError):
    """Resource does not exist."""
    pass


class ForbiddenError(SentinelXError):
    """Caller is authenticated but lacks permission for this resource."""
    pass


class ValidationError(SentinelXError):
    """Input data failed business-logic validation."""
    pass


class ScannerUnavailableError(SentinelXError):
    """A required security scanner binary or service is not available."""
    pass


class WorkspaceError(SentinelXError):
    """An error occurred managing an assessment workspace directory."""
    pass


class AssessmentStateError(SentinelXError):
    """Requested operation is invalid for the assessment's current state."""
    pass
