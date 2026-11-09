"""
Central API v1 Router for SENTINEL-X.

Aggregates all sub-routers with consistent URL prefixes and OpenAPI tags.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.assessments import router as assessments_router
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.projects import router as projects_router
from app.api.v1.endpoints.remediation import router as remediation_router
from app.api.v1.endpoints.reports import router as reports_router
from app.api.v1.endpoints.repositories import router as repositories_router
from app.api.v1.endpoints.runtime import router as runtime_router
from app.api.v1.endpoints.sbom import router as sbom_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(repositories_router)
api_router.include_router(assessments_router)
api_router.include_router(findings_router)
api_router.include_router(sbom_router)
api_router.include_router(runtime_router)
api_router.include_router(remediation_router)
api_router.include_router(reports_router)
