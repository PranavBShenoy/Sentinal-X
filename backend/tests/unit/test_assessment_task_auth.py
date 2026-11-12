"""Regression tests for assessment task authorization consumption.

Verifies that ``run_assessment`` fails closed without a valid authorization
request, consumes a pending request exactly once, and passes the validated
request_id to the pipeline (which forwards it to runtime provisioning).
"""
from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from app.models import Assessment, AssessmentStatus, AuthorizationRequest
from app.workers.assessment_tasks import run_assessment


def _make_assessment(db, test_user, test_project, test_repo) -> Assessment:
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()
    return assessment


def test_run_assessment_consumes_authorization_once(
    db, test_user, test_project, test_repo
):
    assessment = _make_assessment(db, test_user, test_project, test_repo)
    request_id = str(uuid.uuid4())
    db.add(AuthorizationRequest(
        user_id=str(test_user.id),
        assessment_id=str(assessment.id),
        tenant_id=str(test_project.owner_id),
        operation="provision",
        request_id=request_id,
        status="pending",
    ))
    db.commit()

    with patch("app.services.assessment_pipeline.AssessmentPipeline") as mock_pipeline:
        mock_pipeline.return_value.execute.return_value = {"status": "completed"}

        result = run_assessment.run(str(assessment.id), request_id=request_id)

    assert result == {"status": "completed"}
    mock_pipeline.assert_called_once_with(
        str(assessment.id), request_id=request_id, authz_component=None
    )

    db.expire_all()
    record = (
        db.query(AuthorizationRequest)
        .filter(AuthorizationRequest.request_id == request_id)
        .first()
    )
    assert record is not None
    assert record.status == "consumed"
    assert record.consumed_at is not None

    # A second delivery must fail closed rather than launch a duplicate run.
    with patch("app.services.assessment_pipeline.AssessmentPipeline") as mock_pipeline_2:
        with pytest.raises(ValueError):
            run_assessment.run(str(assessment.id), request_id=request_id)
        mock_pipeline_2.assert_not_called()


def test_run_assessment_rejects_missing_request_id(db, test_user, test_project, test_repo):
    assessment = _make_assessment(db, test_user, test_project, test_repo)

    with pytest.raises(ValueError):
        run_assessment.run(str(assessment.id), request_id=None)


def test_run_assessment_rejects_forged_request_id(db, test_user, test_project, test_repo):
    assessment = _make_assessment(db, test_user, test_project, test_repo)

    with pytest.raises(ValueError):
        run_assessment.run(str(assessment.id), request_id="forged-request-id")


def test_run_assessment_rejects_request_bound_to_other_assessment(
    db, test_user, test_project, test_repo
):
    assessment = _make_assessment(db, test_user, test_project, test_repo)
    other_assessment = _make_assessment(db, test_user, test_project, test_repo)

    request_id = str(uuid.uuid4())
    db.add(AuthorizationRequest(
        user_id=str(test_user.id),
        assessment_id=str(other_assessment.id),
        tenant_id=str(test_project.owner_id),
        operation="provision",
        request_id=request_id,
        status="pending",
    ))
    db.commit()

    with pytest.raises(ValueError):
        run_assessment.run(str(assessment.id), request_id=request_id)
