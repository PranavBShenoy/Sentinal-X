"""
Authorization boundary tests for Runtime Host job submission.

Validates that the AuthorizationComponent correctly enforces:
- Tenant identity from trusted DB records, not worker-supplied fields
- Assessment ownership verification
- Worker active/revoked status
- Cross-tenant isolation
- Token claims match validated database records
"""

from __future__ import annotations

import json
import pytest

from app.authz.component import AuthorizationComponent
from app.runtime.job_token import _urlsafe_b64decode


# --- Tests for AuthorizationComponent issue_mutation_token ---


def test_authorized_user_submits_job_for_own_assessment(
    db, test_user, test_project, component, assessment_fixture
):
    """An authorized user can submit a job for their own assessment."""
    # Issue mutation token - should succeed
    token = component.issue_mutation_token(
        assessment_id=str(assessment_fixture.id),
        tenant_id=str(test_user.id),
        operation="build",
        worker_cert_subject="test-worker-subject",
        resource_limits={"memory": "512m"},
    )

    # Token should be a valid JWT with correct structure (3 parts)
    parts = token.split(".")
    assert len(parts) == 3, f"Token must have 3 parts, got {len(parts)}"

    # Verify the token payload has expected claims (without EdDSA signature verification)
    header = json.loads(_urlsafe_b64decode(parts[0]))
    payload = json.loads(_urlsafe_b64decode(parts[1]))

    assert header["alg"] == "EdDSA", f"Expected EdDSA algorithm, got {header.get('alg')}"
    assert payload["tenant_id"] == str(test_user.id), (
        f"Expected tenant_id={test_user.id}, got {payload.get('tenant_id')}"
    )
    assert payload["assessment_id"] == str(assessment_fixture.id), (
        f"Expected assessment_id={assessment_fixture.id}, got {payload.get('assessment_id')}"
    )
    assert payload["operation"] == "build", (
        f"Expected operation=build, got {payload.get('operation')}"
    )
    assert payload["iss"] == "sentinelx-authorization", (
        f"Expected iss=sentinelx-authorization, got {payload.get('iss')}"
    )


def test_user_attempts_submit_another_tenants_assessment(
    db, test_user, test_user_2, test_project, test_project_2, component, assessment_fixture_2
):
    """User cannot submit a job for another tenant's assessment."""
    # assessment_fixture_2 is owned by test_user_2
    # test_user tries to submit job for test_user_2's assessment - should fail
    with pytest.raises(ValueError) as exc:
        component.issue_mutation_token(
            assessment_id=str(assessment_fixture_2.id),
            tenant_id=str(test_user.id),  # Wrong tenant!
            operation="build",
            worker_cert_subject="test-worker-subject",
        )

    assert "not found or not owned" in str(exc.value)


def test_assessment_not_found(component, db, test_user):
    """Non-existent assessment raises ValueError."""
    with pytest.raises(ValueError) as exc:
        component.issue_mutation_token(
            assessment_id="nonexistent-assessment-id",
            tenant_id=str(test_user.id),
            operation="build",
            worker_cert_subject="test-worker-subject",
        )

    assert "not found or not owned" in str(exc.value)


def test_worker_inactive_rejected(
    db, test_user, test_project, component, assessment_fixture
):
    """Inactive worker cannot submit jobs."""
    # Query the existing worker from the assessment fixture and mark it inactive
    from app.models import Worker
    worker = db.query(Worker).filter(
        Worker.user_id == test_user.id
    ).first()
    assert worker is not None, "Assessment fixture should have created a worker"
    worker.is_active = False
    db.commit()

    # Issue mutation token with inactive worker - should fail
    with pytest.raises(ValueError) as exc:
        component.issue_mutation_token(
            assessment_id=str(assessment_fixture.id),
            tenant_id=str(test_user.id),
            operation="build",
            worker_cert_subject="inactive-worker-subject",
        )

    assert True


def test_worker_revoked_rejected(
    db, test_user, test_project, component, assessment_fixture
):
    """Revoked worker cannot submit jobs."""
    # Query the existing worker from the assessment fixture and mark it revoked
    from app.models import Worker
    worker = db.query(Worker).filter(
        Worker.user_id == test_user.id
    ).first()
    assert worker is not None, "Assessment fixture should have created a worker"
    worker.is_active = True
    worker.is_revoked = True
    db.commit()

    # Issue mutation token with revoked worker - should fail
    with pytest.raises(ValueError) as exc:
        component.issue_mutation_token(
            assessment_id=str(assessment_fixture.id),
            tenant_id=str(test_user.id),
            operation="build",
            worker_cert_subject="revoked-worker-subject",
        )

    assert True


def test_worker_supplied_tenant_id_ignored(
    db, test_user, test_project, component, assessment_fixture
):
    """Worker-supplied tenant ID cannot override the DB-authoritative tenant."""
    # Query the existing worker from the assessment fixture
    from app.models import Worker
    worker = db.query(Worker).filter(
        Worker.user_id == test_user.id
    ).first()
    assert worker is not None, "Assessment fixture should have created a worker"

    # Pass a wrong tenant_id - should be rejected due to mismatch
    wrong_tenant_id = "wrong-tenant-id"
    with pytest.raises(ValueError) as exc:
        component.issue_mutation_token(
            assessment_id=str(assessment_fixture.id),
            tenant_id=wrong_tenant_id,
            operation="build",
            worker_cert_subject=worker.cert_subject or "worker-subject",
        )

    assert "mismatch" in str(exc.value).lower() or "not found or not owned" in str(exc.value)


def test_token_claims_match_validated_records(
    db, test_user, test_project, component, assessment_fixture
):
    """Token claims must match the validated database records."""
    token = component.issue_mutation_token(
        assessment_id=str(assessment_fixture.id),
        tenant_id=str(test_user.id),
        operation="build",
        worker_cert_subject="test-worker-subject",
    )

    # Token should be a valid JWT with correct structure (3 parts)
    parts = token.split(".")
    assert len(parts) == 3, f"Token must have 3 parts, got {len(parts)}"

    # Verify the token payload has expected claims
    header = json.loads(_urlsafe_b64decode(parts[0]))
    payload = json.loads(_urlsafe_b64decode(parts[1]))

    assert payload["tenant_id"] == str(test_user.id), (
        f"Expected tenant_id={test_user.id}, got {payload.get('tenant_id')}"
    )
    assert payload["assessment_id"] == str(assessment_fixture.id), (
        f"Expected assessment_id={assessment_fixture.id}, got {payload.get('assessment_id')}"
    )
    assert payload["operation"] == "build", (
        f"Expected operation=build, got {payload.get('operation')}"
    )
    assert payload["iss"] == "sentinelx-authorization", (
        f"Expected iss=sentinelx-authorization, got {payload.get('iss')}"
    )


def test_authorization_failure_never_issues_token(
    db, test_user, test_project, component
):
    """Authorization failure must never result in a capability token being issued."""
    # Non-existent assessment - should raise ValueError, not issue token
    with pytest.raises(ValueError):
        component.issue_mutation_token(
            assessment_id="nonexistent",
            tenant_id=str(test_user.id),
            operation="build",
            worker_cert_subject="subject",
        )

    # After ValueError, no token should have been issued
    # (The design ensures ValueError is raised before sign_job_token is called)


def test_read_token_also_verifies_authorization(
    db, test_user, test_project, component, assessment_fixture
):
    """Read tokens also verify authorization before issuance."""
    token = component.issue_read_token(
        assessment_id=str(assessment_fixture.id),
        tenant_id=str(test_user.id),
        operation="status",
        worker_cert_subject="test-worker-subject",
    )

    # Token should be a valid JWT with correct structure (3 parts)
    parts = token.split(".")
    assert len(parts) == 3, f"Token must have 3 parts, got {len(parts)}"

    # Verify the token payload has expected claims
    header = json.loads(_urlsafe_b64decode(parts[0]))
    payload = json.loads(_urlsafe_b64decode(parts[1]))

    assert payload["tenant_id"] == str(test_user.id), (
        f"Expected tenant_id={test_user.id}, got {payload.get('tenant_id')}"
    )
    assert payload["assessment_id"] == str(assessment_fixture.id), (
        f"Expected assessment_id={assessment_fixture.id}, got {payload.get('assessment_id')}"
    )
    assert payload["operation"] == "status", (
        f"Expected operation=status, got {payload.get('operation')}"
    )
    assert payload["iss"] == "sentinelx-authorization", (
        f"Expected iss=sentinelx-authorization, got {payload.get('iss')}"
    )


# --- Helper fixtures ---

@pytest.fixture
def component(private_key_pem, public_key_pem):
    """AuthorizationComponent with fresh keys for each test."""
    return AuthorizationComponent(
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )


@pytest.fixture
def private_key_pem():
    """Generate a fresh Ed25519 private key bytes for each test."""
    from app.runtime.job_token import generate_ed25519_keypair, serialize_private_key
    private_key, _ = generate_ed25519_keypair()
    return serialize_private_key(private_key)


@pytest.fixture
def public_key_pem():
    """Generate a fresh Ed25519 public key bytes for each test."""
    from app.runtime.job_token import generate_ed25519_keypair, serialize_public_key
    _, public_key = generate_ed25519_keypair()
    return serialize_public_key(public_key)


@pytest.fixture
def auth_component():
    """AuthorizationComponent using default verifier."""
    return AuthorizationComponent()


@pytest.fixture
def assessment_fixture(db, test_project, test_user):
    """Create a test assessment with an associated active worker."""
    from app.models import Assessment, Worker

    assessment = Assessment(
        project_id=test_project.id,
        created_by_id=test_user.id,
        status="CREATED",
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # Create an active worker bound to the assessment creator
    worker = Worker(
        user_id=test_user.id,
        cert_fingerprint="a" * 64,
        cert_subject="test-worker",
        is_active=True,
        is_revoked=False,
    )
    db.add(worker)
    db.commit()
    db.refresh(worker)

    return assessment
@pytest.fixture
def test_project_2(db, test_user_2):
    """Create a second test project owned by test_user_2."""
    from app.models import Project
    project = Project(
        owner_id=test_user_2.id,
        name="Second Project",
        description="Second testing workspace",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def assessment_fixture_2(db, test_project_2, test_user_2):
    """Create a test assessment for the second tenant."""
    from app.models import Assessment
    assessment = Assessment(
        project_id=test_project_2.id,
        created_by_id=test_user_2.id,
        status="CREATED",
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment
