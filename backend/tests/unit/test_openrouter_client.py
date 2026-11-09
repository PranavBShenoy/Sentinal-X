"""
Unit tests for OpenRouterClient.

Verifies:
- Configured check (API key presence)
- Prompt injection protection and evidence bounding
- Secret redaction in prompt snippets
- Deterministic fallback for SECRET, DEPENDENCY, SAST, and DAST categories
- Mocked successful API response parsing and Pydantic validation
- HTTP error and timeout resilience
- Invalid schema / malformed JSON handling
- Remediation proposal creation
"""
import json
from unittest.mock import MagicMock, patch

import pytest
import httpx

from app.core.config import get_settings
from app.integrations.openrouter.client import (
    AIExplanationResponse,
    OpenRouterClient,
)
from app.models import (
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    RemediationStatus,
)

settings = get_settings()


@pytest.fixture
def dummy_finding():
    finding = Finding(
        id="f1111111-1111-1111-1111-111111111111",
        assessment_id="a1111111-1111-1111-1111-111111111111",
        category=FindingCategory.SAST,
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        title="SQL Injection in user search",
        description="User input directly concatenated into SQL query.",
        source_tool="semgrep",
        rule_id="python.lang.security.audit.sqli",
        file_path="app/views.py",
        line_start=42,
        component=None,
        affected_version=None,
        fixed_version=None,
        cve_ids=[],
        code_snippet="query = f\"SELECT * FROM users WHERE id = '{user_id}'\"",
    )
    return finding


def test_is_configured():
    client = OpenRouterClient()
    client.api_key = None
    assert client.is_configured() is False

    client.api_key = "   "
    assert client.is_configured() is False

    client.api_key = "sk-or-v1-testkey123"
    assert client.is_configured() is True


def test_build_prompt_evidence_bounding_and_redaction(dummy_finding):
    client = OpenRouterClient()
    # Add a secret to code_snippet to ensure redaction occurs
    dummy_finding.code_snippet = "password = 'SuperSecretDbPassword99!'"

    messages = client._build_prompt(dummy_finding)
    assert len(messages) == 2

    system_msg = messages[0]["content"]
    assert "CRITICAL SECURITY INSTRUCTIONS" in system_msg
    assert "<evidence>" in system_msg or "<evidence>" in messages[1]["content"]

    user_msg = messages[1]["content"]
    assert "<evidence>" in user_msg
    assert "</evidence>" in user_msg
    # Raw password should be redacted
    assert "SuperSecretDbPassword99!" not in user_msg
    assert "REDACTED" in user_msg or "[REDACTED" in user_msg


def test_deterministic_fallback_categories(dummy_finding):
    client = OpenRouterClient()

    # 1. SECRET category
    dummy_finding.category = FindingCategory.SECRET
    dummy_finding.file_path = "backend/config.py"
    dummy_finding.rule_id = "generic-api-key"
    secret_exp = client._generate_deterministic_explanation(dummy_finding)
    assert "exposed credential" in secret_exp.summary.lower()
    assert "rotate or revoke" in " ".join(secret_exp.remediation_steps).lower()
    assert secret_exp.patch_proposal is not None
    assert "SECRET_KEY" in secret_exp.patch_proposal

    # 2. DEPENDENCY category
    dummy_finding.category = FindingCategory.DEPENDENCY
    dummy_finding.component = "requests"
    dummy_finding.affected_version = "2.25.0"
    dummy_finding.fixed_version = "2.31.0"
    dummy_finding.cve_ids = ["CVE-2023-32681"]
    dep_exp = client._generate_deterministic_explanation(dummy_finding)
    assert "requests" in dep_exp.summary
    assert any("2.31.0" in step for step in dep_exp.remediation_steps)
    assert "- requests==2.25.0" in dep_exp.patch_proposal
    assert "+ requests==2.31.0" in dep_exp.patch_proposal

    # 3. SAST category
    dummy_finding.category = FindingCategory.SAST
    sast_exp = client._generate_deterministic_explanation(dummy_finding)
    assert "SQL Injection" in sast_exp.summary
    assert sast_exp.confidence == "HIGH"
    assert len(sast_exp.remediation_steps) > 0

    # 4. DAST category
    dummy_finding.category = FindingCategory.DAST
    dummy_finding.endpoint = "http://127.0.0.1:8000/api/v1/users"
    dummy_finding.file_path = None
    dast_exp = client._generate_deterministic_explanation(dummy_finding)
    assert "http://127.0.0.1:8000/api/v1/users" in dast_exp.summary


def test_call_openrouter_success():
    client = OpenRouterClient()
    client.api_key = "sk-mock-key"

    mock_llm_json = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "summary": "Verified SQL injection via user input string formatting.",
                        "impact": "Full database read/write access and credential theft.",
                        "confidence": "HIGH",
                        "remediation_steps": [
                            "Use parameterized queries with SQLAlchemy text() and bindparams.",
                            "Implement strict input validation for user identifiers."
                        ],
                        "patch_proposal": "--- a/app/views.py\n+++ b/app/views.py\n- query = f\"...\"\n+ query = text(\"...\")",
                        "limitations": [
                            "Static inspection without runtime query log execution."
                        ]
                    })
                }
            }
        ]
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = mock_llm_json

    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        result = client._call_openrouter([{"role": "user", "content": "test"}])
        assert result is not None
        assert isinstance(result, AIExplanationResponse)
        assert result.confidence == "HIGH"
        assert len(result.remediation_steps) == 2
        assert any("parameterized" in step.lower() for step in result.remediation_steps)
        assert "text(" in result.patch_proposal

        # Verify headers
        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer sk-mock-key"
        assert "response_format" in call_kwargs["json"]


def test_call_openrouter_http_error():
    client = OpenRouterClient()
    client.api_key = "sk-mock-key"

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 429
    mock_response.text = "Rate limit exceeded"

    with patch("httpx.Client.post", return_value=mock_response):
        result = client._call_openrouter([{"role": "user", "content": "test"}])
        assert result is None


def test_call_openrouter_timeout_resilience():
    client = OpenRouterClient()
    client.api_key = "sk-mock-key"

    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Read timed out")):
        result = client._call_openrouter([{"role": "user", "content": "test"}])
        assert result is None


def test_call_openrouter_schema_validation_failure():
    client = OpenRouterClient()
    client.api_key = "sk-mock-key"

    # Missing mandatory fields 'summary' and 'impact'
    invalid_json = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({"random_field": "unexpected"})
                }
            }
        ]
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = invalid_json

    with patch("httpx.Client.post", return_value=mock_response):
        result = client._call_openrouter([{"role": "user", "content": "test"}])
        # Should gracefully return None instead of crashing
        assert result is None


def test_create_remediation_proposal_deterministic(dummy_finding):
    client = OpenRouterClient()
    client.api_key = None  # Ensure deterministic fallback

    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = dummy_finding

    proposal = client.generate_remediation_proposal(
        finding_id=str(dummy_finding.id),
        user_id="u1111111-1111-1111-1111-111111111111",
        session=mock_session,
    )

    assert proposal is not None
    assert proposal.status == RemediationStatus.PROPOSED
    assert "SQL Injection" in proposal.summary
    assert len(proposal.remediation_steps) > 0
    assert proposal.proposed_branch.startswith("sentinelx-fix/sast-")
    mock_session.add.assert_called_once_with(proposal)
