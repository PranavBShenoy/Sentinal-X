from app.schemas.schemas import AssessmentConfig
from app.services.assessment_pipeline import _assessment_scan_options


def test_assessment_module_selections_are_persisted():
    config = AssessmentConfig(
        enable_sast=False,
        enable_secrets=True,
        enable_sbom=False,
        enable_deps=True,
        enable_runtime=False,
        enable_active_dast=False,
    )

    assert config.model_dump() == {
        "enable_sast": False,
        "enable_secrets": True,
        "enable_sbom": False,
        "enable_deps": True,
        "enable_runtime": False,
        "enable_active_dast": False,
        "enable_git_history_scan": False,
        "target_url": None,
        "openapi_spec_url": None,
        "artifact_url": None,
        "artifact_sha256": None,
        "test_username": None,
        "test_password": None,
        "scan_depth": "standard",
        "max_concurrent_scanners": 2,
    }


def test_scan_options_respect_user_selections_and_legacy_defaults():
    assert _assessment_scan_options({"enable_sast": False, "enable_runtime": False}) == {
        "enable_sast": False,
        "enable_secrets": True,
        "enable_sbom": True,
        "enable_deps": True,
        "enable_runtime": False,
        "enable_active_dast": False,
    }
    assert _assessment_scan_options(None) == {
        "enable_sast": True,
        "enable_secrets": True,
        "enable_sbom": True,
        "enable_deps": True,
        "enable_runtime": True,
        "enable_active_dast": False,
    }
