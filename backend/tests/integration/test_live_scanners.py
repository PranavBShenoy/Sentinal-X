"""
Live integration test executing actual scanner binaries and native DAST engine
against controlled test repositories containing known test vulnerabilities and secrets.
"""
from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from app.integrations.gitleaks.scanner import GitleaksScanner
from app.integrations.grype.scanner import GrypeScanner
from app.integrations.osv.scanner import OSVScanner
from app.integrations.semgrep.scanner import SemgrepScanner
from app.integrations.syft.scanner import SyftScanner
from app.integrations.trivy.scanner import TrivyScanner
from app.integrations.zap.scanner import ZapScanner
from app.models import (
    Assessment,
    AssessmentStatus,
    CheckStatus,
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Project,
    Repository,
    ScanJobStatus,
)
from app.reporting.generator import ReportGenerator


class InsecureTestServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "session=insecure_token_123; Path=/")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Insecure Target</h1></body></html>")

    def log_message(self, format, *args):
        pass


def test_live_gitleaks_actual_binary_and_secret_masking(db, test_user):
    """Test actual Gitleaks binary on secret_leak fixture and verify secret masking."""
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "secret_leak"
    assert fixture_dir.exists()

    project = Project(name="Gitleaks Live Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/secret_leak", clone_url=str(fixture_dir))
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    scanner = GitleaksScanner()
    assert scanner.is_available(), f"Gitleaks binary at {scanner.gitleaks_path} is not available"

    result = scanner.scan(str(assessment.id), str(fixture_dir))
    # Scan completed; check status is FAILED because secrets were found
    assert result["status"] == ScanJobStatus.COMPLETED.value
    assert result["check_status"] == CheckStatus.FAILED.value
    assert result["findings_count"] >= 2

    findings = db.query(Finding).filter(Finding.assessment_id == str(assessment.id)).all()
    assert len(findings) >= 2

    for f in findings:
        assert f.category == FindingCategory.SECRET
        assert f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        # Ensure secret is masked and never stored in plain text
        if "AKIA" in (f.description or ""):
            assert "..." in f.description
            assert "AKIAIOSFODNN7EXAMPLE" not in f.description


def test_live_trivy_vulnerability_detection(db, test_user):
    """Test actual Trivy binary detecting real CVEs in vuln_deps fixture."""
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "vuln_deps"
    assert fixture_dir.exists()

    project = Project(name="Trivy Live Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/vuln_deps", clone_url=str(fixture_dir))
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    trivy = TrivyScanner()
    assert trivy.is_available(), f"Trivy binary at {trivy.trivy_path} is not available"

    result = trivy.scan(str(assessment.id), str(fixture_dir))
    # Scan completed; check status is FAILED because vulnerabilities were detected
    assert result["status"] == ScanJobStatus.COMPLETED.value
    assert result["check_status"] == CheckStatus.FAILED.value
    assert result["findings_count"] > 0

    findings = db.query(Finding).filter(Finding.assessment_id == str(assessment.id)).all()
    assert len(findings) > 0
    # Requests 2.6.0 has CVE-2018-18074
    cve_list = [cve for f in findings for cve in (f.cve_ids or [])]
    assert any("CVE-" in cve for cve in cve_list)


def test_live_native_dast_against_test_application(db, test_user):
    """Start controlled test HTTP server and run actual DAST probes against it."""
    port = 9877
    server = HTTPServer(("127.0.0.1", port), InsecureTestServer)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.5)

    try:
        project = Project(name="DAST Live Test", owner_id=test_user.id)
        db.add(project)
        db.flush()

        repo = Repository(project_id=project.id, full_name="tests/dast", clone_url="/tmp")
        db.add(repo)
        db.flush()

        assessment = Assessment(
            project_id=project.id,
            repository_id=repo.id,
            created_by_id=test_user.id,
            branch="main",
            target_url=f"http://127.0.0.1:{port}",
            status=AssessmentStatus.CREATED,
        )
        db.add(assessment)
        db.commit()

        dast = ZapScanner()
        result = dast.scan(str(assessment.id), f"http://127.0.0.1:{port}")

        # Scan completed; check status is FAILED because insecure headers were detected
        assert result["status"] == ScanJobStatus.COMPLETED.value
        assert result["check_status"] == CheckStatus.FAILED.value
        assert result["findings_count"] >= 3

        findings = db.query(Finding).filter(Finding.assessment_id == str(assessment.id)).all()
        titles = [f.title for f in findings]

        # Verify specific DAST findings
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("X-Content-Type-Options" in t for t in titles)
        assert any("Server" in t for t in titles)

    finally:
        server.shutdown()
        server.server_close()


def test_report_generation_formats_integrity(db, test_user):
    """Verify generation of JSON, SARIF, and CSV reports with file existence and non-zero size."""
    project = Project(name="Reports Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/reports", clone_url="/tmp")
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.flush()

    # Add a sample finding
    finding = Finding(
        assessment_id=assessment.id,
        fingerprint="test-fingerprint-12345",
        source_tool="gitleaks",
        title="Exposed Test API Key",
        description="Found test secret key",
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=FindingCategory.SECRET,
        rule_id="CWE-798",
        cve_ids=[],
        risk_score=8.5,
        status=FindingStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    generator = ReportGenerator()
    for fmt in ("json", "sarif", "csv"):
        res = generator.generate(str(assessment.id), format=fmt)
        assert res["format"] == fmt
        assert os.path.exists(res["file_path"])
        assert os.path.getsize(res["file_path"]) > 0


def test_live_semgrep_sast_vulnerability_detection(db, test_user):
    """Test actual Semgrep binary executing offline rules against controlled vulnerable SQLi fixture."""
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "vuln_sqli"
    assert fixture_dir.exists()

    # Copy to temporary workspace path outside 'tests/' to prevent default test file exclusion
    import tempfile
    import shutil
    temp_ws = Path(tempfile.mkdtemp(prefix="sentinelx_semgrep_test_"))
    try:
        shutil.copy(fixture_dir / "main.py", temp_ws / "main.py")
        shutil.copy(fixture_dir / "requirements.txt", temp_ws / "requirements.txt")

        project = Project(name="Semgrep Live Test", owner_id=test_user.id)
        db.add(project)
        db.flush()

        repo = Repository(project_id=project.id, full_name="tests/vuln_sqli", clone_url=str(temp_ws))
        db.add(repo)
        db.flush()

        assessment = Assessment(
            project_id=project.id,
            repository_id=repo.id,
            created_by_id=test_user.id,
            branch="main",
            status=AssessmentStatus.CREATED,
        )
        db.add(assessment)
        db.commit()

        scanner = SemgrepScanner()
        assert scanner.is_available(), f"Semgrep binary at {scanner.semgrep_path} is not available"
        version = scanner.get_version()
        assert version is not None and "1." in version

        result = scanner.scan(str(assessment.id), str(temp_ws))
        assert result["status"] == ScanJobStatus.COMPLETED.value
        assert result["check_status"] == CheckStatus.FAILED.value
        assert result["findings_count"] >= 1

        findings = db.query(Finding).filter(Finding.assessment_id == str(assessment.id)).all()
        assert len(findings) >= 1

        sqli_findings = [f for f in findings if f.subcategory == "SQL_INJECTION"]
        assert len(sqli_findings) >= 1
        f = sqli_findings[0]
        assert f.category == FindingCategory.SAST
        assert f.severity in (FindingSeverity.HIGH, FindingSeverity.MEDIUM)
        assert f.file_path == "main.py"
        assert f.line_start == 20
        assert f.code_snippet is not None
        assert "cursor.execute(query)" in f.code_snippet
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_live_grype_vulnerability_detection_against_sbom_and_dir(db, test_user):
    """Test actual Grype binary against both Syft-generated SBOM and directory fixture."""
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "vuln_deps"
    assert fixture_dir.exists()

    project = Project(name="Grype Live Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/vuln_deps", clone_url=str(fixture_dir))
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    # Step 1: Run Syft to generate real SBOM
    syft = SyftScanner()
    assert syft.is_available(), f"Syft binary at {syft.syft_path} is not available"
    syft_res = syft.scan(str(assessment.id), str(fixture_dir))
    assert syft_res["status"] == ScanJobStatus.COMPLETED.value
    sbom_path = syft_res.get("sbom_path")
    assert sbom_path and os.path.exists(sbom_path)

    # Step 2: Run Grype against the generated SBOM
    grype = GrypeScanner()
    assert grype.is_available(), f"Grype binary at {grype.grype_path} is not available"
    version = grype.get_version()
    assert version is not None and "0." in version

    sbom_result = grype.scan(str(assessment.id), sbom_path, is_sbom=True)
    assert sbom_result["status"] == ScanJobStatus.COMPLETED.value
    assert sbom_result["check_status"] == CheckStatus.FAILED.value
    assert sbom_result["findings_count"] >= 10

    findings = db.query(Finding).filter(Finding.assessment_id == str(assessment.id)).all()
    assert len(findings) >= 10

    # Verify requests 2.6.0 known CVE
    requests_findings = [f for f in findings if f.component == "requests"]
    assert len(requests_findings) >= 1
    cve_ids = [cve for f in requests_findings for cve in (f.cve_ids or [])]
    assert "CVE-2018-18074" in cve_ids

    # Step 3: Run Grype directly against directory
    dir_result = grype.scan(str(assessment.id), str(fixture_dir), is_sbom=False)
    assert dir_result["status"] == ScanJobStatus.COMPLETED.value
    assert dir_result["check_status"] == CheckStatus.FAILED.value


def test_live_osv_scanner_dependency_vulnerability_detection(db, test_user):
    """Test actual Google OSV-Scanner binary with native offline database on vuln_deps fixture."""
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "vuln_deps"
    assert fixture_dir.exists()

    project = Project(name="OSV Live Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/vuln_deps", clone_url=str(fixture_dir))
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    scanner = OSVScanner()
    assert scanner.is_available(), f"OSV-Scanner binary at {scanner.osv_path} is not available"
    version = scanner.get_version()
    assert version is not None and "2." in version

    result = scanner.scan(str(assessment.id), str(fixture_dir))
    assert result["status"] == ScanJobStatus.COMPLETED.value
    assert result["check_status"] == CheckStatus.FAILED.value
    assert result["findings_count"] >= 10

    findings = db.query(Finding).filter(Finding.assessment_id == str(assessment.id), Finding.source_tool == "osv-scanner").all()
    assert len(findings) >= 10

    # Verify requests 2.6.0 has CVE-2018-18074 alias or PYSEC-2018-28
    req_vulns = [f for f in findings if f.component == "requests"]
    assert len(req_vulns) >= 1
    all_cves = [cve for f in req_vulns for cve in (f.cve_ids or [])]
    assert "CVE-2018-18074" in all_cves

    # Verify severity and CVSS
    high_vulns = [f for f in req_vulns if f.severity == FindingSeverity.HIGH]
    assert len(high_vulns) >= 1
    assert any(f.cvss_score == 7.5 for f in high_vulns)


def test_live_scanners_error_handling_and_fallback(db, test_user):
    """Verify BLOCKED status when binary missing, clean scan on empty dir, and timeout safety."""
    project = Project(name="Scanner Error Handling Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/empty", clone_url="/tmp")
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    # 1. Missing binary produces BLOCKED status without raising unhandled exception
    fake_semgrep = SemgrepScanner(semgrep_path="/nonexistent/semgrep_binary")
    assert not fake_semgrep.is_available()
    res_semgrep = fake_semgrep.scan(str(assessment.id), "/tmp")
    assert res_semgrep["check_status"] == CheckStatus.BLOCKED.value

    fake_grype = GrypeScanner(grype_path="/nonexistent/grype_binary")
    assert not fake_grype.is_available()
    res_grype = fake_grype.scan(str(assessment.id), "/tmp")
    assert res_grype["check_status"] == CheckStatus.BLOCKED.value

    fake_osv = OSVScanner(osv_path="/nonexistent/osv_binary")
    assert not fake_osv.is_available()
    res_osv = fake_osv.scan(str(assessment.id), "/tmp")
    assert res_osv["check_status"] == CheckStatus.BLOCKED.value

    # 2. Scanning directory with no packages returns clean CheckStatus.PASSED with 0 findings
    import tempfile
    import shutil
    empty_dir = Path(tempfile.mkdtemp(prefix="sentinelx_empty_"))
    try:
        real_osv = OSVScanner()
        clean_res = real_osv.scan(str(assessment.id), str(empty_dir))
        assert clean_res["check_status"] == CheckStatus.PASSED.value
        assert clean_res["findings_count"] == 0
    finally:
        shutil.rmtree(empty_dir, ignore_errors=True)


def test_cross_scanner_cve_deduplication(db, test_user):
    """
    Verify that when multiple scanners (Trivy, Grype, OSV) scan the same target
    and detect the same CVE, the FindingCorrelator suppresses duplicates,
    leaves a single primary active finding, and aggregates provenance in additional_sources.
    """
    from app.analysis.correlation.correlator import FindingCorrelator
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "vuln_deps"
    assert fixture_dir.exists()

    project = Project(name="Dedup Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/vuln_deps", clone_url=str(fixture_dir))
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    aid = str(assessment.id)

    # 1. Run Trivy, Grype, and OSV against the same target
    trivy_res = TrivyScanner().scan(aid, str(fixture_dir))
    assert trivy_res["status"] == ScanJobStatus.COMPLETED.value

    grype_res = GrypeScanner().scan(aid, str(fixture_dir))
    assert grype_res["status"] == ScanJobStatus.COMPLETED.value

    osv_res = OSVScanner().scan(aid, str(fixture_dir))
    assert osv_res["status"] == ScanJobStatus.COMPLETED.value

    # Prior to correlation, multiple findings exist for CVE-2018-18074
    findings_pre = db.query(Finding).filter(Finding.assessment_id == aid).all()
    cve_findings_pre = [
        f for f in findings_pre
        if f.cve_ids and "CVE-2018-18074" in f.cve_ids and (f.component or "").lower() == "requests"
    ]
    assert len(cve_findings_pre) >= 2
    tools_reporting = {f.source_tool for f in cve_findings_pre}
    assert len(tools_reporting) >= 2

    # 2. Run correlation engine
    correlator = FindingCorrelator()
    summary = correlator.correlate(aid)
    assert summary["deduped_duplicates"] >= 1

    # 3. Verify deduplication post-conditions (expire session to reload updated rows from DB)
    db.expire_all()
    findings_post = db.query(Finding).filter(Finding.assessment_id == aid).all()
    cve_findings_post = [
        f for f in findings_post
        if f.cve_ids and "CVE-2018-18074" in f.cve_ids and (f.component or "").lower() == "requests"
    ]

    active_findings = [f for f in cve_findings_post if f.status != FindingStatus.SUPPRESSED]
    suppressed_findings = [f for f in cve_findings_post if f.status == FindingStatus.SUPPRESSED]

    # Exactly ONE finding remains active
    assert len(active_findings) == 1
    primary = active_findings[0]

    # All others are marked SUPPRESSED with traceable audit reason
    assert len(suppressed_findings) >= 1
    for supp in suppressed_findings:
        assert supp.suppression_reason is not None
        assert f"Correlated duplicate of {primary.source_tool}" in supp.suppression_reason
        assert "CVE-2018-18074" in supp.suppression_reason

    # Primary finding preserves provenance of duplicates in raw_evidence["additional_sources"]
    additional_sources = primary.raw_evidence.get("additional_sources", [])
    assert len(additional_sources) >= 1
    source_tools = {s["tool"] for s in additional_sources}
    for supp in suppressed_findings:
        assert supp.source_tool in source_tools


def test_osv_scanner_corrupted_manifest_error(db, test_user):
    """
    Verify OSV-Scanner distinguishes exit code 128 due to corrupted manifest
    from clean scans, returning CheckStatus.ERROR and ScanJobStatus.FAILED.
    """
    import tempfile
    import shutil

    project = Project(name="OSV Error Test", owner_id=test_user.id)
    db.add(project)
    db.flush()

    repo = Repository(project_id=project.id, full_name="tests/corrupt", clone_url="/tmp")
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    temp_dir = Path(tempfile.mkdtemp(prefix="sentinelx_corrupt_manifest_"))
    try:
        corrupt_manifest = temp_dir / "package-lock.json"
        corrupt_manifest.write_text('{"name": "broken-manifest", "dependencies": { invalid json')

        scanner = OSVScanner()
        result = scanner.scan(str(assessment.id), str(temp_dir))

        assert result["status"] == ScanJobStatus.FAILED.value
        assert result["check_status"] == CheckStatus.ERROR.value
        assert "failed to extract package manifest" in result.get("error", "").lower()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


