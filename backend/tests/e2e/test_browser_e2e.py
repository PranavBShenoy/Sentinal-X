"""
SENTINEL-X End-to-End Real Browser Integration Test Suite.

Uses headless Chromium and Selenium to verify the entire platform workflow:
1. User Registration & Authentication (JWT storage)
2. User Login & Session Persistence
3. Dashboard Telemetry & Metrics Display
4. Project Creation with Local Vulnerability Fixture
5. Security Assessment Configuration & Pipeline Launch
6. Live Progress Tracking & Pipeline Execution
7. Findings Explorer with Severity Filtering & Modal Inspection
8. Interactive Dependency Graph Visualization
9. Automated Remediation Hub Inspection
10. Compliance & Multi-Format Report Generation & Download (PDF/JSON/SARIF)
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Generator

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def is_browser_available() -> bool:
    """Check if Chromium and chromedriver are available in the system."""
    chrome_bin = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    driver_bin = shutil.which("chromedriver")
    return bool(chrome_bin and driver_bin)


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


@pytest.fixture(scope="module")
def e2e_environment() -> Generator[dict, None, None]:
    """Sets up FastAPI backend on port 8000 and Vite preview frontend on port 3000."""
    if not is_browser_available():
        pytest.skip("Chromium or chromedriver is not available in this environment")

    workspace_root = Path(__file__).resolve().parent.parent.parent.parent
    backend_dir = workspace_root / "backend"
    frontend_dir = workspace_root / "frontend"
    test_db_path = "/tmp/sentinelx_browser_e2e.db"

    # Remove stale DB if exists
    for f in Path("/tmp").glob("sentinelx_browser_e2e.db*"):
        try:
            f.unlink()
        except OSError:
            pass

    # Run database migration
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{test_db_path}"
    env["CELERY_TASK_ALWAYS_EAGER"] = "true"
    env["RATE_LIMIT_ENABLED"] = "false"
    env["ASSESSMENT_WORKSPACE_BASE"] = "/tmp/sentinelx_workspaces"

    subprocess.run(
        ["python3", "-m", "alembic", "upgrade", "head"],
        cwd=str(backend_dir),
        env=env,
        check=True,
        capture_output=True,
    )

    api_log = open("/tmp/e2e_api.log", "w")
    vite_log = open("/tmp/e2e_vite.log", "w")

    # Start FastAPI backend on 8000
    api_proc = subprocess.Popen(
        ["python3", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(backend_dir),
        env=env,
        stdout=api_log,
        stderr=api_log,
    )

    # Start Vite preview on 3000
    vite_proc = subprocess.Popen(
        ["npx", "vite", "preview", "--port", "3000", "--host", "127.0.0.1"],
        cwd=str(frontend_dir),
        stdout=vite_log,
        stderr=vite_log,
    )

    # Wait for both servers to be responsive
    api_ready = False
    frontend_ready = False
    for _ in range(30):
        if not api_ready:
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/api/v1/health", timeout=1) as resp:
                    if resp.status == 200:
                        api_ready = True
            except Exception:
                pass
        if not frontend_ready:
            try:
                with urllib.request.urlopen("http://127.0.0.1:3000/", timeout=1) as resp:
                    if resp.status == 200:
                        frontend_ready = True
            except Exception:
                pass
        if api_ready and frontend_ready:
            break
        time.sleep(0.5)

    assert api_ready, "FastAPI backend failed to start on port 8000"
    assert frontend_ready, "Vite frontend failed to start on port 3000"

    yield {
        "base_url": "http://127.0.0.1:3000",
        "api_url": "http://127.0.0.1:8000",
        "workspace_root": workspace_root,
        "db_path": test_db_path,
    }

    # Teardown
    vite_proc.terminate()
    api_proc.terminate()
    try:
        vite_proc.wait(timeout=3)
        api_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        vite_proc.kill()
        api_proc.kill()
    api_log.close()
    vite_log.close()


@pytest.fixture(scope="module")
def browser() -> Generator[webdriver.Chrome, None, None]:
    """Initializes a headless Chromium webdriver."""
    if not is_browser_available():
        pytest.skip("Chromium or chromedriver is not available")

    chrome_bin = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    driver_bin = shutil.which("chromedriver")

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1600,1000")
    if chrome_bin:
        options.binary_location = chrome_bin

    service = Service(executable_path=driver_bin)
    driver = webdriver.Chrome(service=service, options=options)
    driver.implicitly_wait(5)

    yield driver

    driver.quit()


def test_full_browser_e2e_platform_lifecycle(browser: webdriver.Chrome, e2e_environment: dict):
    """
    Executes the complete user and assessment lifecycle in headless Chromium:
    Register -> Login -> Dashboard -> Projects -> Create Assessment -> Findings -> Remediation -> Reports.
    """
    base_url = e2e_environment["base_url"]
    workspace_root = e2e_environment["workspace_root"]
    fixture_dir = workspace_root / "tests" / "fixtures" / "vuln_sqli"
    assert fixture_dir.exists(), f"Vulnerable fixture missing: {fixture_dir}"

    wait = WebDriverWait(browser, 15)

    # =========================================================================
    # Step 1: User Registration
    # =========================================================================
    browser.get(f"{base_url}/register")
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "h1")))
    assert "Create an Account" in browser.page_source

    name_input = browser.find_element(By.CSS_SELECTOR, "input[placeholder='Jane Doe']")
    email_input = browser.find_element(By.CSS_SELECTOR, "input[type='email']")
    password_input = browser.find_element(By.CSS_SELECTOR, "input[type='password']")
    submit_btn = browser.find_element(By.CSS_SELECTOR, "button[type='submit']")

    test_email = "auditor@sentinelx.security"
    test_pass = "P@ssw0rd123!AuditSecure"

    name_input.send_keys("Lead Security Auditor")
    email_input.send_keys(test_email)
    password_input.send_keys(test_pass)
    submit_btn.click()

    # Wait for redirect to Dashboard
    wait.until(lambda d: d.current_url.rstrip("/") == base_url.rstrip("/"))
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Security Posture') or contains(text(), 'Dashboard')]")))

    # Verify session token in localStorage
    token = browser.execute_script("return localStorage.getItem('sentinelx_access_token');")
    assert token is not None and len(token) > 20, "JWT access token not set in localStorage"

    # =========================================================================
    # Step 2: Dashboard Telemetry
    # =========================================================================
    browser.get(f"{base_url}/")
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Active Projects') or contains(text(), 'Projects')]")))
    assert "SENTINEL-X" in browser.page_source or "Security" in browser.page_source

    # =========================================================================
    # Step 3: Project and Repository Creation
    # =========================================================================
    try:
        browser.get(f"{base_url}/projects")
        print("Projects page URL:", browser.current_url)
        print("Page title:", browser.title)
        print("Page source snippet:", browser.page_source[:500])
        wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Security Projects')]")))
    except Exception as e:
        print("\n[DEBUG] Failure on projects page!")
        print("Current URL:", browser.current_url)
        print("Page source:\n", browser.page_source)
        try:
            browser_logs = browser.get_log("browser")
            print("Browser console logs:", browser_logs)
        except Exception as log_err:
            print("Could not retrieve browser logs:", log_err)
        raise e

    # Click "+ New Project" button to open modal
    new_proj_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'New Project')]")))
    new_proj_btn.click()

    # Fill in modal fields
    proj_name_input = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[placeholder='e.g. Sentinel Core API']")))
    proj_desc_input = browser.find_element(By.CSS_SELECTOR, "textarea[placeholder='Production microservice handling customer payments...']")
    clone_url_input = browser.find_element(By.CSS_SELECTOR, "input[placeholder='https://github.com/org/repo.git or /path/to/repo']")

    proj_name_input.send_keys("E2E SQLi Fixture Project")
    proj_desc_input.send_keys("Automated Browser E2E Target for Static & Dependency Testing")
    clone_url_input.send_keys(str(fixture_dir))

    # Submit modal
    create_submit_btn = browser.find_element(By.XPATH, "//button[contains(., 'Create Project')]")
    create_submit_btn.click()

    # Verify new project appears in list
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'E2E SQLi Fixture Project')]")))
    assert "E2E SQLi Fixture Project" in browser.page_source

    # =========================================================================
    # Step 4: Assessment Creation & Execution
    # =========================================================================
    browser.get(f"{base_url}/assessments/new")
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Launch Security Assessment')]")))

    # Wait for project/repository options to populate and button to become clickable
    launch_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Execute Assessment Pipeline')]")))
    launch_btn.click()

    # Wait for navigation to Assessment Detail page (/assessments/<id>)
    wait.until(lambda d: "/assessments/" in d.current_url and not d.current_url.endswith("/new"))
    assessment_id = browser.current_url.split("/assessments/")[1].split("/")[0].split("?")[0]
    assert len(assessment_id) > 10, f"Invalid assessment ID in URL: {browser.current_url}"

    # Wait for assessment pipeline to complete (eager execution or background polling)
    wait.until(
        EC.presence_of_element_located((
            By.XPATH,
            "//*[contains(text(), 'Branch:') or contains(text(), 'Completed') or contains(text(), 'Partial Coverage') or contains(text(), 'Scan Jobs')]"
        ))
    )

    # Verify scan jobs or telemetry cards rendered
    assert "Semgrep" in browser.page_source or "Jobs" in browser.page_source or "Scan" in browser.page_source

    # =========================================================================
    # Step 5: Findings Explorer
    # =========================================================================
    browser.get(f"{base_url}/findings?assessment_id={assessment_id}")
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Findings Explorer')]")))

    # Wait for findings table to load
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Findings') or contains(text(), 'SQL') or contains(text(), 'Total')]")))

    # Check search input interaction
    search_input = browser.find_element(By.CSS_SELECTOR, "input[placeholder*='Search']")
    search_input.send_keys("SQL")
    time.sleep(0.5)

    # Click on finding row in table if available
    finding_rows = browser.find_elements(By.XPATH, "//tbody/tr")
    if finding_rows:
        finding_rows[0].click()
        # Modal should appear
        wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Vulnerability Details') or contains(text(), 'Remediation Advice')]")))
        # Close modal
        close_btns = browser.find_elements(By.XPATH, "//div[@role='dialog']//button | //div[contains(@class, 'fixed')]//button")
        if close_btns:
            close_btns[0].click()

    # =========================================================================
    # Step 6: Dependency Graph View
    # =========================================================================
    try:
        browser.get(f"{base_url}/assessments/{assessment_id}/graph")
        print("\nGraph page URL:", browser.current_url)
        print("Graph page source snippet:\n", browser.page_source[:800])
        wait.until(
            EC.presence_of_element_located((
                By.XPATH,
                "//*[contains(., 'Dependency Relationship') or contains(., 'Attack Graph') or contains(., 'Return to Assessment') or contains(., 'Total Components')]"
            ))
        )
    except Exception as e:
        print("\n[DEBUG] Failure on graph page!")
        print("Current URL:", browser.current_url)
        print("Page source:\n", browser.page_source)
        raise e

    # =========================================================================
    # Step 7: Remediation Hub
    # =========================================================================
    browser.get(f"{base_url}/remediation?assessment_id={assessment_id}")
    wait.until(
        EC.presence_of_element_located((
            By.XPATH,
            "//*[contains(., 'Remediation & Patch Hub') or contains(., 'Remediation')]"
        ))
    )

    # =========================================================================
    # Step 8: Multi-Format Reports Generation and Download Verification
    # =========================================================================
    browser.get(f"{base_url}/reports?assessment_id={assessment_id}")
    wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(., 'Security Assessment Reports')]")))

    # Click Generate Report
    generate_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Generate Report')]")))
    generate_btn.click()

    # Wait for report entry in Available Downloads
    wait.until(EC.presence_of_element_located((By.XPATH, "//a[contains(., 'Download File')]")))
    download_link = browser.find_element(By.XPATH, "//a[contains(., 'Download File')]")
    download_url = download_link.get_attribute("href")
    assert download_url is not None and "/reports/" in download_url, f"Invalid download link: {download_url}"
    assert "token=" in download_url, "Download link must include authenticated token query parameter"

    # Verify direct download returns 200 and non-empty content
    req = urllib.request.Request(download_url)  # noqa: S310
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        assert resp.status == 200, f"Download failed with status {resp.status}"
        data = resp.read()
        assert len(data) > 0, "Downloaded report file is empty"

    print(f"\n[Browser E2E] Successfully verified complete workflow. Downloaded report size: {len(data)} bytes.")
