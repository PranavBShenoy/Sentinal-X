"""
Unit tests for runtime project detection.
"""
import os
import tempfile
from pathlib import Path

from app.runtime.detection.detector import ProjectDetector


def test_detect_fastapi_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("fastapi>=0.100.0\nuvicorn>=0.22.0\n")
        main_py = Path(tmpdir) / "main.py"
        main_py.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

        detector = ProjectDetector()
        profile = detector.detect(tmpdir)

        assert profile.project_type == "fastapi"
        assert profile.port == 8000
        assert profile.has_dockerfile is False


def test_detect_flask_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("flask>=2.0.0\n")
        app_py = Path(tmpdir) / "app.py"
        app_py.write_text("from flask import Flask\napp = Flask(__name__)\n")

        detector = ProjectDetector()
        profile = detector.detect(tmpdir)

        assert profile.project_type == "flask"
        assert profile.port == 5000


def test_detect_node_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = Path(tmpdir) / "package.json"
        pkg.write_text('{"name": "my-app", "dependencies": {"express": "^4.18.0"}}')

        detector = ProjectDetector()
        profile = detector.detect(tmpdir)

        assert profile.project_type == "nodejs"
        assert profile.port == 3000


def test_detect_environment_variables():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_ex = Path(tmpdir) / ".env.example"
        env_ex.write_text("DATABASE_URL=postgres://...\nREDIS_URL=redis://...\n")

        detector = ProjectDetector()
        profile = detector.detect(tmpdir)

        assert "DATABASE_URL" in profile.required_env_vars
        assert "REDIS_URL" in profile.required_env_vars
