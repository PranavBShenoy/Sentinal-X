"""
Project type detector for runtime provisioning.

Inspects workspace files to identify application type, entry points,
required services, and environment variables.

Returns ProjectProfile with:
- type: fastapi | flask | nodejs | nextjs | react | unknown
- confidence: HIGH | MEDIUM | LOW
- entry_point: path to main file
- port: detected or guessed application port
- package_manager: pip | npm | yarn | pnpm
- has_dockerfile: bool
- has_docker_compose: bool
- required_env_vars: List[str] - found in .env.example, docker-compose, etc.
- services: List[str] - detected databases, caches, etc.
- build_command: str or None
- start_command: str or None
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ProjectProfile:
    project_type: str = "unknown"
    confidence: str = "LOW"
    entry_point: Optional[str] = None
    port: int = 8000
    package_manager: Optional[str] = None
    has_dockerfile: bool = False
    has_docker_compose: bool = False
    required_env_vars: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    build_command: Optional[str] = None
    start_command: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


# Regex patterns for env var extraction
_ENV_VAR_RE = re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?")
_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.IGNORECASE | re.MULTILINE)
_UVICORN_PORT_RE = re.compile(r"--port\s+(\d+)")
_NODE_PORT_RE = re.compile(r"PORT\s*[=:]\s*(\d+)|listen\s*\(\s*(\d+)\s*\)")

# Service keywords to scan for
_SERVICE_KEYWORDS = {
    "postgres": ["postgres", "postgresql", "psycopg2", "pg"],
    "mysql": ["mysql", "mysqlclient", "pymysql"],
    "mongodb": ["mongodb", "pymongo", "mongoose"],
    "redis": ["redis", "redis-py", "ioredis", "aioredis"],
    "rabbitmq": ["amqp", "pika", "amqplib"],
    "elasticsearch": ["elasticsearch", "opensearch"],
    "sqlite": ["sqlite3", "aiosqlite"],
}


class ProjectDetector:
    """Inspects a workspace directory and returns a ProjectProfile."""

    def detect(self, workspace_path: str) -> ProjectProfile:
        root = Path(workspace_path)
        profile = ProjectProfile()

        if not root.exists() or not root.is_dir():
            profile.warnings.append(f"Workspace path does not exist: {workspace_path}")
            return profile

        # --- Discover key indicator files ---
        req_txt = root / "requirements.txt"
        pyproject = root / "pyproject.toml"
        setup_py = root / "setup.py"
        package_json = root / "package.json"
        dockerfile = root / "Dockerfile"
        docker_compose_yml = root / "docker-compose.yml"
        docker_compose_yaml = root / "docker-compose.yaml"
        env_example = root / ".env.example"
        env_file = root / ".env"
        lockfile_poetry = root / "poetry.lock"
        lockfile_pipenv = root / "Pipfile.lock"
        yarn_lock = root / "yarn.lock"
        pnpm_lock = root / "pnpm-lock.yaml"

        profile.has_dockerfile = dockerfile.exists()
        profile.has_docker_compose = docker_compose_yml.exists() or docker_compose_yaml.exists()

        # --- Determine ecosystem (Python vs Node) ---
        is_python = req_txt.exists() or pyproject.exists() or setup_py.exists() or lockfile_poetry.exists() or lockfile_pipenv.exists()
        is_node = package_json.exists()

        if is_python:
            self._detect_python(root, profile, req_txt, pyproject, setup_py)
        elif is_node:
            self._detect_node(root, profile, package_json, yarn_lock, pnpm_lock)
        else:
            profile.project_type = "unknown"
            profile.confidence = "LOW"
            profile.warnings.append("No requirements.txt, pyproject.toml, or package.json found")

        # --- Detect port from Dockerfile ---
        if profile.has_dockerfile:
            port = self._extract_dockerfile_port(dockerfile)
            if port:
                profile.port = port

        # --- Collect required env vars ---
        env_vars: set[str] = set()

        if env_example.exists():
            env_vars |= self._parse_env_file(env_example)
        if env_file.exists():
            env_vars |= self._parse_env_file(env_file)

        compose_file = docker_compose_yml if docker_compose_yml.exists() else docker_compose_yaml
        if compose_file.exists():
            env_vars |= self._parse_docker_compose_env_vars(compose_file)

        # Scan source files for env var references
        env_vars |= self._scan_source_env_vars(root)

        # Strip common non-useful vars and deduplicate
        profile.required_env_vars = sorted(env_vars - _INTERNAL_SYSTEM_VARS)

        # --- Detect backing services ---
        profile.services = self._detect_services(root, req_txt, package_json, docker_compose_yml or docker_compose_yaml)

        return profile

    # ------------------------------------------------------------------ #
    # Python ecosystem
    # ------------------------------------------------------------------ #

    def _detect_python(
        self,
        root: Path,
        profile: ProjectProfile,
        req_txt: Path,
        pyproject: Path,
        setup_py: Path,
    ) -> None:
        profile.package_manager = "pip"

        # Read dependency strings
        dep_text = ""
        if req_txt.exists():
            dep_text += req_txt.read_text(errors="ignore").lower()
        if pyproject.exists():
            dep_text += pyproject.read_text(errors="ignore").lower()
        if setup_py.exists():
            dep_text += setup_py.read_text(errors="ignore").lower()

        # Determine framework
        if "fastapi" in dep_text:
            profile.project_type = "fastapi"
            profile.confidence = "HIGH"
            profile.port = 8000
            entry = self._find_python_entry(root, keywords=["fastapi", "app", "main"])
            profile.entry_point = entry
            if entry:
                module = Path(entry).stem
                profile.start_command = f"uvicorn {module}:app --host 0.0.0.0 --port 8000"
            else:
                profile.start_command = "uvicorn main:app --host 0.0.0.0 --port 8000"
        elif "flask" in dep_text:
            profile.project_type = "flask"
            profile.confidence = "HIGH"
            profile.port = 5000
            entry = self._find_python_entry(root, keywords=["flask", "app", "main"])
            profile.entry_point = entry
            if entry:
                module = Path(entry).stem
                profile.start_command = f"python {entry}"
            else:
                profile.start_command = "flask run --host 0.0.0.0 --port 5000"
        elif "django" in dep_text:
            profile.project_type = "django"
            profile.confidence = "HIGH"
            profile.port = 8000
            manage = root / "manage.py"
            if manage.exists():
                profile.entry_point = "manage.py"
                profile.start_command = "python manage.py runserver 0.0.0.0:8000"
        elif "tornado" in dep_text or "aiohttp" in dep_text:
            profile.project_type = "python-web"
            profile.confidence = "MEDIUM"
            profile.port = 8000
            entry = self._find_python_entry(root, keywords=["app", "main", "server"])
            profile.entry_point = entry
            if entry:
                profile.start_command = f"python {entry}"
        else:
            profile.project_type = "python"
            profile.confidence = "MEDIUM"
            profile.port = 8000
            entry = self._find_python_entry(root, keywords=["main", "app", "server"])
            profile.entry_point = entry
            if entry:
                profile.start_command = f"python {entry}"

        # Detect uvicorn / gunicorn port overrides in scripts
        if profile.start_command:
            m = _UVICORN_PORT_RE.search(profile.start_command)
            if m:
                profile.port = int(m.group(1))

        # Check if poetry or pipenv
        if (root / "poetry.lock").exists():
            profile.package_manager = "poetry"
        elif (root / "Pipfile").exists():
            profile.package_manager = "pipenv"

    def _find_python_entry(self, root: Path, keywords: list[str]) -> Optional[str]:
        """Return path (relative to root) of the most likely Python entry point."""
        candidates = []
        # Priority: exact filename matches
        for name in ["main.py", "app.py", "server.py", "run.py", "wsgi.py", "asgi.py"]:
            p = root / name
            if p.exists():
                return name
        # Scan top-level Python files for framework usage
        for py_file in root.glob("*.py"):
            text = py_file.read_text(errors="ignore").lower()
            if any(kw in text for kw in keywords):
                candidates.append(py_file.name)
        if candidates:
            return candidates[0]
        # Fallback: any .py in root
        py_files = list(root.glob("*.py"))
        if py_files:
            return py_files[0].name
        return None

    # ------------------------------------------------------------------ #
    # Node ecosystem
    # ------------------------------------------------------------------ #

    def _detect_node(
        self,
        root: Path,
        profile: ProjectProfile,
        package_json: Path,
        yarn_lock: Path,
        pnpm_lock: Path,
    ) -> None:
        # Determine package manager
        if pnpm_lock.exists():
            profile.package_manager = "pnpm"
        elif yarn_lock.exists():
            profile.package_manager = "yarn"
        else:
            profile.package_manager = "npm"

        try:
            pkg = json.loads(package_json.read_text(errors="ignore"))
        except Exception:
            pkg = {}

        deps = {}
        deps.update(pkg.get("dependencies", {}))
        deps.update(pkg.get("devDependencies", {}))
        dep_names = {k.lower() for k in deps}

        scripts = pkg.get("scripts", {})
        build_script = scripts.get("build")
        start_script = scripts.get("start") or scripts.get("dev")

        if "next" in dep_names:
            profile.project_type = "nextjs"
            profile.confidence = "HIGH"
            profile.port = 3000
            profile.build_command = f"{profile.package_manager} run build"
            profile.start_command = f"{profile.package_manager} start"
            profile.entry_point = "pages/index.js" if (root / "pages").exists() else "app/page.tsx"
        elif "react" in dep_names and "express" not in dep_names:
            profile.project_type = "react"
            profile.confidence = "HIGH"
            profile.port = 3000
            profile.build_command = f"{profile.package_manager} run build"
            profile.start_command = f"{profile.package_manager} start"
            profile.entry_point = "src/index.js" if (root / "src" / "index.js").exists() else "src/main.jsx"
        elif "express" in dep_names or "koa" in dep_names or "fastify" in dep_names:
            profile.project_type = "nodejs"
            profile.confidence = "HIGH"
            profile.port = 3000
            main_file = pkg.get("main", "index.js")
            if (root / main_file).exists():
                profile.entry_point = main_file
            else:
                profile.entry_point = self._find_node_entry(root)
            if profile.entry_point:
                profile.start_command = f"node {profile.entry_point}"
        elif "nuxt" in dep_names:
            profile.project_type = "nuxt"
            profile.confidence = "HIGH"
            profile.port = 3000
            profile.build_command = f"{profile.package_manager} run build"
            profile.start_command = f"{profile.package_manager} start"
        elif "svelte" in dep_names or "@sveltejs/kit" in dep_names:
            profile.project_type = "sveltekit"
            profile.confidence = "HIGH"
            profile.port = 3000
            profile.build_command = f"{profile.package_manager} run build"
            profile.start_command = f"{profile.package_manager} preview"
        else:
            profile.project_type = "nodejs"
            profile.confidence = "MEDIUM"
            profile.port = 3000
            main_file = pkg.get("main", "index.js")
            profile.entry_point = main_file if (root / main_file).exists() else self._find_node_entry(root)
            if profile.entry_point:
                profile.start_command = f"node {profile.entry_point}"

        # Override with package.json scripts if present
        if build_script and not profile.build_command:
            profile.build_command = f"{profile.package_manager} run build"
        if start_script and not profile.start_command:
            profile.start_command = f"{profile.package_manager} start"

        # Try to detect port from scripts
        full_scripts = " ".join(scripts.values())
        m = _NODE_PORT_RE.search(full_scripts)
        if m:
            detected_port = int(m.group(1) or m.group(2))
            if 1024 <= detected_port <= 65535:
                profile.port = detected_port

    def _find_node_entry(self, root: Path) -> Optional[str]:
        for name in ["index.js", "index.ts", "server.js", "server.ts", "app.js", "app.ts", "main.js", "main.ts"]:
            if (root / name).exists():
                return name
        return None

    # ------------------------------------------------------------------ #
    # Dockerfile port extraction
    # ------------------------------------------------------------------ #

    def _extract_dockerfile_port(self, dockerfile: Path) -> Optional[int]:
        try:
            content = dockerfile.read_text(errors="ignore")
            matches = _EXPOSE_RE.findall(content)
            if matches:
                return int(matches[0])
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # Env var scanning
    # ------------------------------------------------------------------ #

    def _parse_env_file(self, path: Path) -> set[str]:
        """Extract variable names from a .env or .env.example file."""
        vars_: set[str] = set()
        try:
            for line in path.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key = line.split("=", 1)[0].strip()
                    if key and re.match(r"^[A-Z][A-Z0-9_]{1,}$", key):
                        vars_.add(key)
        except Exception:
            pass
        return vars_

    def _parse_docker_compose_env_vars(self, path: Path) -> set[str]:
        """Extract environment variable names from docker-compose file."""
        vars_: set[str] = set()
        try:
            content = path.read_text(errors="ignore")
            # Match lines like: VAR_NAME=value or VAR_NAME: value or - VAR_NAME=...
            for m in _ENV_VAR_RE.finditer(content):
                vars_.add(m.group(1))
            # Also match plain KEY= patterns in environment sections
            plain_re = re.compile(r"^\s*-?\s*([A-Z][A-Z0-9_]{1,})\s*=", re.MULTILINE)
            for m in plain_re.finditer(content):
                vars_.add(m.group(1))
        except Exception:
            pass
        return vars_

    def _scan_source_env_vars(self, root: Path) -> set[str]:
        """Scan source files for os.environ / process.env references."""
        vars_: set[str] = set()
        # Python patterns: os.environ["VAR"] or os.environ.get("VAR") or os.getenv("VAR")
        py_re = re.compile(r"""os\.(?:environ\.get|environ\[|getenv)\s*\(\s*['"]([\w]+)['"]""")
        # Node/JS patterns: process.env.VAR_NAME
        js_re = re.compile(r"""process\.env\.([A-Z][A-Z0-9_]{1,})""")

        source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
        # Only scan files at max 3 levels deep to avoid runaway
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in source_extensions:
                # Skip node_modules, .venv, __pycache__, etc.
                parts = path.relative_to(root).parts
                if any(p in _SKIP_DIRS for p in parts):
                    continue
                try:
                    text = path.read_text(errors="ignore")
                    for m in py_re.finditer(text):
                        vars_.add(m.group(1))
                    for m in js_re.finditer(text):
                        vars_.add(m.group(1))
                except Exception:
                    pass
        return vars_

    # ------------------------------------------------------------------ #
    # Backing service detection
    # ------------------------------------------------------------------ #

    def _detect_services(
        self,
        root: Path,
        req_txt: Path,
        package_json: Path,
        compose_file: Optional[Path],
    ) -> list[str]:
        services: set[str] = set()

        # Build a combined dependency string
        dep_text = ""
        if req_txt.exists():
            dep_text += req_txt.read_text(errors="ignore").lower()
        if package_json.exists():
            dep_text += package_json.read_text(errors="ignore").lower()
        if compose_file and compose_file.exists():
            dep_text += compose_file.read_text(errors="ignore").lower()

        for service, keywords in _SERVICE_KEYWORDS.items():
            if any(kw in dep_text for kw in keywords):
                services.add(service)

        return sorted(services)


# Variables to exclude from required_env_vars (too generic / OS-level)
_INTERNAL_SYSTEM_VARS: set[str] = {
    "HOME", "PATH", "USER", "SHELL", "PWD", "TERM", "LANG", "LC_ALL",
    "HOSTNAME", "PYTHONPATH", "NODE_ENV", "CI", "DEBUG",
}

_SKIP_DIRS: set[str] = {
    "node_modules", ".venv", "venv", "__pycache__", ".git",
    ".tox", "dist", "build", ".next", ".nuxt", "coverage",
}
