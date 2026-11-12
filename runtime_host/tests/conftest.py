"""Isolate Runtime Host authentication persistence from user home state."""

import os
import tempfile

import pytest

# auth.py is imported during test collection. Give its module-level store a
# writable temporary location before that import can touch the user's home.
os.environ.setdefault(
    "SENTINELX_NONCE_STORE_PATH",
    os.path.join(tempfile.gettempdir(), f"sentinelx-pytest-{os.getpid()}-nonces.db"),
)


@pytest.fixture(autouse=True)
def runtime_host_nonce_store(tmp_path, monkeypatch):
    from runtime_host.app import auth
    from runtime_host.app.nonce_store import NonceStore

    monkeypatch.setattr(auth, "_nonce_store", NonceStore(str(tmp_path / "nonces.db")))

    # Lifespan tests must never touch a real VM Docker daemon or persistent
    # Runtime Host state. Use isolated SQLite files and a no-Docker executor.
    monkeypatch.setenv("SENTINELX_NONCE_STORE_PATH", str(tmp_path / "lifespan-nonces.db"))
    monkeypatch.setenv("SENTINELX_JOB_STORE_PATH", str(tmp_path / "jobs.db"))
    from runtime_host.app import main

    class NoDockerExecutor:
        def __init__(self, *args, **kwargs):
            self.bind_ip = "127.0.0.1"

        def health_check(self):
            return False

    monkeypatch.setattr(main, "DockerExecutor", NoDockerExecutor)
