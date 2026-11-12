from runtime_host.app.executor import DockerExecutor
from pathlib import Path


def test_run_uses_private_bind_address_and_advertised_target(monkeypatch):
    executor = DockerExecutor(
        advertised_host="runtime.internal.example",
        bind_ip="10.20.30.40",
    )
    calls = []

    def fake_docker(args, timeout_seconds=60):
        calls.append(args)
        return True, "ok"

    monkeypatch.setattr(executor, "_run_docker", fake_docker)
    result = executor.submit_run(
        job_id="job-1",
        assessment_id="assessment-1",
        image_tag="sentinelx-app-assessment",
        container_name="sentinelx-cont-assessment",
        network_name="sentinelx-net-assessment",
        app_port=8000,
        host_port=32123,
    )

    assert result.target_url == "http://runtime.internal.example:32123"
    assert "10.20.30.40:32123:8000" in calls[1]


def test_runtime_host_uvicorn_binds_all_container_interfaces():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    assert '"--host", "0.0.0.0"' in dockerfile.read_text()
