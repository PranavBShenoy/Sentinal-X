import hashlib
import io
import tarfile
from unittest.mock import MagicMock, patch

import pytest

from runtime_host.app.artifact import ArtifactError, download_artifact, extract_artifact_safely


def _archive(name="main.py", data=b"print('ok')", member_type=tarfile.REGTYPE):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name)
        info.type = member_type
        info.mode = 0o600
        info.size = len(data) if member_type == tarfile.REGTYPE else 0
        archive.addfile(info, io.BytesIO(data) if info.size else None)
    return buffer.getvalue()


def test_artifact_requires_https_and_allowlisted_origin():
    with pytest.raises(ArtifactError, match="Only HTTPS"):
        download_artifact("http://files.example/a.tgz", "0" * 64, allowlist="files.example")
    with pytest.raises(ArtifactError, match="allowlist"):
        download_artifact("https://other.example/a.tgz", "0" * 64, allowlist="files.example")


def test_download_pins_resolved_ip_and_checks_hash():
    contents = b"archive-data"
    response = MagicMock()
    response.status = 200
    response.read.side_effect = [contents, b""]
    connection = MagicMock()
    connection.getresponse.return_value = response
    tls_socket = MagicMock()
    raw_socket = MagicMock()
    context = MagicMock()
    context.wrap_socket.return_value = tls_socket
    with (
        patch("runtime_host.app.artifact.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 0))]),
        patch("runtime_host.app.artifact.socket.create_connection", return_value=raw_socket) as connect,
        patch("runtime_host.app.artifact.ssl.create_default_context", return_value=context),
        patch("runtime_host.app.artifact.http.client.HTTPSConnection", return_value=connection),
    ):
        result = download_artifact(
            "https://files.example/artifact.tgz",
            hashlib.sha256(contents).hexdigest(),
            allowlist="files.example",
        )
    assert result == contents
    connect.assert_called_once_with(("8.8.8.8", 443), timeout=60.0)
    context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="files.example")
    connection.request.assert_called_once()


def test_download_rejects_hash_mismatch():
    contents = b"archive-data"
    response = MagicMock()
    response.status = 200
    response.read.side_effect = [contents, b""]
    connection = MagicMock()
    connection.getresponse.return_value = response
    raw_socket, tls_socket, context = MagicMock(), MagicMock(), MagicMock()
    context.wrap_socket.return_value = tls_socket
    with (
        patch("runtime_host.app.artifact.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 0))]),
        patch("runtime_host.app.artifact.socket.create_connection", return_value=raw_socket),
        patch("runtime_host.app.artifact.ssl.create_default_context", return_value=context),
        patch("runtime_host.app.artifact.http.client.HTTPSConnection", return_value=connection),
    ):
        with pytest.raises(ArtifactError, match="does not match"):
            download_artifact("https://files.example/a", "0" * 64, allowlist="files.example")


def test_safe_extraction_writes_regular_files(tmp_path):
    extracted = extract_artifact_safely(_archive(), str(tmp_path))
    assert (tmp_path / extracted.split("/")[-1] / "main.py").read_bytes() == b"print('ok')"


@pytest.mark.parametrize("name", ["../escape", "/absolute", "nested/../../escape"])
def test_safe_extraction_rejects_traversal(tmp_path, name):
    with pytest.raises(ArtifactError, match="traversal"):
        extract_artifact_safely(_archive(name), str(tmp_path))


def test_safe_extraction_rejects_symlinks(tmp_path):
    with pytest.raises(ArtifactError, match="unsupported member type"):
        extract_artifact_safely(_archive("link", member_type=tarfile.SYMTYPE), str(tmp_path))
