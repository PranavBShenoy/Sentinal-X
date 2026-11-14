import pytest
from pydantic import ValidationError

from app.core.repository_url import validate_clone_url
from app.schemas.schemas import RepositoryCreate


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repository.git",
        "https://gitlab.com/group/subgroup/repository",
        "https://bitbucket.org/owner/repository",
        "https://codeberg.org/owner/repository",
    ],
)
def test_supported_https_git_hosts_are_accepted(url):
    assert validate_clone_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "/etc/passwd",
        "file:///etc/passwd",
        "http://github.com/owner/repository.git",
        "https://127.0.0.1/owner/repository.git",
        "https://169.254.169.254/latest/meta-data",
        "https://github.com:8443/owner/repository.git",
        "https://user:pass@github.com/owner/repository.git",
        "https://github.com/owner/../secrets",
    ],
)
def test_unsafe_repository_clone_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_clone_url(url)


def test_api_repository_schema_rejects_unsafe_clone_url():
    with pytest.raises(ValidationError):
        RepositoryCreate(full_name="owner/repository", clone_url="http://127.0.0.1/secrets")
