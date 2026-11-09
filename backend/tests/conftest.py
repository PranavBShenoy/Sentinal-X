"""
Pytest configuration and shared fixtures for SENTINEL-X test suite.
"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_PATH = "/tmp/sentinelx_test.db"
if os.path.exists(TEST_DB_PATH):
    try:
        os.remove(TEST_DB_PATH)
    except Exception:
        pass

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ["JWT_SECRET"] = "a" * 64
os.environ["ENCRYPTION_KEY"] = "U1RST05HX0ZFUk5FVF9LRVlfVEVTVF9PQUJDRDExMjI="

from app.core import database
from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models import Project, Repository, User

# Ensure database engine uses the test DB
test_engine = create_engine(
    f"sqlite:///{TEST_DB_PATH}",
    connect_args={"check_same_thread": False},
)
database.engine = test_engine
database.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Reset rate limiter state before each test to prevent 429 rate limit interference."""
    from app.core.rate_limiter import limiter
    limiter._memory_fallback.clear()
    if limiter._redis_client is not None:
        try:
            keys = limiter._redis_client.keys("sentinelx:ratelimit:*")
            if keys:
                limiter._redis_client.delete(*keys)
        except Exception:
            pass
    yield


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass


@pytest.fixture(scope="function")
def db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    session = database.SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        session = database.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db):
    user = User(
        email="security-tester@example.com",
        username="sectester",
        hashed_password=hash_password("ComplexP@ssw0rd123!"),
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_user_2(db):
    user = User(
        email="second-user@example.com",
        username="seconduser",
        hashed_password=hash_password("ComplexP@ssw0rd456!"),
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user):
    token = create_access_token(subject=str(test_user.id))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_2(test_user_2):
    token = create_access_token(subject=str(test_user_2.id))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_project(db, test_user):
    project = Project(
        owner_id=test_user.id,
        name="Security Test Project",
        description="Automated testing workspace",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def test_repo(db, test_project):
    repo = Repository(
        project_id=test_project.id,
        full_name="sentinelx-org/test-application",
        clone_url="https://github.com/sentinelx-org/test-application.git",
        default_branch="main",
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo
