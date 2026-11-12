"""Unit tests for the Worker database model."""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.database import Base
from app.models import Worker

# A SHA-256 hex digest is 64 characters.
FINGERPRINT = "a" * 64
CERT_SUBJECT = "CN=sentinelx-worker-1,O=SENTINEL-X"


def _make_worker(user_id, fingerprint=FINGERPRINT, **overrides):
    kwargs = {
        "user_id": user_id,
        "cert_fingerprint": fingerprint,
        "cert_subject": CERT_SUBJECT,
    }
    kwargs.update(overrides)
    return Worker(**kwargs)


def test_worker_creation(db, test_user):
    worker = _make_worker(test_user.id)
    db.add(worker)
    db.commit()
    db.refresh(worker)

    assert worker.id is not None
    assert worker.user_id == test_user.id
    assert worker.cert_fingerprint == FINGERPRINT
    assert worker.cert_subject == CERT_SUBJECT
    assert isinstance(worker.created_at, datetime)


def test_worker_uuid_primary_key(db, test_user):
    worker = _make_worker(test_user.id)
    db.add(worker)
    db.commit()
    db.refresh(worker)

    parsed = uuid.UUID(worker.id)
    assert str(parsed) == worker.id


def test_worker_user_relationship(db, test_user):
    worker = _make_worker(test_user.id)
    db.add(worker)
    db.commit()
    db.refresh(worker)
    db.refresh(test_user)

    assert worker.user.id == test_user.id
    assert any(w.id == worker.id for w in test_user.workers)


def test_worker_unique_cert_fingerprint(db, test_user):
    db.add(_make_worker(test_user.id))
    db.commit()

    duplicate = _make_worker(test_user.id)
    db.add(duplicate)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_worker_active_revoked_defaults(db, test_user):
    worker = _make_worker(test_user.id)
    db.add(worker)
    db.commit()
    db.refresh(worker)

    assert worker.is_active is True
    assert worker.is_revoked is False
    assert worker.revoked_at is None


def test_worker_revocation_timestamp(db, test_user):
    worker = _make_worker(test_user.id)
    db.add(worker)
    db.commit()
    db.refresh(worker)

    revoked_at = datetime.now(timezone.utc)
    worker.is_active = False
    worker.is_revoked = True
    worker.revoked_at = revoked_at
    db.commit()
    db.refresh(worker)

    assert worker.is_active is False
    assert worker.is_revoked is True
    assert worker.revoked_at is not None


def test_worker_registered_in_metadata():
    assert "workers" in Base.metadata.tables

    table = Base.metadata.tables["workers"]
    assert set(table.columns.keys()) == {
        "id",
        "user_id",
        "cert_fingerprint",
        "cert_subject",
        "is_active",
        "is_revoked",
        "created_at",
        "revoked_at",
    }
    assert list(table.primary_key.columns.keys()) == ["id"]
