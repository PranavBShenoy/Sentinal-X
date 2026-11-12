"""Regression guard for Alembic's single, connected migration chain."""
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_migrations_have_one_head_and_reach_base() -> None:
    backend_dir = Path(__file__).resolve().parents[2]
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "migrations"))
    scripts = ScriptDirectory.from_config(config)

    assert len(scripts.get_heads()) == 1
    revisions = list(scripts.walk_revisions())
    assert revisions
    assert revisions[-1].down_revision is None
