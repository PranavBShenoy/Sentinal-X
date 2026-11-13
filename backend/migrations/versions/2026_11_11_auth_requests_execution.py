"""Add durable authorization requests and execution tracking.

Revision ID: 6a7b8c9d0e1f
Revises: b7e4c1a92f30
Create Date: 2026-11-11 11:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "6a7b8c9d0e1f"
down_revision: Union[str, None] = "b7e4c1a92f30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> tuple[sa.Table, sa.Table]:
    metadata = sa.MetaData()
    uuid_type = sa.String(length=36).with_variant(
        sa.UUID(as_uuid=False), "postgresql"
    )
    # Register referenced tables in metadata so dialect compilers can resolve
    # foreign-key targets; these existing tables are not created by this revision.
    sa.Table("users", metadata, sa.Column("id", uuid_type, primary_key=True))
    sa.Table("assessments", metadata, sa.Column("id", uuid_type, primary_key=True))

    authorization_requests = sa.Table(
        "authorization_requests",
        metadata,
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("user_id", uuid_type, nullable=False),
        sa.Column("assessment_id", uuid_type, nullable=False),
        sa.Column("tenant_id", uuid_type, nullable=False),
        sa.Column("operation", sa.String(length=20), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_id", uuid_type, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["assessments.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    sa.Index("ix_auth_requests_user_id", authorization_requests.c.user_id)
    sa.Index(
        "ix_auth_requests_assessment_id", authorization_requests.c.assessment_id
    )
    sa.Index("ix_auth_requests_request_id", authorization_requests.c.request_id)
    sa.Index("ix_auth_requests_status", authorization_requests.c.status)

    executions = sa.Table(
        "executions",
        metadata,
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("authorization_request_id", uuid_type, nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("crashed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["authorization_request_id"],
            ["authorization_requests.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("authorization_request_id"),
    )
    sa.Index(
        "ix_executions_authorization_request_id",
        executions.c.authorization_request_id,
    )
    sa.Index("ix_executions_status", executions.c.status)
    return authorization_requests, executions


def upgrade() -> None:
    authorization_requests, executions = _tables()

    # Emit CREATE TABLE IF NOT EXISTS while preserving the complete model schema
    # across PostgreSQL and SQLite migration/test environments.
    op.execute(sa.schema.CreateTable(authorization_requests, if_not_exists=True))
    op.execute(sa.schema.CreateTable(executions, if_not_exists=True))

    for table in (authorization_requests, executions):
        for index in sorted(table.indexes, key=lambda item: item.name or ""):
            op.execute(sa.schema.CreateIndex(index, if_not_exists=True))


def downgrade() -> None:
    authorization_requests, executions = _tables()
    op.execute(sa.schema.DropTable(executions, if_exists=True))
    op.execute(sa.schema.DropTable(authorization_requests, if_exists=True))
