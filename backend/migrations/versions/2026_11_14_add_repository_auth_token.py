"""Add encrypted auth token and token type to repositories.

Revision ID: c8d9e0f1a2b3
Revises: 6a7b8c9d0e1f
Create Date: 2026-11-14 23:55:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c8d9e0f1a2b3"
down_revision: Union[str, None] = "6a7b8c9d0e1f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use batch_alter_table for SQLite compatibility in tests and PostgreSQL in prod
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.add_column(sa.Column("encrypted_auth_token", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("auth_token_type", sa.String(length=50), nullable=True, server_default="pat")
        )


def downgrade() -> None:
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.drop_column("auth_token_type")
        batch_op.drop_column("encrypted_auth_token")
