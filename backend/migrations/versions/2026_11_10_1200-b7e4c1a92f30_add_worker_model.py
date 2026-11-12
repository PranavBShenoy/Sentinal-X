"""add_worker_model

Revision ID: b7e4c1a92f30
Revises: 1dca02b9811e
Create Date: 2026-11-10 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b7e4c1a92f30'
down_revision: Union[str, None] = '1dca02b9811e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'workers',
        sa.Column(
            'id',
            sa.String(length=36).with_variant(
                sa.UUID(as_uuid=False), 'postgresql'
            ),
            nullable=False,
        ),
        sa.Column(
            'user_id',
            sa.String(length=36).with_variant(
                sa.UUID(as_uuid=False), 'postgresql'
            ),
            nullable=False,
        ),
        sa.Column('cert_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('cert_subject', sa.String(length=500), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_workers_cert_fingerprint'),
        'workers',
        ['cert_fingerprint'],
        unique=True,
    )
    op.create_index(
        'ix_workers_user_id', 'workers', ['user_id'], unique=False
    )


def downgrade() -> None:
    op.drop_index('ix_workers_user_id', table_name='workers')
    op.drop_index(op.f('ix_workers_cert_fingerprint'), table_name='workers')
    op.drop_table('workers')
