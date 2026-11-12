"""add execution_id to authorization_requests and executions table

Revision ID: 6a7b8c9d0e1f
Revises: b7e4c1a92f30
Create Date: 2026-11-11 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '6a7b8c9d0e1f'
down_revision: Union[str, None] = 'b7e4c1a92f30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add execution_id column to authorization_requests
    op.add_column(
        'authorization_requests',
        sa.Column(
            'execution_id',
            sa.String(length=36),
            nullable=True,
        ),
    )

    # Create executions table for durable execution tracking
    op.create_table(
        'executions',
        sa.Column(
            'id',
            sa.String(length=36).with_variant(
                sa.UUID(as_uuid=False), 'postgresql'
            ),
            nullable=False,
        ),
        sa.Column(
            'authorization_request_id',
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column('status', sa.String(20), nullable=False, default='pending'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result', sa.JSON, nullable=True),
        sa.Column('crashed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                   server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(
            ['authorization_request_id'],
            ['authorization_requests.id'],
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_executions_authorization_request_id',
        'executions',
        ['authorization_request_id'],
        unique=True,
    )
    op.create_index(
        'ix_executions_status',
        'executions',
        ['status'],
        unique=False,
    )


def downgrade() -> None:
    # Drop indexes first
    op.drop_index(
        'ix_executions_authorization_request_id', table_name='executions'
    )
    op.drop_index('ix_executions_status', table_name='executions')

    # Drop executions table
    op.drop_table('executions')

    # Remove execution_id column
    op.drop_column('authorization_requests', 'execution_id')
