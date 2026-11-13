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
    uuid_type = sa.String(length=36).with_variant(
        sa.UUID(as_uuid=False), 'postgresql'
    )

    # Authorization requests are the durable provenance record consumed by
    # the control plane and referenced by each execution.
    op.create_table(
        'authorization_requests',
        sa.Column('id', uuid_type, nullable=False),
        sa.Column('user_id', uuid_type, nullable=False),
        sa.Column('assessment_id', uuid_type, nullable=False),
        sa.Column('tenant_id', uuid_type, nullable=False),
        sa.Column('operation', sa.String(length=20), nullable=False),
        sa.Column('request_id', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ['user_id'], ['users.id'], ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['assessment_id'], ['assessments.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('request_id'),
    )
    op.create_index(
        'ix_auth_requests_user_id', 'authorization_requests', ['user_id']
    )
    op.create_index(
        'ix_auth_requests_assessment_id',
        'authorization_requests',
        ['assessment_id'],
    )
    op.create_index(
        'ix_auth_requests_request_id',
        'authorization_requests',
        ['request_id'],
    )
    op.create_index(
        'ix_auth_requests_status', 'authorization_requests', ['status']
    )

    # Add execution_id column to authorization_requests
    op.add_column(
        'authorization_requests',
        sa.Column(
            'execution_id',
            uuid_type,
            nullable=True,
        ),
    )

    # Create executions table for durable execution tracking
    op.create_table(
        'executions',
        sa.Column(
            'id',
            uuid_type,
            nullable=False,
        ),
        sa.Column(
            'authorization_request_id',
            uuid_type,
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

    op.drop_index('ix_auth_requests_status', table_name='authorization_requests')
    op.drop_index('ix_auth_requests_request_id', table_name='authorization_requests')
    op.drop_index('ix_auth_requests_assessment_id', table_name='authorization_requests')
    op.drop_index('ix_auth_requests_user_id', table_name='authorization_requests')
    op.drop_table('authorization_requests')
