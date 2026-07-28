"""add scan progress/tool_statuses and ZAP credential tool

Revision ID: 9c3f7a21b6d4
Revises: fb13b3966584
Create Date: 2026-07-28 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9c3f7a21b6d4'
down_revision: Union[str, None] = 'fb13b3966584'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column(
        'scans',
        sa.Column(
            'tool_statuses',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_check_constraint(
        'ck_scans_progress_range', 'scans', 'progress BETWEEN 0 AND 100'
    )

    # Postgres enum values can only be added outside a transaction block.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE credential_tool ADD VALUE IF NOT EXISTS 'ZAP'")


def downgrade() -> None:
    op.drop_constraint('ck_scans_progress_range', 'scans', type_='check')
    op.drop_column('scans', 'tool_statuses')
    op.drop_column('scans', 'progress')
    # Postgres has no "remove enum value" operation; downgrading
    # credential_tool would require recreating the type, which risks data
    # loss if a ZAP credential row already exists. Left as a manual step.
