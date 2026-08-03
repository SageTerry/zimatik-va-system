"""add threat_status and threat_intel_enriched_at to findings

Revision ID: c8b2f4a91d67
Revises: a1c8e4f9b3d2
Create Date: 2026-07-31 16:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c8b2f4a91d67'
down_revision: Union[str, None] = 'a1c8e4f9b3d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    threat_status = sa.Enum(
        'ACTIVELY_EXPLOITED', 'POC_AVAILABLE', 'PATCH_AVAILABLE', 'MONITOR', 'UNKNOWN',
        name='threat_status',
    )
    threat_status.create(op.get_bind())

    op.add_column(
        'findings',
        sa.Column(
            'threat_status', threat_status, nullable=False, server_default='UNKNOWN'
        ),
    )
    op.add_column(
        'findings',
        sa.Column('threat_intel_enriched_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_findings_threat_status', 'findings', ['threat_status'])


def downgrade() -> None:
    op.drop_index('ix_findings_threat_status', table_name='findings')
    op.drop_column('findings', 'threat_intel_enriched_at')
    op.drop_column('findings', 'threat_status')
    sa.Enum(name='threat_status').drop(op.get_bind())
