"""add credential_store table

Revision ID: fb13b3966584
Revises: e132b17395d6
Create Date: 2026-07-24 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'fb13b3966584'
down_revision: Union[str, None] = 'e132b17395d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'credential_store',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tool', sa.Enum('NESSUS', 'SONARQUBE', name='credential_tool'), nullable=False),
        sa.Column('base_url', sa.String(length=500), nullable=False),
        sa.Column('api_key', sa.Text(), nullable=True),
        sa.Column('api_secret', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tool'),
    )


def downgrade() -> None:
    op.drop_table('credential_store')
