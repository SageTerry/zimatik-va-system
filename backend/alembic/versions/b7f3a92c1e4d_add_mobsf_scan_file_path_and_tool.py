"""add scans.file_path and MobSF tool/credential enum values

Revision ID: b7f3a92c1e4d
Revises: 9c3f7a21b6d4
Create Date: 2026-07-30 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b7f3a92c1e4d'
down_revision: Union[str, None] = '9c3f7a21b6d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column(
            'file_path',
            sa.String(length=1000),
            nullable=True,
        ),
    )

    # Postgres enum values can only be added outside a transaction block.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE tool_source ADD VALUE IF NOT EXISTS 'MOBSF'")
        op.execute("ALTER TYPE credential_tool ADD VALUE IF NOT EXISTS 'MOBSF'")


def downgrade() -> None:
    op.drop_column('scans', 'file_path')
    # Postgres has no "remove enum value" operation; downgrading tool_source/
    # credential_tool would require recreating both types, which risks data
    # loss if a MobSF finding or credential row already exists. Left as a
    # manual step, same precedent as the ZAP credential-tool migration.
