"""add BANDIT/SAFETY tool_source values and DEPENDENCY location_type value

Revision ID: d4a8e651f2c9
Revises: b7f3a92c1e4d
Create Date: 2026-07-30 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd4a8e651f2c9'
down_revision: Union[str, None] = 'b7f3a92c1e4d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres enum values can only be added outside a transaction block.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE tool_source ADD VALUE IF NOT EXISTS 'BANDIT'")
        op.execute("ALTER TYPE tool_source ADD VALUE IF NOT EXISTS 'SAFETY'")
        op.execute("ALTER TYPE location_type ADD VALUE IF NOT EXISTS 'DEPENDENCY'")


def downgrade() -> None:
    # Postgres has no "remove enum value" operation; downgrading would
    # require recreating tool_source/location_type, which risks data loss
    # if a Bandit/Safety finding already exists. Left as a manual step,
    # same precedent as prior enum-adding migrations.
    pass
