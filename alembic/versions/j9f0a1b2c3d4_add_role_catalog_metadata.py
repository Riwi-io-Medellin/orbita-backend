"""add app-owned role catalog metadata

Revision ID: j9f0a1b2c3d4
Revises: i8e9f0a1b2c3
Create Date: 2026-08-21 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "j9f0a1b2c3d4"
down_revision: Union[str, Sequence[str], None] = "i8e9f0a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("roles", sa.Column("display_name", sa.String(length=120), nullable=True))
    op.add_column("roles", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("roles", sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False))
    op.add_column("roles", sa.Column("managed_by_app", sa.Boolean(), server_default="false", nullable=False))
    op.execute("UPDATE roles SET display_name = name WHERE display_name IS NULL")
    op.alter_column("roles", "display_name", nullable=False)


def downgrade() -> None:
    op.drop_column("roles", "managed_by_app")
    op.drop_column("roles", "is_active")
    op.drop_column("roles", "description")
    op.drop_column("roles", "display_name")
