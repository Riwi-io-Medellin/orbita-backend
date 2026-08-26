"""make the launcher access policy explicit

Revision ID: i8e9f0a1b2c3
Revises: h7d8e9f0a1b2
Create Date: 2026-08-21 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "i8e9f0a1b2c3"
down_revision: Union[str, Sequence[str], None] = "h7d8e9f0a1b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "applications",
        sa.Column("access_policy", sa.String(length=32), server_default="catalog", nullable=False),
    )
    op.execute(
        """
        UPDATE applications
        SET access_policy = 'sso_role'
        FROM apps
        WHERE apps.application_id = applications.id
        """
    )


def downgrade() -> None:
    op.drop_column("applications", "access_policy")
