"""add sso secret rotation grace window

Revision ID: l1a2b3c4d5e6
Revises: k0a1b2c3d4e5
Create Date: 2026-09-01 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "l1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "k0a1b2c3d4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("apps", sa.Column("previous_client_secret_hash", sa.String(length=255), nullable=True))
    op.add_column("apps", sa.Column("previous_secret_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("apps", "previous_secret_expires_at")
    op.drop_column("apps", "previous_client_secret_hash")
