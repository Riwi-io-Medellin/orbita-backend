"""add local password auth

Revision ID: e4a5b6c7d8e9
Revises: d3f4a5b6c7d8
Create Date: 2026-08-12 00:00:01.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e4a5b6c7d8e9'
down_revision: Union[str, Sequence[str], None] = 'd3f4a5b6c7d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('password_hash', sa.String(length=255), nullable=True))
    op.alter_column('users', 'microsoft_id', existing_type=sa.UUID(), nullable=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column('users', 'microsoft_id', existing_type=sa.UUID(), nullable=False)
    op.drop_column('users', 'password_hash')
