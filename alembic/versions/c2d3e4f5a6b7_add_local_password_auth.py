"""add local password auth

Revision ID: c2d3e4f5a6b7
Revises: b1e2c3d4e5f6
"""
from alembic import op
import sqlalchemy as sa

revision = "c2d3e4f5a6b7"
down_revision = "b1e2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("users", "microsoft_id", existing_type=sa.UUID(), nullable=True)
    op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "password_hash")
    op.alter_column("users", "microsoft_id", existing_type=sa.UUID(), nullable=False)
