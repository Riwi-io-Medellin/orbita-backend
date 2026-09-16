"""retain the applied local-password migration for rollback compatibility

Revision ID: o4d5e6f7a8b9
Revises: n3c4d5e6f7a8

The application feature that used this column was reverted, but production has
already recorded this Alembic revision. Keeping the migration allows the
previous application version to start against that database state.
"""
from alembic import op
import sqlalchemy as sa


revision = "o4d5e6f7a8b9"
down_revision = "n3c4d5e6f7a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("must_change_password", sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
