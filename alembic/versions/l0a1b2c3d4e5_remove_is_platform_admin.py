"""remove is_platform_admin in favor of the global admin role

Revision ID: l0a1b2c3d4e5
Revises: l1a2b3c4d5e6
Create Date: 2026-09-09 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "l0a1b2c3d4e5"
down_revision: Union[str, Sequence[str], None] = "l1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Preserve every existing platform administrator by granting the canonical
    # global role before removing the duplicate boolean source of truth.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM users WHERE is_platform_admin = true)
               AND NOT EXISTS (SELECT 1 FROM global_roles WHERE name = 'admin') THEN
                RAISE EXCEPTION 'Cannot migrate platform admins: global admin role is missing';
            END IF;
        END $$;
    """)
    op.execute("""
        INSERT INTO user_global_roles (user_id, global_role_id)
        SELECT users.id, global_roles.id
        FROM users
        JOIN global_roles ON global_roles.name = 'admin'
        WHERE users.is_platform_admin = true
        ON CONFLICT DO NOTHING
    """)
    op.drop_column("users", "is_platform_admin")


def downgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute("""
        UPDATE users
        SET is_platform_admin = true
        FROM user_global_roles, global_roles
        WHERE user_global_roles.user_id = users.id
          AND user_global_roles.global_role_id = global_roles.id
          AND global_roles.name = 'admin'
    """)
