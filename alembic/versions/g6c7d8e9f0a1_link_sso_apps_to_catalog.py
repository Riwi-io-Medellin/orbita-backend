"""link SSO apps to launcher applications

Revision ID: g6c7d8e9f0a1
Revises: f5b6c7d8e9f0
Create Date: 2026-08-14 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import hashlib
import sqlalchemy as sa


revision: str = "g6c7d8e9f0a1"
down_revision: Union[str, Sequence[str], None] = "f5b6c7d8e9f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("apps", sa.Column("application_id", sa.UUID(), nullable=True))
    op.create_unique_constraint("uq_apps_application_id", "apps", ["application_id"])
    op.create_foreign_key(
        "fk_apps_application_id_applications",
        "apps",
        "applications",
        ["application_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.add_column("authorization_codes", sa.Column("code_hash", sa.String(length=255), nullable=True))
    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id, code FROM authorization_codes")).mappings()
    for row in rows:
        code_hash = hashlib.sha256(row["code"].encode("utf-8")).hexdigest()
        connection.execute(
            sa.text("UPDATE authorization_codes SET code_hash = :code_hash WHERE id = :id"),
            {"code_hash": code_hash, "id": row["id"]},
        )
    op.alter_column("authorization_codes", "code_hash", nullable=False)
    op.create_unique_constraint("uq_authorization_codes_code_hash", "authorization_codes", ["code_hash"])
    op.drop_column("authorization_codes", "code")


def downgrade() -> None:
    op.execute("DELETE FROM authorization_codes")
    op.add_column("authorization_codes", sa.Column("code", sa.String(length=255), nullable=True))
    op.alter_column("authorization_codes", "code", nullable=False)
    op.create_unique_constraint("uq_authorization_codes_code", "authorization_codes", ["code"])
    op.drop_constraint("uq_authorization_codes_code_hash", "authorization_codes", type_="unique")
    op.drop_column("authorization_codes", "code_hash")
    op.drop_constraint("fk_apps_application_id_applications", "apps", type_="foreignkey")
    op.drop_constraint("uq_apps_application_id", "apps", type_="unique")
    op.drop_column("apps", "application_id")
