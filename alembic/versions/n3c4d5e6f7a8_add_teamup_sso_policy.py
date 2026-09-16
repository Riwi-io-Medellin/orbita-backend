"""add TeamUp SSO policy, claims and logout tickets

Revision ID: n3c4d5e6f7a8
Revises: m2b3c4d5e6f7
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "n3c4d5e6f7a8"
down_revision = "m2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("apps", sa.Column("role_cardinality", sa.String(16), server_default="multiple", nullable=False))
    op.add_column("apps", sa.Column("migration_access_enabled", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("apps", sa.Column("jit_role_adoption_enabled", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("apps", sa.Column("released_claims", postgresql.JSONB(), server_default="[]", nullable=False))
    op.add_column("user_app_roles", sa.Column("source", sa.String(32), server_default="manual", nullable=False))
    op.create_check_constraint("ck_apps_role_cardinality", "apps", "role_cardinality IN ('single', 'multiple')")

    op.create_table(
        "app_post_logout_uris",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("app_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("apps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("post_logout_uri", sa.String(2048), nullable=False),
        sa.UniqueConstraint("app_id", "post_logout_uri", name="uq_app_post_logout_uri"),
    )
    op.create_table(
        "app_global_role_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("app_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("apps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("global_role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("global_roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("app_role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("app_id", "global_role_id", name="uq_app_global_role_mapping"),
    )
    op.create_table(
        "user_federated_attributes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("value", sa.String(255), nullable=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("sync_status", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "name", name="uq_user_federated_attribute"),
    )
    op.create_table(
        "logout_tickets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ticket_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("app_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("apps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("post_logout_uri", sa.String(2048), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("logout_tickets")
    op.drop_table("user_federated_attributes")
    op.drop_table("app_global_role_mappings")
    op.drop_table("app_post_logout_uris")
    op.drop_constraint("ck_apps_role_cardinality", "apps", type_="check")
    op.drop_column("user_app_roles", "source")
    op.drop_column("apps", "released_claims")
    op.drop_column("apps", "jit_role_adoption_enabled")
    op.drop_column("apps", "migration_access_enabled")
    op.drop_column("apps", "role_cardinality")
