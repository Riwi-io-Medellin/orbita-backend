"""add application-scoped access and SSO

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
"""
from alembic import op
import sqlalchemy as sa


revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "application_access_roles",
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("key", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("application_id", "key"),
    )
    op.create_table(
        "user_application_access_roles",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("role_key", sa.String(length=80), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["application_id", "role_key"],
            ["application_access_roles.application_id", "application_access_roles.key"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "application_id", "role_key"),
    )
    op.create_table(
        "application_clients",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("client_id", sa.String(length=120), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=512), nullable=False),
        sa.Column("redirect_uri", sa.String(length=2048), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id"),
        sa.UniqueConstraint("client_id"),
    )
    op.create_table(
        "sso_authorization_codes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=2048), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["application_clients.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index("ix_sso_authorization_codes_expires_at", "sso_authorization_codes", ["expires_at"])

    # Preserve the access granted by the legacy global-role mapping while future
    # assignments use roles scoped to a single application.
    op.execute("""
        INSERT INTO application_access_roles (application_id, key, name, description)
        SELECT application_roles.application_id, roles.name, roles.name, roles.description
        FROM application_roles
        JOIN roles ON roles.id = application_roles.role_id
        ON CONFLICT (application_id, key) DO NOTHING
    """)
    op.execute("""
        INSERT INTO user_application_access_roles (user_id, application_id, role_key)
        SELECT user_roles.user_id, application_roles.application_id, roles.name
        FROM user_roles
        JOIN roles ON roles.id = user_roles.role_id
        JOIN application_roles ON application_roles.role_id = roles.id
        ON CONFLICT (user_id, application_id, role_key) DO NOTHING
    """)


def downgrade() -> None:
    op.drop_index("ix_sso_authorization_codes_expires_at", table_name="sso_authorization_codes")
    op.drop_table("sso_authorization_codes")
    op.drop_table("application_clients")
    op.drop_table("user_application_access_roles")
    op.drop_table("application_access_roles")
