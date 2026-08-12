"""add access control and audit

Revision ID: b1e2c3d4e5f6
Revises: dec8400918b6
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b1e2c3d4e5f6"
down_revision = "dec8400918b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("roles",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("name"),
    )
    op.create_table("applications",
        sa.Column("id", sa.UUID(), nullable=False), sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False), sa.Column("description", sa.Text(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False), sa.Column("icon", sa.String(length=50)),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("slug"),
    )
    op.create_table("user_roles",
        sa.Column("user_id", sa.UUID(), nullable=False), sa.Column("role_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
    )
    op.create_table("application_roles",
        sa.Column("application_id", sa.UUID(), nullable=False), sa.Column("role_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("application_id", "role_id"),
    )
    op.create_table("audit_logs",
        sa.Column("id", sa.UUID(), nullable=False), sa.Column("user_id", sa.UUID()), sa.Column("event", sa.String(length=100), nullable=False),
        sa.Column("application_id", sa.UUID()), sa.Column("ip_address", sa.String(length=64)), sa.Column("user_agent", sa.String(length=512)),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="SET NULL"), sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_user_created_at", "audit_logs", ["user_id", "created_at"])
    op.create_index("ix_audit_logs_event_created_at", "audit_logs", ["event", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_event_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_created_at", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("application_roles")
    op.drop_table("user_roles")
    op.drop_table("applications")
    op.drop_table("roles")
