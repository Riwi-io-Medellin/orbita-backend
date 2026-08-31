"""add external identity providers

Revision ID: k0a1b2c3d4e5
Revises: j9f0a1b2c3d4
Create Date: 2026-08-30 00:00:00.000000
"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "k0a1b2c3d4e5"
down_revision: Union[str, Sequence[str], None] = "j9f0a1b2c3d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # A case-insensitive unique index is required before email is used for the
    # one-time external account correlation. Stop safely rather than deciding
    # which historical person should win a collision.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM users
                GROUP BY lower(btrim(email))
                HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION 'Cannot add normalized email uniqueness: duplicate users.email values exist';
            END IF;
        END $$;
    """)
    op.create_index("uq_users_email_normalized", "users", [sa.text("lower(btrim(email))")], unique=True)

    op.create_table(
        "providers",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )
    op.bulk_insert(
        sa.table(
            "providers",
            sa.column("id", sa.UUID()), sa.column("code", sa.String()), sa.column("name", sa.String()),
            sa.column("type", sa.String()), sa.column("active", sa.Boolean()),
        ),
        [
            {"id": uuid.uuid4(), "code": "microsoft", "name": "Microsoft", "type": "oauth", "active": False},
            {"id": uuid.uuid4(), "code": "moodle", "name": "Moodle", "type": "credentials", "active": True},
        ],
    )
    # Provider codes are part of the identity contract (and of the tenant
    # invariant below), so they must not be renamed after identities exist.
    op.execute("""
        CREATE FUNCTION prevent_provider_code_change()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.code <> OLD.code THEN
                RAISE EXCEPTION 'Provider code is immutable';
            END IF;
            RETURN NEW;
        END;
        $$;
    """)
    op.execute("""
        CREATE TRIGGER trg_provider_code_immutable
        BEFORE UPDATE OF code ON providers
        FOR EACH ROW EXECUTE FUNCTION prevent_provider_code_change()
    """)
    op.create_table(
        "external_identities",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("provider_id", sa.UUID(), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("provider_tenant_id", sa.String(length=255), nullable=True),
        sa.Column("provider_email", sa.String(length=255), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("length(btrim(provider_user_id)) > 0", name="ck_external_identity_subject_present"),
        sa.ForeignKeyConstraint(["provider_id"], ["providers.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "provider_id", name="uq_external_identity_user_provider"),
    )
    op.execute("""
        CREATE UNIQUE INDEX uq_external_identity_provider_subject
        ON external_identities (provider_id, COALESCE(provider_tenant_id, ''), provider_user_id)
    """)
    op.execute("""
        CREATE FUNCTION enforce_external_identity_provider_tenant()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE provider_code text;
        BEGIN
            SELECT code INTO provider_code FROM providers WHERE id = NEW.provider_id;
            IF provider_code IS NULL THEN
                RAISE EXCEPTION 'External identity references an unknown provider';
            END IF;
            IF provider_code = 'moodle' AND NEW.provider_tenant_id IS NOT NULL THEN
                RAISE EXCEPTION 'Moodle external identities must not have a tenant id';
            END IF;
            IF provider_code = 'microsoft' AND NEW.provider_tenant_id IS NULL THEN
                RAISE EXCEPTION 'Microsoft external identities require a tenant id';
            END IF;
            RETURN NEW;
        END;
        $$;
    """)
    op.execute("""
        CREATE TRIGGER trg_external_identity_provider_tenant
        BEFORE INSERT OR UPDATE OF provider_id, provider_tenant_id ON external_identities
        FOR EACH ROW EXECUTE FUNCTION enforce_external_identity_provider_tenant()
    """)
    op.create_table(
        "moodle_login_failures",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("subject_hash", sa.String(length=64), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=False),
        sa.Column("failed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_moodle_login_failures_subject_hash", "moodle_login_failures", ["subject_hash"])
    op.create_index("ix_moodle_login_failures_ip_hash", "moodle_login_failures", ["ip_hash"])
    op.create_index("ix_moodle_login_failures_failed_at", "moodle_login_failures", ["failed_at"])


def downgrade() -> None:
    op.drop_index("ix_moodle_login_failures_failed_at", table_name="moodle_login_failures")
    op.drop_index("ix_moodle_login_failures_ip_hash", table_name="moodle_login_failures")
    op.drop_index("ix_moodle_login_failures_subject_hash", table_name="moodle_login_failures")
    op.drop_table("moodle_login_failures")
    op.execute("DROP TRIGGER trg_external_identity_provider_tenant ON external_identities")
    op.execute("DROP FUNCTION enforce_external_identity_provider_tenant()")
    op.execute("DROP INDEX uq_external_identity_provider_subject")
    op.drop_table("external_identities")
    op.execute("DROP TRIGGER trg_provider_code_immutable ON providers")
    op.execute("DROP FUNCTION prevent_provider_code_change()")
    op.drop_table("providers")
    op.drop_index("uq_users_email_normalized", table_name="users")
