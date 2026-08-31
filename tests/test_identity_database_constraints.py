import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest


ROOT = Path(__file__).resolve().parents[1]


def _test_database_url() -> str:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not configured")
    database_name = url.rsplit("/", 1)[-1].split("?", 1)[0]
    if not database_name.endswith("_test"):
        pytest.fail("TEST_DATABASE_URL must point to a disposable database whose name ends in _test")
    return url


@pytest.mark.integration
def test_provider_tenant_and_identity_uniqueness_are_enforced_by_postgresql():
    async_url = _test_database_url()
    environment = {**os.environ, "DATABASE_URL": async_url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    database_url = async_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    with psycopg.connect(database_url) as connection:
        moodle_id, microsoft_id = connection.execute(
            "SELECT id, code FROM providers WHERE code IN ('moodle', 'microsoft') ORDER BY code"
        ).fetchall()
        provider_ids = {code: provider_id for provider_id, code in (moodle_id, microsoft_id)}
        user_id = uuid4()
        connection.execute(
            "INSERT INTO users (id, email, full_name, is_active) VALUES (%s, %s, %s, true)",
            (user_id, f"identity-constraint-{user_id}@riwi.io", "Identity Constraint"),
        )
        connection.execute(
            """
            INSERT INTO external_identities (id, user_id, provider_id, provider_user_id, provider_tenant_id)
            VALUES (%s, %s, %s, %s, NULL)
            """,
            (uuid4(), user_id, provider_ids["moodle"], "1909"),
        )
        connection.commit()

        with pytest.raises(psycopg.Error):
            connection.execute("UPDATE providers SET code = 'renamed-moodle' WHERE code = 'moodle'")
        connection.rollback()

        with pytest.raises(psycopg.Error):
            connection.execute(
                """
                INSERT INTO external_identities (id, user_id, provider_id, provider_user_id, provider_tenant_id)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (uuid4(), uuid4(), provider_ids["moodle"], "bad-moodle", "tenant-not-allowed"),
            )
        connection.rollback()

        connection.execute(
            """
            INSERT INTO external_identities (id, user_id, provider_id, provider_user_id, provider_tenant_id)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (uuid4(), user_id, provider_ids["microsoft"], "oid-123", "tenant-123"),
        )
        connection.commit()

        with pytest.raises(psycopg.Error):
            connection.execute(
                """
                INSERT INTO external_identities (id, user_id, provider_id, provider_user_id, provider_tenant_id)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (uuid4(), user_id, provider_ids["microsoft"], "another-oid", "tenant-123"),
            )
        connection.rollback()

        with pytest.raises(psycopg.Error):
            connection.execute(
                """
                INSERT INTO external_identities (id, user_id, provider_id, provider_user_id, provider_tenant_id)
                VALUES (%s, %s, %s, %s, NULL)
                """,
                (uuid4(), uuid4(), provider_ids["moodle"], "1909"),
            )
        connection.rollback()

        with pytest.raises(psycopg.Error):
            connection.execute(
                """
                INSERT INTO external_identities (id, user_id, provider_id, provider_user_id, provider_tenant_id)
                VALUES (%s, %s, %s, %s, NULL)
                """,
                (uuid4(), uuid4(), provider_ids["microsoft"], "oid-without-tenant"),
            )
        connection.rollback()
