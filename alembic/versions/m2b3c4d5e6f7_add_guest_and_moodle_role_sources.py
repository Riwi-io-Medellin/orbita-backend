"""add guest role and Moodle role sources

Revision ID: m2b3c4d5e6f7
Revises: l0a1b2c3d4e5
"""
from alembic import op


revision = "m2b3c4d5e6f7"
down_revision = "l0a1b2c3d4e5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Keep current staff-based access intact while changing its stable key.
    op.execute("""
        INSERT INTO global_roles (id, name, description)
        SELECT gen_random_uuid(), 'teamleader', 'Liderazgo académico de Riwi'
        WHERE NOT EXISTS (SELECT 1 FROM global_roles WHERE name = 'teamleader')
    """)
    op.execute("""
        INSERT INTO global_roles (id, name, description)
        SELECT gen_random_uuid(), 'guest', 'Cuenta sin rol ni acceso por catálogo'
        WHERE NOT EXISTS (SELECT 1 FROM global_roles WHERE name = 'guest')
    """)
    op.execute("""
        INSERT INTO user_global_roles (user_id, global_role_id)
        SELECT ugr.user_id, teamleader.id
        FROM user_global_roles ugr
        JOIN global_roles staff ON staff.id = ugr.global_role_id AND staff.name = 'staff'
        JOIN global_roles teamleader ON teamleader.name = 'teamleader'
        ON CONFLICT DO NOTHING
    """)
    op.execute("""
        INSERT INTO application_global_roles (application_id, global_role_id)
        SELECT agr.application_id, teamleader.id
        FROM application_global_roles agr
        JOIN global_roles staff ON staff.id = agr.global_role_id AND staff.name = 'staff'
        JOIN global_roles teamleader ON teamleader.name = 'teamleader'
        ON CONFLICT DO NOTHING
    """)
    op.execute("""
        DELETE FROM user_global_roles
        WHERE global_role_id IN (SELECT id FROM global_roles WHERE name = 'staff')
    """)
    op.execute("""
        DELETE FROM application_global_roles
        WHERE global_role_id IN (SELECT id FROM global_roles WHERE name = 'staff')
    """)
    op.execute("DELETE FROM global_roles WHERE name = 'staff'")

    op.execute("""
        CREATE TABLE user_global_role_sources (
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            global_role_id UUID NOT NULL REFERENCES global_roles(id) ON DELETE CASCADE,
            source VARCHAR(32) NOT NULL,
            PRIMARY KEY (user_id, global_role_id, source)
        )
    """)
    # Existing assignments were administered before provenance existed.
    op.execute("""
        INSERT INTO user_global_role_sources (user_id, global_role_id, source)
        SELECT user_id, global_role_id, 'manual' FROM user_global_roles
    """)
    op.execute("""
        INSERT INTO user_global_role_sources (user_id, global_role_id, source)
        SELECT users.id, guest.id, 'fallback'
        FROM users CROSS JOIN global_roles guest
        WHERE guest.name = 'guest'
          AND NOT EXISTS (
              SELECT 1 FROM user_global_roles ugr WHERE ugr.user_id = users.id
          )
    """)
    op.execute("""
        INSERT INTO user_global_roles (user_id, global_role_id)
        SELECT sources.user_id, sources.global_role_id
        FROM user_global_role_sources sources
        JOIN global_roles role ON role.id = sources.global_role_id AND role.name = 'guest'
        ON CONFLICT DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DROP TABLE user_global_role_sources")
    op.execute("""
        INSERT INTO global_roles (id, name, description)
        SELECT gen_random_uuid(), 'staff', 'Personal interno de Riwi'
        WHERE NOT EXISTS (SELECT 1 FROM global_roles WHERE name = 'staff')
    """)
    op.execute("""
        INSERT INTO user_global_roles (user_id, global_role_id)
        SELECT ugr.user_id, staff.id
        FROM user_global_roles ugr
        JOIN global_roles teamleader ON teamleader.id = ugr.global_role_id AND teamleader.name = 'teamleader'
        JOIN global_roles staff ON staff.name = 'staff'
        ON CONFLICT DO NOTHING
    """)
    op.execute("""
        INSERT INTO application_global_roles (application_id, global_role_id)
        SELECT agr.application_id, staff.id
        FROM application_global_roles agr
        JOIN global_roles teamleader ON teamleader.id = agr.global_role_id AND teamleader.name = 'teamleader'
        JOIN global_roles staff ON staff.name = 'staff'
        ON CONFLICT DO NOTHING
    """)
    op.execute("DELETE FROM user_global_roles WHERE global_role_id IN (SELECT id FROM global_roles WHERE name IN ('guest', 'teamleader'))")
    op.execute("DELETE FROM application_global_roles WHERE global_role_id IN (SELECT id FROM global_roles WHERE name = 'teamleader')")
    op.execute("DELETE FROM global_roles WHERE name IN ('guest', 'teamleader')")
