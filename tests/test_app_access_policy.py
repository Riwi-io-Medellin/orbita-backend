from app.modules.apps.service import resolve_app_access_policy


def resolve(global_roles, explicit=None, mapped=None, *, migration=True):
    return resolve_app_access_policy(
        global_roles=global_roles,
        explicit_roles=explicit or [],
        mapped_roles=mapped or [],
        role_cardinality="single",
        migration_access_enabled=migration,
    )


def test_guest_is_suppressed_even_with_explicit_role():
    assert resolve(["guest"], explicit=["admin"]).roles == []
    assert resolve(["guest"], explicit=["admin"]).migration is False


def test_explicit_role_precedes_derived_coder():
    access = resolve(["coder"], explicit=["tl_english"], mapped=["coder"])
    assert access.roles == ["tl_english"]


def test_derived_coder_and_temporary_migration_access():
    assert resolve(["coder"], mapped=["coder"]).roles == ["coder"]
    access = resolve(["teamleader"])
    assert access.roles == []
    assert access.migration is True


def test_single_role_policy_fails_closed_on_conflict():
    assert resolve(["admin"], explicit=["admin", "staff"]).roles == []
