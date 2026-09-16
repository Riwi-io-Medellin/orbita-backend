from app.modules.access.service import (
    BOOTSTRAP_ROLE_SOURCE,
    MANUAL_ROLE_SOURCE,
    MOODLE_ROLE_SOURCE,
    resolve_effective_role,
)


def test_manual_admin_remains_effective_when_moodle_role_changes():
    assert resolve_effective_role({
        MANUAL_ROLE_SOURCE: "admin",
        MOODLE_ROLE_SOURCE: "student",
    }) == "admin"
    assert resolve_effective_role({
        BOOTSTRAP_ROLE_SOURCE: "admin",
        MOODLE_ROLE_SOURCE: "teamleader",
    }) == "admin"


def test_unrecognized_moodle_role_resolves_to_guest_without_admin():
    assert resolve_effective_role({}) == "guest"
