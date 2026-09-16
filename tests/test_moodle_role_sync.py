from types import SimpleNamespace

import pytest

from app.modules.access.service import (
    AccessService,
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


@pytest.mark.asyncio
async def test_ambiguous_moodle_clan_clears_a_previously_synchronized_value():
    attribute = SimpleNamespace(value="McCarthy (PM)", source="moodle", sync_status="synced", observed_at=None)

    class Db:
        async def scalar(self, _query):
            return attribute

        async def commit(self):
            pass

    await AccessService.sync_moodle_clan(
        Db(),
        user_id="user-id",
        role_name="coder",
        clan=None,
        status="ambiguous",
    )

    assert attribute.value is None
    assert attribute.sync_status == "ambiguous"
