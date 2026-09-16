from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.modules.apps import router as apps_router
from app.modules.users.schemas import BulkUserIds


@pytest.mark.asyncio
async def test_list_app_users_includes_role_identifier(monkeypatch):
    user_id = uuid4()
    role_id = uuid4()
    app = SimpleNamespace(id=uuid4())

    async def get_app(_db, _client_id):
        return app

    async def list_rows(_db, _app, *, limit, offset):
        assert (limit, offset) == (20, 0)
        return [(user_id, "person@riwi.io", "Persona Riwi", role_id, "admin")]

    monkeypatch.setattr(apps_router.AppService, "get_by_client_id", get_app)
    monkeypatch.setattr(apps_router.RoleService, "list_user_roles_for_app", list_rows)

    rows = await apps_router.list_app_users("teamlead", limit=20, offset=0, db=object())

    assert rows[0].user_id == user_id
    assert rows[0].role_id == role_id
    assert rows[0].role_name == "admin"


@pytest.mark.asyncio
async def test_bulk_assignment_forwards_every_selected_user(monkeypatch):
    app = SimpleNamespace(id=uuid4())
    role = SimpleNamespace(id=uuid4())
    user_ids = [uuid4(), uuid4()]
    captured: dict[str, object] = {}

    async def get_app(_db, _client_id):
        return app

    async def get_role(_db, _app, role_id):
        assert role_id == role.id
        return role

    async def assign_many(_db, received_user_ids, received_app, received_role):
        captured["user_ids"] = received_user_ids
        assert received_app is app
        assert received_role is role
        return received_user_ids, []

    monkeypatch.setattr(apps_router.AppService, "get_by_client_id", get_app)
    monkeypatch.setattr(apps_router.RoleService, "get_role_by_id", get_role)
    monkeypatch.setattr(apps_router.RoleService, "bulk_assign_role_to_users", assign_many)

    result = await apps_router.bulk_assign_role(
        "teamlead", role.id, BulkUserIds(user_ids=user_ids), db=object(),
    )

    assert captured["user_ids"] == user_ids
    assert result.updated_user_ids == user_ids
