from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.modules.apps import router as apps_router


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
