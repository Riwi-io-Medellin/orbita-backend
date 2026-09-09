from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.modules.access.service import AccessService
from app.modules.auth.dependencies import get_current_platform_admin
from app.modules.users.models import User


class RoleLookupDatabase:
    def __init__(self, role_id=None):
        self.role_id = role_id

    async def scalar(self, _statement):
        return self.role_id


class BootstrapDatabase:
    def __init__(self, users, admin_role_id):
        self.users = users
        self.admin_role_id = admin_role_id
        self.executed = []
        self.commits = 0

    async def scalars(self, _statement):
        return iter(self.users)

    async def scalar(self, _statement):
        return self.admin_role_id

    async def execute(self, statement):
        self.executed.append(statement)

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_global_admin_role_authorizes_platform_administration():
    user = User(id=uuid4(), email="admin@example.com", full_name="Admin", is_active=True)

    result = await get_current_platform_admin(
        current_user=user,
        db=RoleLookupDatabase(role_id=uuid4()),
    )

    assert result is user


@pytest.mark.asyncio
async def test_missing_global_admin_role_is_forbidden():
    user = User(id=uuid4(), email="staff@example.com", full_name="Staff", is_active=True)

    with pytest.raises(HTTPException) as exc_info:
        await get_current_platform_admin(current_user=user, db=RoleLookupDatabase())

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_bootstrap_assigns_admin_role_without_changing_account_status():
    user = User(id=uuid4(), email="admin@example.com", full_name="Admin", is_active=False)
    db = BootstrapDatabase(users=[user], admin_role_id=uuid4())

    await AccessService.bootstrap_platform_admins(db, [" ADMIN@example.com "])

    assert user.is_active is False
    assert len(db.executed) == 1
    assert db.commits == 1
