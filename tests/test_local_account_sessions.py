from datetime import datetime, UTC
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.modules.auth import router as auth_router
from app.modules.auth.dependencies import get_current_user
from app.modules.auth.jwt import create_access_token, decode_access_token
from app.modules.auth.passwords import hash_password, verify_password
from app.modules.auth.schemas import PasswordChangeRequest
from app.modules.users.models import User
from app.modules.users import router as users_router
from app.modules.users.schemas import LocalUserCreate


def request_for(path: str = "/api/apps") -> Request:
    return Request({"type": "http", "method": "GET", "path": path, "headers": []})


def test_central_token_records_authentication_method():
    token = create_access_token("user-id", "user@example.com", ["coder"], auth_method="moodle")

    assert decode_access_token(token)["auth_method"] == "moodle"


def test_password_change_requirement_only_applies_to_local_session(monkeypatch):
    user = SimpleNamespace(must_change_password=True)
    request = request_for()

    monkeypatch.setattr(auth_router, "decode_access_token", lambda _token: {"auth_method": "local"})
    assert auth_router._local_password_change_required(request, user) is True

    monkeypatch.setattr(auth_router, "decode_access_token", lambda _token: {"auth_method": "moodle"})
    assert auth_router._local_password_change_required(request, user) is False

    monkeypatch.setattr(auth_router, "decode_access_token", lambda _token: {"auth_method": "microsoft"})
    assert auth_router._local_password_change_required(request, user) is False


@pytest.mark.asyncio
async def test_local_temporary_password_blocks_regular_protected_routes(monkeypatch):
    user = User(is_active=True, must_change_password=True)
    request = request_for()

    monkeypatch.setattr("app.modules.auth.dependencies.decode_access_token", lambda _token: {
        "sub": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
        "auth_method": "local",
    })

    async def get_user(_db, _user_id):
        return user

    monkeypatch.setattr("app.modules.auth.dependencies.UserService.get_user_by_id", get_user)
    request.scope["headers"] = [(b"cookie", b"access_token=fake")]

    with pytest.raises(HTTPException) as raised:
        await get_current_user(request, db=object())

    assert raised.value.status_code == 403
    assert raised.value.detail == "password_change_required"


@pytest.mark.asyncio
async def test_moodle_session_is_not_blocked_by_local_temporary_password(monkeypatch):
    user = User(is_active=True, must_change_password=True)
    request = request_for()

    monkeypatch.setattr("app.modules.auth.dependencies.decode_access_token", lambda _token: {
        "sub": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
        "auth_method": "moodle",
    })

    async def get_user(_db, _user_id):
        return user

    monkeypatch.setattr("app.modules.auth.dependencies.UserService.get_user_by_id", get_user)
    request.scope["headers"] = [(b"cookie", b"access_token=fake")]

    assert await get_current_user(request, db=object()) is user


@pytest.mark.asyncio
async def test_password_change_clears_first_login_requirement(monkeypatch):
    user = User(id=uuid4(), password_hash=hash_password("temporary-password"), must_change_password=True)

    class FakeDb:
        async def commit(self):
            return None

    async def no_op(*_args, **_kwargs):
        return None

    monkeypatch.setattr(auth_router.AppSessionService, "revoke_all_for_user", no_op)
    monkeypatch.setattr(auth_router.AccessService, "audit", no_op)

    result = await auth_router.change_current_user_password(
        PasswordChangeRequest(current_password="temporary-password", new_password="permanent-password"),
        request_for("/api/auth/me/password"),
        current_user=user,
        db=FakeDb(),
    )

    assert result == {"message": "Contraseña actualizada"}
    assert user.must_change_password is False
    assert verify_password("permanent-password", user.password_hash)


@pytest.mark.asyncio
async def test_admin_created_local_user_gets_one_time_password(monkeypatch):
    captured: dict[str, object] = {}
    created = User(
        id=uuid4(),
        email="new.user@example.com",
        full_name="New User",
        is_active=True,
        password_hash="placeholder",
        must_change_password=True,
        created_at=datetime.now(UTC),
        deleted_at=None,
    )

    async def get_by_email(_db, _email):
        return None

    async def create_user(_db, **kwargs):
        captured.update(kwargs)
        created.password_hash = kwargs["password_hash"]
        return created

    async def no_op(*_args, **_kwargs):
        return None

    monkeypatch.setattr(users_router.UserService, "get_by_email", get_by_email)
    monkeypatch.setattr(users_router.UserService, "create_local_user", create_user)
    monkeypatch.setattr(users_router.AccessService, "ensure_default_role", no_op)
    monkeypatch.setattr(users_router.AccessService, "audit", no_op)

    response = await users_router.create_local_user(
        LocalUserCreate(email="new.user@example.com", full_name="New User"),
        request_for("/api/users/"),
        db=object(),
    )

    assert response.email == "new.user@example.com"
    assert response.must_change_password is True
    assert captured["is_active"] is True
    assert captured["must_change_password"] is True
    assert verify_password(response.temporary_password, str(captured["password_hash"]))
