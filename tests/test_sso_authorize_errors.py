import pytest
from fastapi import HTTPException, status
from starlette.requests import Request

from app.config.settings import settings
from app.modules.auth import router as auth_router


def request_for_authorize() -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/auth/authorize",
        "query_string": b"",
        "headers": [],
        "scheme": "https",
        "server": ("testserver", 443),
    })


@pytest.mark.asyncio
async def test_authorize_redirects_authenticated_unprovisioned_user_to_ui(monkeypatch):
    app = object()
    user = object()

    async def get_app(_db, _client_id):
        return app

    async def is_available(_db, _app):
        return True

    async def valid_redirect(_db, _app, _redirect_uri):
        return True

    async def current_user(_request, _db):
        return user

    async def denied(_db, _user, _client_id, _redirect_uri, _state):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not provisioned for this app",
        )

    monkeypatch.setattr(auth_router.AppService, "get_by_client_id", get_app)
    monkeypatch.setattr(auth_router.AppService, "is_available_for_sso", is_available)
    monkeypatch.setattr(auth_router.AppService, "validate_redirect_uri", valid_redirect)
    monkeypatch.setattr(auth_router, "_get_optional_current_user", current_user)
    monkeypatch.setattr(auth_router, "build_authorize_redirect", denied)

    response = await auth_router.start_sso_authorization(
        request_for_authorize(),
        client_id="teamlead",
        redirect_uri="https://teamlead.example/callback",
        state="state-with-at-least-16-chars",
        db=object(),
    )

    assert response.status_code == 302
    assert response.headers["location"] == (
        f"{settings.frontend_url}/auth?error=sso_access_denied"
    )
