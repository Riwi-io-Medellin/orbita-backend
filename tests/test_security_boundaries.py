from datetime import UTC, datetime, timedelta
import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.modules.apps.application_lifecycle import hash_client_secret
from app.modules.apps.models import App
from app.modules.apps.service import AppService
from app.modules.auth.csrf import issue_csrf_token, verify_csrf_token
from app.modules.auth.jwt import create_access_token, decode_access_token
from app.security import csrf_and_origin_protection


def request_for(method: str, path: str, *, origin: str, headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(b"origin", origin.encode("ascii"))]
    for name, value in (headers or {}).items():
        raw_headers.append((name.lower().encode("ascii"), value.encode("ascii")))
    return Request({
        "type": "http", "method": method, "path": path, "query_string": b"",
        "headers": raw_headers, "scheme": "http", "server": ("testserver", 80),
    })


@pytest.mark.asyncio
async def test_cookie_mutations_require_trusted_origin_and_session_bound_csrf(monkeypatch):
    async def accepted(_request):
        return Response(status_code=204)

    rejected_origin = await csrf_and_origin_protection(
        request_for("POST", "/api/auth/login", origin="https://evil.example"), accepted,
    )
    assert rejected_origin.status_code == 403

    session_jti = "central-session-id"
    monkeypatch.setattr("app.security.decode_access_token", lambda _token: {"jti": session_jti})

    no_csrf = await csrf_and_origin_protection(
        request_for("POST", "/api/auth/logout", origin="http://localhost:5173"), accepted,
    )
    assert no_csrf.status_code == 403

    valid_csrf = issue_csrf_token(session_jti)
    protected = await csrf_and_origin_protection(
        request_for(
            "POST", "/api/auth/logout", origin="http://localhost:5173",
            headers={"X-CSRF-Token": valid_csrf},
        ),
        accepted,
    )
    assert protected.status_code == 204


def test_csrf_tokens_are_bound_to_session_and_expiry():
    token = issue_csrf_token("session-a")
    assert verify_csrf_token(token, "session-a")
    assert not verify_csrf_token(token, "session-b")
    assert not verify_csrf_token("session-a.1.nonce.invalid", "session-a")


def test_central_jwt_has_unique_session_identifier():
    first = decode_access_token(create_access_token("user-a", "user@example.com", ["coder"]))
    second = decode_access_token(create_access_token("user-a", "user@example.com", ["coder"]))
    assert first["jti"]
    assert first["jti"] != second["jti"]


def test_secret_rotation_accepts_old_secret_only_during_grace_period():
    old_secret = "old-secret"
    app = App(
        client_id="test-app",
        name="Test App",
        client_secret_hash=hash_client_secret("new-secret"),
        previous_client_secret_hash=hash_client_secret(old_secret),
        previous_secret_expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    assert AppService.verify_client_secret(app, "new-secret")
    assert AppService.verify_client_secret(app, old_secret)
    app.previous_secret_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert not AppService.verify_client_secret(app, old_secret)
