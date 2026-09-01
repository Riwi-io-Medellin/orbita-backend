"""HTTP boundary protections for browser requests authenticated by cookies."""

from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from app.config.settings import settings
from app.modules.auth.csrf import verify_csrf_token
from app.modules.auth.jwt import decode_access_token

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SERVER_TO_SERVER_PATHS = {"/api/auth/token", "/api/auth/introspect"}
_PUBLIC_AUTH_PATHS = {
    "/api/auth/login",
    "/api/auth/moodle/login",
    "/api/auth/moodle/password-reset",
}


def _is_server_to_server(request: Request) -> bool:
    return request.url.path in _SERVER_TO_SERVER_PATHS or (
        request.url.path.startswith("/api/apps/") and request.url.path.endswith("/role-catalog")
    )


def _trusted_origins() -> set[str]:
    return settings.allowed_frontend_origins() | {settings.resolved_public_base_url.rstrip("/")}


async def csrf_and_origin_protection(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if request.method not in _UNSAFE_METHODS or not request.url.path.startswith("/api/"):
        return await call_next(request)
    if _is_server_to_server(request):
        return await call_next(request)

    origin = request.headers.get("origin", "").rstrip("/")
    if origin not in _trusted_origins():
        return JSONResponse(status_code=403, content={"detail": "Untrusted request origin"})

    # Login/reset requests have no central session yet. Origin validation protects them from browser CSRF.
    if request.url.path in _PUBLIC_AUTH_PATHS:
        return await call_next(request)

    payload = decode_access_token(request.cookies.get(settings.access_cookie_name, ""))
    if not verify_csrf_token(request.headers.get("x-csrf-token"), payload.get("jti")):
        return JSONResponse(status_code=403, content={"detail": "CSRF validation failed"})
    return await call_next(request)
