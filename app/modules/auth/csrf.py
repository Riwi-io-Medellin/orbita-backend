"""CSRF tokens bound to a signed central-session JWT identifier."""

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from app.config.settings import settings

CSRF_TTL_MINUTES = 30


def issue_csrf_token(session_jti: str) -> str:
    expires_at = int((datetime.now(UTC) + timedelta(minutes=CSRF_TTL_MINUTES)).timestamp())
    nonce = secrets.token_urlsafe(16)
    payload = f"{session_jti}.{expires_at}.{nonce}"
    signature = hmac.new(
        settings.csrf_signing_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).digest()
    return f"{payload}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')}"


def verify_csrf_token(token: str | None, session_jti: str | None) -> bool:
    if not token or not session_jti:
        return False
    try:
        token_jti, raw_expiry, nonce, signature = token.split(".", 3)
        expires_at = int(raw_expiry)
    except (AttributeError, ValueError):
        return False
    if token_jti != session_jti or not nonce or expires_at < int(datetime.now(UTC).timestamp()):
        return False
    payload = f"{token_jti}.{raw_expiry}.{nonce}"
    expected = hmac.new(
        settings.csrf_signing_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).digest()
    padded = signature + "=" * (-len(signature) % 4)
    try:
        received = base64.urlsafe_b64decode(padded.encode("ascii"))
    except ValueError:
        return False
    return hmac.compare_digest(expected, received)
