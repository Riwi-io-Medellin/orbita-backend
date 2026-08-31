from authlib.integrations.starlette_client import OAuth
from datetime import UTC, datetime

from app.config.settings import settings

oauth = OAuth()

oauth.register(
    name="microsoft",
    client_id=settings.microsoft_client_id,
    client_secret=settings.microsoft_client_secret,
    server_metadata_url=(
        f"https://login.microsoftonline.com/"
        f"{settings.microsoft_tenant_id}/v2.0/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid profile email User.Read offline_access"
    },
)

def _validate_issuer_claim(claims, value):
    expected = f"https://login.microsoftonline.com/{settings.microsoft_tenant_id}/v2.0"
    return value == expected


ms_claims_options = {
    "iss": {"essential": True, "validate": _validate_issuer_claim},
}


class MicrosoftTenantNotAllowedError(ValueError):
    def __init__(self, tenant_id: object):
        self.tenant_id = str(tenant_id) if tenant_id is not None else None
        super().__init__("Microsoft tenant is not allowed")


def validate_microsoft_claims(claims: dict) -> tuple[str, str, str, str]:
    """Returns trusted identity fields after tenant-specific OIDC validation."""
    if not settings.enable_microsoft_login or not settings.microsoft_tenant_id or not settings.microsoft_client_id:
        raise ValueError("Microsoft login is disabled")
    tenant_id = claims.get("tid")
    oid = claims.get("oid")
    email = claims.get("email")
    issuer = claims.get("iss")
    audience = claims.get("aud")
    expires_at = claims.get("exp")
    expected_issuer = f"https://login.microsoftonline.com/{settings.microsoft_tenant_id}/v2.0"
    if tenant_id != settings.microsoft_tenant_id:
        raise MicrosoftTenantNotAllowedError(tenant_id)
    if issuer != expected_issuer or not oid or not email:
        raise ValueError("Microsoft claims are not accepted")
    audiences = audience if isinstance(audience, list) else [audience]
    if settings.microsoft_client_id not in audiences:
        raise ValueError("Microsoft token audience is not accepted")
    try:
        if datetime.fromtimestamp(int(expires_at), UTC) <= datetime.now(UTC):
            raise ValueError("Microsoft token has expired")
    except (TypeError, ValueError) as exc:
        raise ValueError("Microsoft token expiration is not accepted") from exc
    return str(tenant_id), str(oid), str(email), str(claims.get("name") or email)
