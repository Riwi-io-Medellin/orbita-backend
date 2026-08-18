import re

from authlib.integrations.starlette_client import OAuth

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

# "common" endpoint discovery doc returns issuer as a literal
# "https://login.microsoftonline.com/{tenantid}/v2.0" template, not the real
# tenant GUID, so Authlib's default exact-match "iss" check always fails.
# Accept any Microsoft tenant issuer instead of the unexpanded template.
_ISS_PATTERN = re.compile(
    r"^https://login\.microsoftonline\.com/[0-9a-fA-F-]{36}/v2\.0$"
)


def _validate_issuer_claim(claims, value):
    return bool(_ISS_PATTERN.match(value))


ms_claims_options = {
    "iss": {"essential": True, "validate": _validate_issuer_claim},
}