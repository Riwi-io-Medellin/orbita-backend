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