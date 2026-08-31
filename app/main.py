from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Request
from app.config.settings import settings
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware

from app.modules.users.router import router as users_router
from app.modules.auth.router import router as auth_router
from app.modules.apps.router import router as apps_router
from app.modules.apps.sync_router import router as apps_sync_router
from app.modules.access.router import router as applications_router
from app.modules.access.service import AccessService
from app.modules.auth.jwt import get_jwks
from app.database.session import AsyncSessionLocal

BASE_DIR = Path(__file__).resolve().parent.parent


def run_migrations() -> None:
    cfg = Config(BASE_DIR / "alembic.ini")
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await anyio.to_thread.run_sync(run_migrations)
    async with AsyncSessionLocal() as db:
        await AccessService.seed(db)
        await AccessService.bootstrap_platform_admins(
            db,
            settings.platform_admin_emails.split(","),
        )
    yield


OPENAPI_TAGS = [
    {
        "name": "Authentication",
        "description": (
            "Central login (Moodle credentials, Microsoft OAuth when configured, or temporary local email/password), the central session cookie, "
            "and the SSO handoff (`/authorize` + `/token`) other apps use to get a per-app JWT."
        ),
    },
    {
        "name": "Apps",
        "description": (
            "Platform-admin-only registry of external apps allowed to use Orbita SSO: OAuth client "
            "credentials, redirect URIs, and each app's own roles (e.g. staff/coder/admin) with "
            "per-user assignment. The role-catalog synchronization endpoint is server-to-server and "
            "authenticates the app with its own client credentials."
        ),
    },
    {
        "name": "Applications",
        "description": (
            "The app launcher and platform audit log. A `catalog` application is visible through a "
            "global role or direct grant; an `sso_role` application is visible only through an "
            "app-scoped role and can therefore complete its SSO handoff."
        ),
    },
    {
        "name": "Users",
        "description": (
            "Platform-admin-only user management: activate/deactivate or soft-delete accounts (one at "
            "a time or in bulk), grant/revoke global roles and manage direct grants for catalog-only apps. "
            "SSO access is managed from the Apps tag by assigning an app-scoped role."
        ),
    },
    {
        "name": "System",
        "description": "Unauthenticated infrastructure endpoints (health check, JWKS for token verification).",
    },
]

app = FastAPI(
    title="Orbita API",
    version="1.0.0",
    description=(
        "Orbita is Riwi's own backend **and** the central SSO identity provider for other Riwi apps. "
        "Users authenticate here (Moodle, Microsoft OAuth when configured, or temporary local email/password) and get a central session "
        "cookie for Orbita itself; other apps redirect here for a handoff and receive a short-lived, "
        "role-bearing JWT scoped to that app. A platform admin manages who can log in, "
        "which apps each user can see, and what role they hold inside each app. See `API_CONTRACT.md` "
        "for the access-policy matrix and the complete endpoint contract."
    ),
    openapi_tags=OPENAPI_TAGS,
    lifespan=lifespan,
)

allowed_origins = [settings.frontend_url]
if settings.environment == "development":
    allowed_origins.extend([
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.jwt_secret,
    same_site="none" if settings.environment == "production" else "lax",
    https_only=settings.environment == "production",
)

@app.get("/api/health", tags=["System"], summary="Health check")
def health_check():
    """Liveness probe. Always returns 200 if the process is up; does not check the database."""
    return {
        "status": "ok",
        "service": "orbita-backend",
    }


@app.get("/api/.well-known/jwks.json", tags=["System"], summary="JSON Web Key Set")
def jwks():
    """Public RSA key(s) used to sign central and per-app JWTs, so other apps' backends can verify tokens locally without calling back to Orbita."""
    return get_jwks()


@app.get("/api/.well-known/orbita-configuration", tags=["System"], summary="Orbita SSO Client Contract discovery")
def orbita_configuration(request: Request):
    """Public discovery document for `Orbita SSO Client Contract v1` consumers."""
    issuer = str(request.base_url).rstrip("/")
    return {
        "contract_version": "1.0",
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/api/auth/authorize",
        "token_endpoint": f"{issuer}/api/auth/token",
        "jwks_uri": f"{issuer}/api/.well-known/jwks.json",
        "introspection_endpoint": f"{issuer}/api/auth/introspect",
        "role_catalog_sync_endpoint": f"{issuer}/api/apps/{{client_id}}/role-catalog",
        "token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "email", "name", "aud", "roles", "jti", "exp"],
    }


app.include_router(
    users_router,
    prefix="/api",
)

app.include_router(
    auth_router,
    prefix="/api",
)

app.include_router(
    apps_router,
    prefix="/api",
)

app.include_router(
    apps_sync_router,
    prefix="/api",
)

app.include_router(
    applications_router,
    prefix="/api",
)
