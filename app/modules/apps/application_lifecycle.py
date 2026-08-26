"""Canonical lifecycle for launcher applications and their optional SSO client."""

import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.access.models import Application, ApplicationAccessPolicy
from app.modules.apps.models import App

_PBKDF2_ITERATIONS = 260_000


def hash_client_secret(raw_secret: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        raw_secret.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return f"{salt}${digest}"


class ApplicationLifecycleService:
    """Owns creation and availability synchronization for the Application/App aggregate."""

    @staticmethod
    async def create_catalog_application(
        db: AsyncSession,
        *,
        slug: str,
        name: str,
        description: str,
        url: str,
        icon: str | None,
    ) -> Application:
        application = Application(
            slug=slug,
            name=name,
            description=description,
            url=url,
            icon=icon,
            access_policy=ApplicationAccessPolicy.CATALOG.value,
        )
        db.add(application)
        await db.commit()
        await db.refresh(application)
        return application

    @staticmethod
    async def create_sso_application(
        db: AsyncSession,
        *,
        client_id: str,
        slug: str,
        name: str,
        description: str,
        url: str,
        icon: str | None,
    ) -> tuple[App, str]:
        """Create the launcher tile and SSO client atomically."""
        raw_secret = secrets.token_urlsafe(32)
        application = Application(
            slug=slug,
            name=name,
            description=description,
            url=url,
            icon=icon,
            access_policy=ApplicationAccessPolicy.SSO_ROLE.value,
        )
        db.add(application)
        await db.flush()

        app = App(
            application_id=application.id,
            client_id=client_id,
            name=name,
            client_secret_hash=hash_client_secret(raw_secret),
        )
        db.add(app)
        await db.commit()
        await db.refresh(app)
        return app, raw_secret

    @staticmethod
    async def get_sso_app_for_application(db: AsyncSession, application_id) -> App | None:
        return await db.scalar(select(App).where(App.application_id == application_id))

    @staticmethod
    async def set_availability(
        db: AsyncSession,
        *,
        is_active: bool,
        application: Application | None = None,
        app: App | None = None,
    ) -> tuple[Application | None, App | None]:
        """Set availability once and synchronize both sides of a linked aggregate."""
        if application is None and app is None:
            raise ValueError("application or app is required")

        if application is None and app is not None and app.application_id is not None:
            application = await db.get(Application, app.application_id)
        if app is None and application is not None:
            app = await ApplicationLifecycleService.get_sso_app_for_application(db, application.id)

        if application is not None:
            application.is_active = is_active
        if app is not None:
            app.is_active = is_active

        await db.commit()
        if application is not None:
            await db.refresh(application)
        if app is not None:
            await db.refresh(app)
        return application, app
