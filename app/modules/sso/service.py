import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.modules.access.models import (
    Application,
    ApplicationAccessRole,
    ApplicationClient,
    SSOAuthorizationCode,
    user_application_access_roles,
)
from app.modules.auth.passwords import hash_password, verify_password
from app.modules.users.models import User


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


class SSOService:
    @staticmethod
    async def get_client(db: AsyncSession, client_id: str) -> ApplicationClient | None:
        return await db.scalar(
            select(ApplicationClient).where(
                ApplicationClient.client_id == client_id,
                ApplicationClient.is_active.is_(True),
            )
        )

    @staticmethod
    async def user_role_keys(db: AsyncSession, user_id, application_id) -> list[str]:
        result = await db.scalars(
            select(user_application_access_roles.c.role_key)
            .where(
                user_application_access_roles.c.user_id == user_id,
                user_application_access_roles.c.application_id == application_id,
            )
            .order_by(user_application_access_roles.c.role_key)
        )
        return list(result)

    @staticmethod
    async def create_authorization_code(
        db: AsyncSession,
        *,
        client: ApplicationClient,
        user: User,
        redirect_uri: str,
    ) -> str:
        code = secrets.token_urlsafe(48)
        db.add(SSOAuthorizationCode(
            code_hash=hash_code(code),
            client_id=client.id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            expires_at=datetime.now(UTC) + timedelta(seconds=settings.sso_code_expire_seconds),
        ))
        await db.commit()
        return code

    @staticmethod
    async def exchange_code(
        db: AsyncSession,
        *,
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ) -> tuple[User, Application, list[str]]:
        client = await SSOService.get_client(db, client_id)
        if client is None or not verify_password(client_secret, client.client_secret_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")
        if not secrets.compare_digest(redirect_uri, client.redirect_uri):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid redirect URI")

        authorization_code = await db.scalar(
            select(SSOAuthorizationCode)
            .where(SSOAuthorizationCode.code_hash == hash_code(code))
            .with_for_update()
        )
        now = datetime.now(UTC)
        if (
            authorization_code is None
            or authorization_code.client_id != client.id
            or authorization_code.redirect_uri != redirect_uri
            or authorization_code.consumed_at is not None
            or authorization_code.expires_at <= now
        ):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired authorization code")

        user = await db.get(User, authorization_code.user_id)
        application = await db.get(Application, client.application_id)
        if user is None or application is None or not user.is_active or not application.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Application access is not available")

        roles = await SSOService.user_role_keys(db, user.id, application.id)
        if not roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not authorized for this application")

        authorization_code.consumed_at = now
        await db.commit()
        return user, application, roles

    @staticmethod
    def generate_client_secret() -> tuple[str, str]:
        secret = secrets.token_urlsafe(48)
        return secret, hash_password(secret)
