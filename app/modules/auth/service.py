import hashlib
import secrets
from datetime import datetime, timedelta, UTC
from urllib.parse import urlencode
from uuid import UUID

from fastapi import HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.apps.models import App
from app.modules.apps.service import AppService, RoleService
from app.modules.auth.models import AppSession, AuthorizationCode
from app.modules.users.models import User

AUTHORIZATION_CODE_TTL_SECONDS = 60


def _hash_authorization_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class AuthorizationCodeService:

    @staticmethod
    async def issue_authorization_code(
        db: AsyncSession,
        user: User,
        app: App,
        redirect_uri: str,
    ) -> str:

        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(
            seconds=AUTHORIZATION_CODE_TTL_SECONDS
        )

        entry = AuthorizationCode(
            code_hash=_hash_authorization_code(code),
            user_id=user.id,
            app_id=app.id,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
        )

        db.add(entry)
        await db.commit()

        return code

    @staticmethod
    async def redeem_authorization_code(
        db: AsyncSession,
        code: str,
        app: App,
        redirect_uri: str,
    ) -> AuthorizationCode | None:

        now = datetime.now(UTC)

        stmt = (
            update(AuthorizationCode)
            .where(
                AuthorizationCode.code_hash == _hash_authorization_code(code),
                AuthorizationCode.app_id == app.id,
                AuthorizationCode.redirect_uri == redirect_uri,
                AuthorizationCode.used_at.is_(None),
                AuthorizationCode.expires_at > now,
            )
            .values(used_at=now)
            .returning(AuthorizationCode)
        )

        result = await db.execute(stmt)
        row = result.scalar_one_or_none()

        return row


class AppSessionService:

    @staticmethod
    async def record_app_session(
        db: AsyncSession,
        jti: str,
        user: User,
        app: App,
        expires_at: datetime,
    ) -> AppSession:

        session = AppSession(
            jti=jti,
            user_id=user.id,
            app_id=app.id,
            expires_at=expires_at,
        )

        db.add(session)
        return session

    @staticmethod
    async def is_session_active(db: AsyncSession, jti: str) -> AppSession | None:

        now = datetime.now(UTC)

        query = select(AppSession).where(
            AppSession.jti == jti,
            AppSession.revoked_at.is_(None),
            AppSession.expires_at > now,
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def revoke_all_for_user(db: AsyncSession, user_id: UUID) -> None:

        stmt = (
            update(AppSession)
            .where(
                AppSession.user_id == user_id,
                AppSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )

        await db.execute(stmt)
        await db.commit()

    @staticmethod
    async def revoke_for_app(db: AsyncSession, app_id: UUID) -> None:
        await db.execute(
            update(AppSession)
            .where(AppSession.app_id == app_id, AppSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
        await db.commit()

    @staticmethod
    async def revoke_for_user_in_app(db: AsyncSession, user_id: UUID, app_id: UUID) -> None:
        await db.execute(
            update(AppSession)
            .where(
                AppSession.user_id == user_id,
                AppSession.app_id == app_id,
                AppSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
        await db.commit()


async def build_authorize_redirect(
    db: AsyncSession,
    user: User,
    client_id: str,
    redirect_uri: str,
    state: str,
) -> RedirectResponse:

    app = await AppService.get_by_client_id(db, client_id)

    if app is None or not await AppService.is_available_for_sso(db, app):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown or inactive app",
        )

    if not await AppService.validate_redirect_uri(db, app, redirect_uri):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri is not registered for this app",
        )

    roles = await RoleService.list_roles_for_user_in_app(db, user.id, app)

    if not roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not provisioned for this app",
        )

    code = await AuthorizationCodeService.issue_authorization_code(db, user, app, redirect_uri)

    query = urlencode({"code": code, "state": state})

    return RedirectResponse(url=f"{redirect_uri}?{query}", status_code=302)
