import hashlib
import hmac
import secrets
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.apps.models import App, AppRedirectURI, Role, UserAppRole
from app.modules.users.models import User

_PBKDF2_ITERATIONS = 260_000


def _hash_secret(raw_secret: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        raw_secret.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return f"{salt}${digest}"


def _verify_secret(raw_secret: str, stored_hash: str) -> bool:
    salt, _, digest = stored_hash.partition("$")
    if not salt or not digest:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        raw_secret.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return hmac.compare_digest(candidate, digest)


class AppService:

    @staticmethod
    async def get_by_client_id(
        db: AsyncSession,
        client_id: str,
    ) -> App | None:

        query = select(App).where(App.client_id == client_id)
        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def list_apps(db: AsyncSession) -> list[App]:
        query = select(App)
        result = await db.execute(query)

        return list(result.scalars().all())

    @staticmethod
    async def create_app(
        db: AsyncSession,
        client_id: str,
        name: str,
    ) -> tuple[App, str]:

        raw_secret = secrets.token_urlsafe(32)

        app = App(
            client_id=client_id,
            name=name,
            client_secret_hash=_hash_secret(raw_secret),
        )

        db.add(app)

        await db.commit()
        await db.refresh(app)

        return app, raw_secret

    @staticmethod
    def verify_client_secret(app: App, raw_secret: str) -> bool:
        return _verify_secret(raw_secret, app.client_secret_hash)

    @staticmethod
    async def add_redirect_uri(
        db: AsyncSession,
        app: App,
        redirect_uri: str,
    ) -> AppRedirectURI:

        entry = AppRedirectURI(
            app_id=app.id,
            redirect_uri=redirect_uri,
        )

        db.add(entry)

        await db.commit()
        await db.refresh(entry)

        return entry

    @staticmethod
    async def set_active_status(
        db: AsyncSession,
        app: App,
        is_active: bool,
    ) -> App:

        app.is_active = is_active

        await db.commit()
        await db.refresh(app)

        return app

    @staticmethod
    async def validate_redirect_uri(
        db: AsyncSession,
        app: App,
        redirect_uri: str,
    ) -> bool:

        query = select(AppRedirectURI).where(
            AppRedirectURI.app_id == app.id,
            AppRedirectURI.redirect_uri == redirect_uri,
        )

        result = await db.execute(query)

        return result.scalar_one_or_none() is not None


class RoleService:

    @staticmethod
    async def create_role(
        db: AsyncSession,
        app: App,
        name: str,
    ) -> Role:

        role = Role(app_id=app.id, name=name)

        db.add(role)

        await db.commit()
        await db.refresh(role)

        return role

    @staticmethod
    async def get_by_app_and_name(
        db: AsyncSession,
        app: App,
        name: str,
    ) -> Role | None:

        query = select(Role).where(
            Role.app_id == app.id,
            Role.name == name,
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def get_role_by_id(
        db: AsyncSession,
        app: App,
        role_id: UUID,
    ) -> Role | None:

        query = select(Role).where(
            Role.app_id == app.id,
            Role.id == role_id,
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def list_for_app(db: AsyncSession, app: App) -> list[Role]:
        query = select(Role).where(Role.app_id == app.id)
        result = await db.execute(query)

        return list(result.scalars().all())

    @staticmethod
    async def assign_role_to_user(
        db: AsyncSession,
        user_id: UUID,
        app: App,
        role: Role,
    ) -> UserAppRole:

        existing_query = select(UserAppRole).where(
            UserAppRole.user_id == user_id,
            UserAppRole.app_id == app.id,
            UserAppRole.role_id == role.id,
        )
        existing = (await db.execute(existing_query)).scalar_one_or_none()

        if existing is not None:
            return existing

        assignment = UserAppRole(
            user_id=user_id,
            app_id=app.id,
            role_id=role.id,
        )

        db.add(assignment)

        await db.commit()
        await db.refresh(assignment)

        return assignment

    @staticmethod
    async def list_roles_for_user_in_app(
        db: AsyncSession,
        user_id: UUID,
        app: App,
    ) -> list[str]:

        query = (
            select(Role.name)
            .join(UserAppRole, UserAppRole.role_id == Role.id)
            .where(
                UserAppRole.user_id == user_id,
                UserAppRole.app_id == app.id,
            )
        )

        result = await db.execute(query)

        return list(result.scalars().all())

    @staticmethod
    async def delete_role(db: AsyncSession, role: Role) -> None:
        await db.execute(delete(UserAppRole).where(UserAppRole.role_id == role.id))
        await db.delete(role)
        await db.commit()

    @staticmethod
    async def unassign_role_from_user(
        db: AsyncSession,
        user_id: UUID,
        app: App,
        role: Role,
    ) -> None:

        await db.execute(
            delete(UserAppRole).where(
                UserAppRole.user_id == user_id,
                UserAppRole.app_id == app.id,
                UserAppRole.role_id == role.id,
            )
        )
        await db.commit()

    @staticmethod
    async def list_user_roles_for_app(
        db: AsyncSession,
        app: App,
    ) -> list[tuple[UUID, str, str, str]]:

        query = (
            select(User.id, User.email, User.full_name, Role.name)
            .join(UserAppRole, UserAppRole.user_id == User.id)
            .join(Role, Role.id == UserAppRole.role_id)
            .where(UserAppRole.app_id == app.id)
            .order_by(User.email, Role.name)
        )

        result = await db.execute(query)

        return list(result.all())
